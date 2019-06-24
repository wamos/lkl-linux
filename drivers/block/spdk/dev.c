#include "dev.h"

#include <linux/idr.h>
#include <linux/blk-mq.h>
#include <spdk/stdinc.h>
#include <spdk/nvme.h>

#include "blk.h"
#include "blk_mq.h"
#include "thread.h"
#include "poll.h"
#include "irq.h"

static DEFINE_IDR(spdk_index_idr);
int spdk_major;

static void free_poll_contexts(struct spdk_poll_ctx *contexts, size_t num)
{
	size_t i;
	struct spdk_poll_ctx *ctx;

	for (i = 0; i < num; i++) {
		ctx = &contexts[i];
		ctx->stop_polling = 1;
		if (ctx->thread_id > 0) {
			spdk_join_poll_thread(ctx->thread_id);
		}
		spdk_teardown_irq(ctx);
	}
	kfree(contexts);
}

static int init_poll_context(struct spdk_poll_ctx *ctx, struct spdk_device *dev,
			     struct spdk_nvme_qpair *qpair)
{
	int err;
	lkl_thread_t thread;

	ctx->dev = dev;
	ctx->qpair = qpair;

	spdk_setup_irq(ctx);

	init_llist_head(&ctx->request_queue);
	init_llist_head(&ctx->irq_queue);

	err = spdk_spawn_poll_thread(&thread,
				     (void (*)(void *))(spdk_poll_thread), ctx);
	if (err != 0) {
		return -err;
	}
	ctx->thread_id = err;
	return 0;
};

int spdk_add(struct spdk_device **spdk_dev, struct lkl_spdk_ns_entry *entry)
{
	struct spdk_device *dev;
	struct spdk_poll_ctx *poll_contexts;
	struct gendisk *disk;
	int err;
	int idx, i;
	int bs;
	sector_t size;

	err = -ENOMEM;
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		goto out;

	err = idr_alloc(&spdk_index_idr, dev, 0, 0, GFP_KERNEL);
	if (err < 0)
		goto out_free_dev;
	idx = err;

	err = -ENOMEM;
	memcpy(&dev->ns_entry, entry, sizeof(struct lkl_spdk_ns_entry));
	dev->tag_set.ops = &spdk_mq_ops;
	// TODO one queue per core!
	dev->tag_set.nr_hw_queues = dev->ns_entry.qpairs_num;
	// TODO get the queue depth from spdk_nvme_ctrlr_get_default_io_qpair_opts
	// and using io_queue_size from spdk_nvme_io_qpair_opts
	dev->tag_set.queue_depth = 128;
	dev->tag_set.numa_node = NUMA_NO_NODE;
	dev->tag_set.cmd_size = sizeof(struct spdk_cmd);
	dev->tag_set.flags = BLK_MQ_F_SHOULD_MERGE | BLK_MQ_F_SG_MERGE;
	dev->tag_set.driver_data = dev;
	dev->dev_id = idx;
	dev->ctl_fd = entry->ctl_fd;

	poll_contexts = kzalloc(
		sizeof(struct spdk_poll_ctx) * entry->qpairs_num, GFP_KERNEL);
	if (!dev)
		goto out_free_idr;

	for (i = 0; i < entry->qpairs_num; i++) {
		err = init_poll_context(&poll_contexts[i], dev,
					dev->ns_entry.qpairs[i]);
		if (err < 0) {
			goto out_free_poll_ctx;
		}
	}
	dev->poll_contexts = poll_contexts;

	err = blk_mq_alloc_tag_set(&dev->tag_set);
	if (err)
		goto out_free_poll_ctx;

	dev->blk_mq_queue = blk_mq_init_queue(&dev->tag_set);

	if (IS_ERR_OR_NULL(dev->blk_mq_queue)) {
		err = PTR_ERR(dev->blk_mq_queue);
		goto out_cleanup_tags;
	}

	bs = spdk_nvme_ns_get_extended_sector_size(dev->ns_entry.ns);
	blk_queue_logical_block_size(dev->blk_mq_queue, bs);
	blk_queue_physical_block_size(dev->blk_mq_queue, bs);
	blk_queue_io_min(dev->blk_mq_queue, bs);
	blk_queue_softirq_done(dev->blk_mq_queue, spdk_softirq_done_fn);

	dev->blk_mq_queue->queuedata = dev;

	blk_queue_max_hw_sectors(dev->blk_mq_queue, BLK_DEF_MAX_SECTORS);

	err = -ENOMEM;
	disk = dev->spdk_disk = alloc_disk(1);
	if (!disk)
		goto out_free_queue;

	disk->flags |= GENHD_FL_EXT_DEVT;
	atomic_set(&dev->spdk_refcnt, 0);
	disk->major = spdk_major;
	disk->private_data = dev;
	disk->queue = dev->blk_mq_queue;
	disk->fops = &spdk_blk_fops;
	sprintf(disk->disk_name, "spdk%d", idx);
	size = spdk_nvme_ns_get_size(dev->ns_entry.ns) / 512;

	set_capacity(disk, size);

	add_disk(disk);

	*spdk_dev = dev;

	return dev->dev_id;
out_free_queue:
	blk_cleanup_queue(dev->blk_mq_queue);
out_cleanup_tags:
	blk_mq_free_tag_set(&dev->tag_set);
out_free_poll_ctx:
	free_poll_contexts(poll_contexts, entry->qpairs_num);
out_free_idr:
	idr_remove(&spdk_index_idr, idx);
out_free_dev:
	kfree(dev);
out:
	return err;
}

static int spdk_exit_cb(int id, void *ptr, void *data)
{
	struct spdk_device *dev = ptr;

	del_gendisk(dev->spdk_disk);
	blk_cleanup_queue(dev->blk_mq_queue);
	blk_mq_free_tag_set(&dev->tag_set);
	put_disk(dev->spdk_disk);
	free_poll_contexts(dev->poll_contexts, dev->ns_entry.qpairs_num);
	kfree(dev);
	return 0;
}

void spdk_remove_devices(void)
{
	idr_for_each(&spdk_index_idr, &spdk_exit_cb, NULL);
	idr_destroy(&spdk_index_idr);
}
