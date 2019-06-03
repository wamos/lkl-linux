#include "dev.h"

#include <linux/idr.h>
#include <linux/blk-mq.h>
#include <spdk/stdinc.h>
#include <spdk/nvme.h>

#include "blk.h"
#include "blk_mq.h"

static DEFINE_IDR(spdk_index_idr);
int spdk_major;

int spdk_add(struct spdk_device **spdk_dev, struct lkl_spdk_ns_entry *entry)
{
	struct spdk_device *dev;
	struct gendisk *disk;
	int err;
	int i;
	int bs;
	sector_t size;

	err = -ENOMEM;
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		goto out;

	err = idr_alloc(&spdk_index_idr, dev, 0, 0, GFP_KERNEL);
	if (err < 0)
		goto out_free_dev;

	i = err;

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
	dev->dev_id = i;
	dev->ctl_fd = entry->ctl_fd;

	err = blk_mq_alloc_tag_set(&dev->tag_set);
	if (err)
		goto out_free_idr;

	dev->spdk_queue = blk_mq_init_queue(&dev->tag_set);

	if (IS_ERR_OR_NULL(dev->spdk_queue)) {
		err = PTR_ERR(dev->spdk_queue);
		goto out_cleanup_tags;
	}

	bs = spdk_nvme_ns_get_extended_sector_size(dev->ns_entry.ns);
	blk_queue_logical_block_size(dev->spdk_queue, bs);
	blk_queue_physical_block_size(dev->spdk_queue, bs);
	blk_queue_io_min(dev->spdk_queue, bs);

	dev->spdk_queue->queuedata = dev;

	blk_queue_max_hw_sectors(dev->spdk_queue, BLK_DEF_MAX_SECTORS);

	err = -ENOMEM;
	disk = dev->spdk_disk = alloc_disk(1);
	if (!disk)
		goto out_free_queue;

	disk->flags |= GENHD_FL_EXT_DEVT;
	atomic_set(&dev->spdk_refcnt, 0);
	disk->major = spdk_major;
	disk->private_data = dev;
	disk->queue = dev->spdk_queue;
	disk->fops = &spdk_blk_fops;
	sprintf(disk->disk_name, "spdk%d", i);
	size = spdk_nvme_ns_get_size(dev->ns_entry.ns) / 512;

	set_capacity(disk, size);

	add_disk(disk);

	*spdk_dev = dev;

	return dev->dev_id;
out_free_queue:
	blk_cleanup_queue(dev->spdk_queue);
out_cleanup_tags:
	blk_mq_free_tag_set(&dev->tag_set);
out_free_idr:
	idr_remove(&spdk_index_idr, i);
out_free_dev:
	kfree(dev);
out:
	return err;
}

static int spdk_exit_cb(int id, void *ptr, void *data)
{
	struct spdk_device *dev = ptr;

	del_gendisk(dev->spdk_disk);
	blk_cleanup_queue(dev->spdk_queue);
	blk_mq_free_tag_set(&dev->tag_set);
	put_disk(dev->spdk_disk);
	kfree(dev);
	return 0;
}

void spdk_remove_devices(void) {
	idr_for_each(&spdk_index_idr, &spdk_exit_cb, NULL);
	idr_destroy(&spdk_index_idr);
}
