#include <linux/blk-mq.h>
#include <linux/kthread.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/hdreg.h>
#include <uapi/linux/spdk.h>

#include <spdk/stdinc.h>
#include <spdk/nvme.h>

static DEFINE_IDR(spdk_index_idr);
static DEFINE_MUTEX(spdk_index_mutex);

static int spdk_major;
static const struct file_operations spdk_ctl_fops;

struct spdk_device {
	// filled out by the caller
	struct lkl_spdk_ns_entry ns_entry;
	// set by sgxlkl_register_spdk_device
	int dev_id;
	atomic_t	spdk_refcnt;
	struct blk_mq_tag_set	tag_set;
	struct gendisk		*spdk_disk;
	struct request_queue	*spdk_queue;
};

struct spdk_cmd {
	void *spdk_buf;
	struct request *req;
};

static void spdk_read_completion_cb(void *ctx, const struct spdk_nvme_cpl *cpl) {
	struct spdk_cmd *cmd = (struct spdk_cmd*) ctx;
	struct bio_vec bvec;
	struct request *req = cmd->req;
	struct req_iterator iter;
	char *p = (char*) cmd->spdk_buf;

	printk(KERN_INFO "%s() at %s:%d\n", __func__, __FILE__, __LINE__);
	rq_for_each_segment(bvec, req, iter) {
		memcpy(page_address(bvec.bv_page) + bvec.bv_offset, p, bvec.bv_len);
		printk(KERN_INFO "%s() at %s:%d: %px..%px <- %px..%px\n", __func__, __FILE__, __LINE__,
			   bvec_to_phys(&bvec), bvec_to_phys(&bvec) + bvec.bv_len, p, p + bvec.bv_len);
		p += bvec.bv_len;
	}

	spdk_dma_free(cmd->spdk_buf);
	cmd->spdk_buf = NULL;
	//blk_mq_complete_request(req);
	// TODO error handling: spdk_nvme_cpl_is_error(cpl)
	blk_mq_end_request(req, BLK_STS_OK);
}

blk_status_t spdk_read(struct spdk_cmd *cmd,
					   struct request *req,
					   struct spdk_nvme_ns *ns,
					   struct spdk_nvme_qpair *qpair,
					   uint64_t lba,
					   uint32_t lba_count) {
	int rc = spdk_nvme_ns_cmd_read(ns, qpair, cmd->spdk_buf, lba, lba_count,
								   spdk_read_completion_cb, cmd, 0);

	if (rc < 0) {
		spdk_dma_free(cmd->spdk_buf);
		cmd->spdk_buf = NULL;
		return rc;
	}

	return 0;
}

static void spdk_write_completion_cb(void *ctx, const struct spdk_nvme_cpl *cpl)
{
	struct spdk_cmd *cmd = (struct spdk_cmd*) ctx;
	struct request *req = cmd->req;

	spdk_dma_free(cmd->spdk_buf);
	cmd->spdk_buf = NULL;
	// TODO error handling: spdk_nvme_cpl_is_error(cpl)
	// what to set in req->status / req->result ?
	blk_mq_end_request(req, BLK_STS_OK);
}

blk_status_t spdk_write(struct spdk_cmd *cmd,
					  struct request *rq,
					  struct spdk_nvme_ns *ns,
					  struct spdk_nvme_qpair *qpair,
					  uint64_t lba,
					  uint32_t lba_count) {
	struct bio_vec bvec;
	struct req_iterator iter;
	int rc;
	char *p = (char*) cmd->spdk_buf;

	rq_for_each_segment(bvec, cmd->req, iter) {
		// Copying from bv_page would not work in systems with MMU.
		// However in lkl memory is always mapped.
		memcpy(p, page_address(bvec.bv_page) + bvec.bv_offset, bvec.bv_len);
		p += bvec.bv_len;
	}

	rc = spdk_nvme_ns_cmd_write(ns, qpair, cmd->spdk_buf, lba, lba_count,
									spdk_write_completion_cb, cmd, 0);
	if (rc < 0) {
		spdk_dma_free(cmd->spdk_buf);
		cmd->spdk_buf = NULL;
		return rc;
	}

	return 0;
}

//blk_status_t spdk_flush() {
//	return 0;
//}
//
//blk_status_t spdk_discard() {
//	return 0;
//}

static blk_status_t spdk_queue_rq(struct blk_mq_hw_ctx *hctx,
			 const struct blk_mq_queue_data *bd)
{
	struct request *rq = bd->rq;
	struct spdk_device *dev = hctx->queue->queuedata;
	struct spdk_nvme_ns *ns = dev->ns_entry.ns;
	struct spdk_nvme_qpair	*qpair = hctx->driver_data;
	struct spdk_cmd *cmd = blk_mq_rq_to_pdu(rq);
	size_t len = blk_rq_bytes(rq);
	uint32_t lba_count;
	uint64_t lba;

	blk_mq_start_request(rq);

	cmd->spdk_buf = spdk_dma_malloc(len, 0x1000, NULL);
	cmd->req = rq;

	int sector_size = spdk_nvme_ns_get_extended_sector_size(ns);
	lba_count = len / sector_size;
	lba = blk_rq_pos(rq) * 512 / sector_size;
	
	switch (req_op(rq)) {
//	case REQ_OP_FLUSH:
//		return spdk_flush();
//	case REQ_OP_DISCARD:
//		return spdk_discard();
//		break;
	case REQ_OP_READ: {
		return spdk_read(cmd, rq, ns, qpair, lba, lba_count);
	}
	case REQ_OP_WRITE: {
		return spdk_write(cmd, rq, ns, qpair, lba, lba_count);
	}
	default:
		return BLK_STS_IOERR;
	}

	return BLK_STS_OK;
}

static int spdk_init_hctx(struct blk_mq_hw_ctx *hctx, void *data,
				unsigned int hctx_idx)
{
	struct spdk_device *dev = data;
	struct spdk_nvme_qpair *queue;

	printk(KERN_INFO "%s() at %s:%d\n", __func__, __FILE__, __LINE__);

	queue = dev->ns_entry.qpairs[hctx_idx];

	BUG_ON(hctx_idx >= dev->ns_entry.qpairs_num);

	hctx->driver_data = queue
;
	return 0;
}

static enum blk_eh_timer_return spdk_timeout(struct request *req, bool reserved)
{
	printk(KERN_INFO "%s() at %s:%d\n", __func__, __FILE__, __LINE__);
	//FIXME, what does the driver expect here?
	return 0;
}

static struct miscdevice spdk_misc = {
	.name		= "spdk-control",
	.fops		= &spdk_ctl_fops,
};

static const struct blk_mq_ops spdk_mq_ops = {
	.queue_rq	= spdk_queue_rq,
	.init_hctx	= spdk_init_hctx,
	.timeout	= spdk_timeout,
};

static int spdk_getgeo(struct block_device *bdev, struct hd_geometry *geo) {
	geo->heads = 1 << 6;
	geo->sectors = 1 << 5;
	geo->cylinders = get_capacity(bdev->bd_disk) >> 11;
	return 0;
}

static const struct block_device_operations spdk_fops = {
	.owner =	THIS_MODULE,
	.getgeo =	spdk_getgeo,
};

static int spdk_add(struct spdk_device **l, struct lkl_spdk_ns_entry *entry)
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
	disk->fops = &spdk_fops;
	sprintf(disk->disk_name, "spdk%d", i);

	size = spdk_nvme_ns_get_size(dev->ns_entry.ns) / 512;
	set_capacity(disk, size);

	add_disk(disk);
	*l = dev;
	printk(KERN_INFO "spdk: added %s", disk->disk_name);
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

static long spdk_control_ioctl(struct file *file, unsigned int cmd,
			       unsigned long parm)
{
	struct spdk_device *dev;
	int ret = -ENOSYS;
	printk(KERN_INFO "%s() at %s:%d\n", __func__, __FILE__, __LINE__);

	mutex_lock(&spdk_index_mutex);
	switch (cmd) {
	case SPDK_CTL_ADD:
		ret = spdk_add(&dev, (struct lkl_spdk_ns_entry *)parm);
		break;
	}

	mutex_unlock(&spdk_index_mutex);

	return ret;
}

static const struct file_operations spdk_ctl_fops = {
	.open		= nonseekable_open,
	.unlocked_ioctl	= spdk_control_ioctl,
	.compat_ioctl	= spdk_control_ioctl,
	.owner		= THIS_MODULE,
	.llseek		= noop_llseek,
};


static void spdk_remove(struct spdk_device *dev)
{
	printk(KERN_INFO "%s() at %s:%d\n", __func__, __FILE__, __LINE__);
	del_gendisk(dev->spdk_disk);
	blk_cleanup_queue(dev->spdk_queue);
	blk_mq_free_tag_set(&dev->tag_set);
	put_disk(dev->spdk_disk);
	kfree(dev);
}

static int __init spdk_init(void)
{
	int err;

	spdk_misc.minor = MISC_DYNAMIC_MINOR;
	err = misc_register(&spdk_misc);
	if (err < 0)
		goto out;

	err = register_blkdev(0, "spdk");
	if (err < 0) {
		err = -EIO;
		goto misc_out;
	}

	spdk_major = err;
	printk(KERN_INFO "spdk: module loaded, minor: %d\n", spdk_misc.minor);
	return 0;

misc_out:
	misc_deregister(&spdk_misc);
out:
	return err;
}

static int spdk_exit_cb(int id, void *ptr, void *data)
{
	struct spdk_device *dev = ptr;
	printk(KERN_INFO "%s() at %s:%d\n", __func__, __FILE__, __LINE__);

	spdk_remove(dev);
	return 0;
}

static void __exit spdk_exit(void)
{
	printk(KERN_INFO "%s() at %s:%d\n", __func__, __FILE__, __LINE__);
	idr_for_each(&spdk_index_idr, &spdk_exit_cb, NULL);
	idr_destroy(&spdk_index_idr);
	unregister_blkdev(spdk_major, "spdk");
	misc_deregister(&spdk_misc);
}

MODULE_LICENSE("GPL");

module_init(spdk_init);
module_exit(spdk_exit);
