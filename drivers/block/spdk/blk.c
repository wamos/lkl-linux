#include <linux/hdreg.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>

static int spdk_getgeo(struct block_device *bdev, struct hd_geometry *geo) {
	geo->heads = 1 << 6;
	geo->sectors = 1 << 5;
	geo->cylinders = get_capacity(bdev->bd_disk) >> 11;
	return 0;
}

const struct block_device_operations spdk_blk_fops = {
	.owner =	THIS_MODULE,
	.getgeo =	spdk_getgeo,
};
