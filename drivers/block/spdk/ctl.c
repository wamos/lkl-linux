#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>

#include "dev.h"
#include "blk_mq.h"

static DEFINE_MUTEX(spdk_index_mutex);

static long spdk_control_ioctl(struct file *file, unsigned int cmd,
			       unsigned long parm)
{
	struct spdk_device *dev;
	int ret = -ENOSYS;

	switch (cmd) {
	case SPDK_CTL_ADD:
		mutex_lock(&spdk_index_mutex);
		ret = spdk_add(&dev, (struct lkl_spdk_ns_entry *)parm);
		mutex_unlock(&spdk_index_mutex);
		break;
	case SPDK_REQ_COMPLETE:
		blk_mq_complete_request((struct request *)parm);
		return 0;
	}

	return ret;
}

static const struct file_operations spdk_ctl_fops = {
	.open = nonseekable_open,
	.unlocked_ioctl = spdk_control_ioctl,
	.compat_ioctl = spdk_control_ioctl,
	.owner = THIS_MODULE,
	.llseek = noop_llseek,
};

struct miscdevice spdk_misc = {
	.name = "spdk-control",
	.fops = &spdk_ctl_fops,
};
