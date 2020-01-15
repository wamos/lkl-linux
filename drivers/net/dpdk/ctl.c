#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>

#include "dev.h"
#include "net.h"

static DEFINE_MUTEX(dpdk_index_mutex);
static int has_initialized_skb = 0;

static long dpdk_control_ioctl(struct file *file, unsigned int cmd,
			       unsigned long parm)
{
	int ret = -ENOSYS;

	switch (cmd) {
	case DPDK_CTL_ADD:
		mutex_lock(&dpdk_index_mutex);
		if (!has_initialized_skb) {
			dpdk_initialize_skb_function();
			has_initialized_skb = 1;
		}
		ret = dpdk_add((struct dpdk_dev *)parm);
		mutex_unlock(&dpdk_index_mutex);
		break;
	}

	return ret;
}

static const struct file_operations dpdk_ctl_fops = {
	.open = nonseekable_open,
	.unlocked_ioctl = dpdk_control_ioctl,
	.compat_ioctl = dpdk_control_ioctl,
	.owner = THIS_MODULE,
	.llseek = noop_llseek,
};

struct miscdevice dpdk_misc = {
	.name = "dpdk-control",
	.fops = &dpdk_ctl_fops,
};
