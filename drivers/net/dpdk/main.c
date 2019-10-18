#include <linux/genhd.h>
#include <linux/miscdevice.h>
#include <linux/module.h>

#include "ctl.h"
#include "dev.h"

static int __init dpdk_init(void)
{
	int err;
	dpdk_misc.minor = MISC_DYNAMIC_MINOR;

	err = misc_register(&dpdk_misc);
	if (err < 0) {
		return err;
  }

	printk(KERN_INFO "dpdk: module loaded, minor: %d\n", dpdk_misc.minor);

  return 0;
}

static void __exit dpdk_exit(void)
{
	struct netdev_dpdk *i_dev, *i_next;

	misc_deregister(&dpdk_misc);

	list_for_each_entry_safe(i_dev, i_next, &dpdk_devs, dpdk_node) {
		printk(KERN_INFO "%s() at %s:%d\n", __func__, __FILE__, __LINE__);
		list_del(&i_dev->dpdk_node);
		dpdk_remove(i_dev);
	}
}

MODULE_LICENSE("GPL");

module_init(dpdk_init);
module_exit(dpdk_exit);
