#include <linux/genhd.h>
#include <linux/miscdevice.h>
#include <linux/module.h>

#include "ctl.h"
#include "dev.h"
#include "pcap_server.h"

static int __init dpdk_init(void)
{
	int err;
	dpdk_misc.minor = MISC_DYNAMIC_MINOR;

	pcap_server_start();

	err = misc_register(&dpdk_misc);
	if (err < 0) {
		return err;
	}

	printk(KERN_INFO "dpdk: module loaded, minor: %d\n", dpdk_misc.minor);

	return 0;
}

void dpdk_exit(void)
{
	struct netdev_dpdk *i_dev, *i_next;

	pcap_server_stop();
	misc_deregister(&dpdk_misc);

	list_for_each_entry_safe (i_dev, i_next, &dpdk_devs, dpdk_node) {
		list_del(&i_dev->dpdk_node);
		dpdk_remove(i_dev);
	}
}
EXPORT_SYMBOL(dpdk_exit);

static void __exit _dpdk_exit(void)
{
	dpdk_exit();
}

MODULE_LICENSE("GPL");

module_init(dpdk_init);
module_exit(_dpdk_exit);
