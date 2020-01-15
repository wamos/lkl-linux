#include <linux/genhd.h>
#include <linux/miscdevice.h>
#include <linux/module.h>

#include "dev.h"
#include "ctl.h"
#include "thread.h"
#include "poll.h"

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

void spdk_exit(void)
{
	spdk_remove_devices();
	unregister_blkdev(spdk_major, "spdk");
	misc_deregister(&spdk_misc);
}

EXPORT_SYMBOL(spdk_exit);

static void __exit _spdk_exit(void)
{
  spdk_exit();
}

MODULE_LICENSE("GPL");

module_init(spdk_init);
module_exit(_spdk_exit);
