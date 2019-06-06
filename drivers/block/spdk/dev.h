#ifndef _SPDK_DEV_H_
#define _SPDK_DEV_H_

#include <linux/blk-mq.h>
#include <uapi/linux/spdk.h>

struct spdk_device {
	// filled out by the caller
	struct lkl_spdk_ns_entry ns_entry;
	// set by sgxlkl_register_spdk_device
	int dev_id;
	int ctl_fd;
	atomic_t spdk_refcnt;
	struct blk_mq_tag_set tag_set;
	struct gendisk *spdk_disk;
	struct request_queue *blk_mq_queue;
	struct llist_head spdk_queue;

	struct spdk_poll_ctx *poll_contexts;
};
extern int spdk_major;

int spdk_add(struct spdk_device **l, struct lkl_spdk_ns_entry *entry);
void spdk_remove_devices(void);

#endif
