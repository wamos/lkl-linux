#ifndef _SPDK_POLL_H_
#define _SPDK_POLL_H_

#include <linux/llist.h>
#include <uapi/linux/spdk.h>

#include "thread.h"
#include "dev.h"

struct spdk_poll_ctx {
	lkl_thread_t thread_id;
	struct spdk_device *dev;
	struct llist_head request_queue;
	struct spdk_nvme_qpair *qpair;
	int stop_polling;

	int irq;
	struct irqaction irqaction;
	struct llist_head irq_queue;
};

struct spdk_cmd {
	void *spdk_buf;
	struct spdk_poll_ctx *poll_ctx;
	struct request *req;
};

void spdk_poll_thread(struct spdk_poll_ctx *ctx);

#endif
