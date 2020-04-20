#ifndef _SPDK_POLL_H_
#define _SPDK_POLL_H_

#include <linux/llist.h>
#include <uapi/linux/spdk.h>

#include "thread.h"
#include "dev.h"

struct spdk_poll_ctx {
	lkl_thread_t *thread;
	struct spdk_device *dev;
	size_t idx;
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
	struct req_iterator iter;
	uint32_t iov_offset;
};

void spdk_poll_thread(struct spdk_poll_ctx *ctx);
void spdk_process_request(struct request *rq, struct spdk_poll_ctx *ctx);

#endif
