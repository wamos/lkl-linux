#ifndef _SPDK_POLL_H_
#define _SPDK_POLL_H_

#include <linux/llist.h>
#include <uapi/linux/spdk.h>
#include <linux/wait.h>

#include "thread.h"
#include "dev.h"

struct spdk_poll_ctx {
	size_t idx;
	struct task_struct *thread;
	struct spdk_device *dev;
	struct spdk_nvme_qpair *qpair;
	size_t queue_length;
	wait_queue_head_t wait_queue;
};

struct spdk_cmd {
	void *spdk_buf;
	struct spdk_poll_ctx *poll_ctx;
	struct request *req;
	struct req_iterator iter;
	unsigned long long ts;
	uint32_t iov_offset;
};

int spdk_poll_thread(struct spdk_poll_ctx *ctx);
void spdk_process_request(struct request *rq, struct spdk_poll_ctx *ctx);

#endif
