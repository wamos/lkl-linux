#include "blk_mq.h"

#include <linux/bvec.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <spdk/stdinc.h>
#include <spdk/nvme.h>

#include <sys/syscall.h>

#include "dev.h"
#include "poll.h"

static blk_status_t spdk_queue_rq(struct blk_mq_hw_ctx *hctx,
				  const struct blk_mq_queue_data *bd)
{
	struct request *rq = bd->rq;
	struct spdk_poll_ctx *ctx = hctx->driver_data;
	int status = BLK_STS_IOERR;

	blk_mq_start_request(rq);

	llist_add(&rq->spdk_queue, &ctx->spdk_queue);

	switch (req_op(rq)) {
	//case REQ_OP_FLUSH:
	//	fprintf(stderr, "%s() at %s:%d: flush\n", __func__, __FILE__, __LINE__);
	//	//return spdk_flush();
	//case REQ_OP_DISCARD:
	//	fprintf(stderr, "%s() at %s:%d: discard\n", __func__, __FILE__, __LINE__);
	//	//return spdk_discard();
	//	//break;
	case REQ_OP_READ:
	case REQ_OP_WRITE:
		status = BLK_STS_OK;
		break;
	}

	return status;
}

static int spdk_init_hctx(struct blk_mq_hw_ctx *hctx, void *data,
			  unsigned int hctx_idx)
{
	struct spdk_device *dev = data;
	struct spdk_poll_ctx *ctx;

	ctx = &dev->poll_contexts[hctx_idx];

	BUG_ON(hctx_idx >= dev->ns_entry.qpairs_num);

	hctx->driver_data = ctx;
	return 0;
}

static enum blk_eh_timer_return spdk_timeout(struct request *req, bool reserved)
{
	//FIXME, what does the driver expect here?
	return 0;
}

const struct blk_mq_ops spdk_mq_ops = {
	.queue_rq = spdk_queue_rq,
	.init_hctx = spdk_init_hctx,
	.timeout = spdk_timeout,
};
