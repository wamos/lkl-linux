#include "blk_mq.h"

#include "linux/smp.h"
#include <linux/bvec.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/trace-helper.h>
#include <spdk/stdinc.h>
#include <spdk/nvme.h>

#include <sys/syscall.h>

#include "dev.h"
#include "poll.h"

//static unsigned n_request = 0;
//char buf[4096];

static blk_status_t spdk_queue_rq(struct blk_mq_hw_ctx *hctx,
				  const struct blk_mq_queue_data *bd)
{
	struct request *rq = bd->rq;
	int r;
	struct spdk_poll_ctx *ctx = hctx->driver_data;
	int status = BLK_STS_IOERR;
	//TRACE_TIME(1000);

	//if (n_request % 1000) {
	//  mm_segment_t fs;
	//  struct file *f = filp_open("/proc/vmstat", O_RDONLY, 0);
	//  if (f) {
	//    fs = get_fs();
	//    while (1) {
	//      int r = f->f_op->read(f, buf, sizeof(buf), &f->f_pos);
	//      if (r <= 0) {
	//        break;
	//      }
	//      write(1, buf, r);
	//    }
	//    set_fs(fs);
	//  }
	//}
	//n_request++;

	blk_mq_start_request(rq);

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
		ctx->queue_length++;
		spdk_process_request(rq, ctx);
		status = BLK_STS_OK;
		break;
	}
	do {
		r = spdk_nvme_qpair_process_completions(ctx->qpair, 0);
	} while (r > 0);

	if (ctx->queue_length) {
		wake_up_interruptible(&ctx->wait_queue);
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
