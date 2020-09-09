#include "poll.h"
#include "linux/smp.h"
#include "thread.h"

#include <linux/llist.h>
#include <linux/kthread.h>
#include <uapi/linux/sched/types.h>
#include <asm/cpu.h>
#include <linux/trace-helper.h>
#include <linux/delay.h>

#include <spdk/stdinc.h>
#include <spdk/nvme.h>

extern unsigned long spdk_dma_memory_begin;
extern unsigned long spdk_dma_memory_end;
extern struct spdk_mempool *spdk_dma_mempool;
extern int sgxlkl_spdk_zerocopy;

// TODO seem to be the maximum size
#define SPDK_DATA_POOL_MAX_SIZE (1048576 * 2)

// This code runs in userspace
static void spdk_read_copy_completion_cb(void *ctx,
					 const struct spdk_nvme_cpl *cpl)
{
	struct spdk_cmd *cmd = (struct spdk_cmd *)ctx;
	struct bio_vec bvec;
	struct request *req = cmd->req;
	struct req_iterator iter;
	char *p = (char *)cmd->spdk_buf;
	rq_for_each_segment (bvec, req, iter) {
		memcpy(page_address(bvec.bv_page) + bvec.bv_offset, p,
		       bvec.bv_len);
		p += bvec.bv_len;
	}

	spdk_mempool_put(spdk_dma_mempool, cmd->spdk_buf);
	cmd->spdk_buf = NULL;
	// TODO error handling: spdk_nvme_cpl_is_error(cpl)

	cmd->poll_ctx->queue_length--;
	blk_mq_end_request(req, BLK_STS_OK);
}

// This code runs in userspace
static void spdk_read_zerocopy_completion_cb(void *ctx,
					     const struct spdk_nvme_cpl *cpl)
{
	struct spdk_cmd *cmd = (struct spdk_cmd *)ctx;
	struct request *req = cmd->req;
	struct req_iterator iter;
	struct bio_vec bvec;
	unsigned total = 0;

	//ticks_t tsc = rdtsc_e();
	//ticks_t ticks = rdtsc_e() - bio->ts;

	// TODO better error handling
	BUG_ON(spdk_nvme_cpl_is_error(cpl));

	//rq_for_each_segment(bvec, req, iter) {
	//	total += bvec.bv_len;
	//}

	//int printf(const char* f,...); printf("%s() at %s:%d: ts: %e\n", __func__, __FILE__, __LINE__, (double)tsc - req->bio->ts);

	//req->bio->ts = tsc;

	//unsigned long bw = (unsigned long)((double)total / ((double)ticks / tsc_hz));
	//int printf(const char* f,...); printf("%s() at %s:%d: queue_size=%u, throughput: %lu bytes/s (t: %llu, size: %u, freq: %lu)\n", __func__, __FILE__, __LINE__, atomic_read(&queue_size), bw, ticks, total, tsc_hz);

	cmd->poll_ctx->queue_length--;
	blk_mq_end_request(req, BLK_STS_OK);
}

static void reset_sgl(void *ref, uint32_t sgl_offset)
{
	struct spdk_cmd *cmd = (struct spdk_cmd *)ref;
	struct request *req = cmd->req;
	struct req_iterator *iter = &cmd->iter;
	struct bio_vec bvec;

	cmd->iov_offset = sgl_offset;

	BUG_ON(!req->bio);

	// This was unfolded from macro expansion of rq_for_each_segment
	for (iter->bio = req->bio; iter->bio; iter->bio = iter->bio->bi_next) {
		for (iter->iter = iter->bio->bi_iter;
		     iter->iter.bi_size &&
		     ((bvec = bio_iter_iovec(iter->bio, iter->iter)), 1);
		     bio_advance_iter(iter->bio, &iter->iter, bvec.bv_len)) {
			if (cmd->iov_offset < bvec.bv_len) {
				return;
			}
			cmd->iov_offset -= bvec.bv_len;
		}
	}
}

static int next_sgl(void *ref, void **address, uint32_t *length)
{
	struct spdk_cmd *cmd = (struct spdk_cmd *)ref;

	struct request *req = cmd->req;
	struct req_iterator *iter = &cmd->iter;
	struct bio_vec bvec;

	BUG_ON(!req->bio);

	// This was unfolded from macro expansion of rq_for_each_segment
	if (!iter->iter.bi_size) {
		BUG_ON(!iter->bio);
		iter->bio = iter->bio->bi_next;
		iter->iter = iter->bio->bi_iter;

		BUG_ON(!iter->iter.bi_size);
	}

	bvec = bio_iter_iovec(iter->bio, iter->iter);
	BUG_ON(cmd->iov_offset > bvec.bv_len);

	*address = lowmem_page_address(bvec.bv_page) + bvec.bv_offset +
		   cmd->iov_offset;
	*length = bvec.bv_len - cmd->iov_offset;

	bio_advance_iter(iter->bio, &iter->iter, bvec.bv_len);
	cmd->iov_offset = 0;

	return 0;
}

static int spdk_read_zerocopy(struct spdk_cmd *cmd, struct request *req,
			      uint64_t lba, uint32_t lba_count)
{
	struct spdk_poll_ctx *ctx = cmd->poll_ctx;

	return spdk_nvme_ns_cmd_readv(ctx->dev->ns_entry.ns, ctx->qpair, lba,
				      lba_count,
				      spdk_read_zerocopy_completion_cb, cmd, 0,
				      reset_sgl, next_sgl);
}

static int spdk_read_copy(struct spdk_cmd *cmd, struct request *req,
			  uint64_t lba, uint32_t lba_count)
{
	size_t len = blk_rq_bytes(req);
	int rc;

	BUG_ON(len > SPDK_DATA_POOL_MAX_SIZE);
	cmd->spdk_buf = spdk_mempool_get(spdk_dma_mempool);
	rc = spdk_nvme_ns_cmd_read(cmd->poll_ctx->dev->ns_entry.ns,
				   cmd->poll_ctx->qpair, cmd->spdk_buf, lba,
				   lba_count, spdk_read_copy_completion_cb, cmd,
				   0);
	if (unlikely(rc < 0)) {
		spdk_mempool_put(spdk_dma_mempool, cmd->spdk_buf);
		cmd->spdk_buf = NULL;
		return rc;
	}
}

// This code runs in userspace
static void spdk_write_completion_cb(void *ctx, const struct spdk_nvme_cpl *cpl)
{
	struct spdk_cmd *cmd = (struct spdk_cmd *)ctx;
	struct request *req = cmd->req;

	//ticks_t tsc = rdtsc_e();
	//int printf(const char* f,...); printf("%s() at %s:%d: ts: %e\n", __func__, __FILE__, __LINE__, (double)tsc - req->bio->ts);
	//req->bio->ts = tsc;

	if (cmd->spdk_buf) {
		spdk_mempool_put(spdk_dma_mempool, cmd->spdk_buf);
		cmd->spdk_buf = NULL;
	}

	// TODO better error handling
	BUG_ON(spdk_nvme_cpl_is_error(cpl));

	cmd->poll_ctx->queue_length--;
	blk_mq_end_request(req, BLK_STS_OK);
}

static int spdk_write_copy(struct spdk_cmd *cmd, struct request *rq,
			   uint64_t lba, uint32_t lba_count)
{
	struct bio_vec bvec;
	struct req_iterator iter;
	struct spdk_poll_ctx *ctx = cmd->poll_ctx;
	int rc;
	char *buf = NULL;
	size_t len = blk_rq_bytes(rq);

	BUG_ON(len > SPDK_DATA_POOL_MAX_SIZE);

	buf = cmd->spdk_buf = spdk_mempool_get(spdk_dma_mempool);

	if (unlikely(!buf)) {
		return -ENOMEM;
	}

	rq_for_each_segment (bvec, cmd->req, iter) {
		// Copying from bv_page would not work in systems with MMU.
		// However in lkl memory is always mapped.
		memcpy(buf, page_address(bvec.bv_page) + bvec.bv_offset,
		       bvec.bv_len);
		buf += bvec.bv_len;
	}

	rc = spdk_nvme_ns_cmd_write(ctx->dev->ns_entry.ns, ctx->qpair,
				    cmd->spdk_buf, lba, lba_count,
				    spdk_write_completion_cb, cmd, 0);

	if (unlikely(rc < 0)) {
		spdk_mempool_put(spdk_dma_mempool, cmd->spdk_buf);
		cmd->spdk_buf = NULL;
		return rc;
	}
}

static int spdk_write_zerocopy(struct spdk_cmd *cmd, struct request *rq,
			       uint64_t lba, uint32_t lba_count)
{
	struct spdk_poll_ctx *ctx = cmd->poll_ctx;

	return spdk_nvme_ns_cmd_writev(ctx->dev->ns_entry.ns, ctx->qpair, lba,
				       lba_count, spdk_write_completion_cb, cmd,
				       0, reset_sgl, next_sgl);
}

static int spdk_write(struct spdk_cmd *cmd, struct request *rq, uint64_t lba,
		      uint32_t lba_count)
{
	struct bio_vec bvec;
	struct req_iterator iter;
	int zerocopy = 1;

	rq_for_each_segment (bvec, cmd->req, iter) {
		// Copying from bv_page would not work in systems with MMU.
		// However in lkl memory is always mapped.
		unsigned long addr = (unsigned long)page_address(bvec.bv_page);
		if (addr > spdk_dma_memory_end ||
		    addr < spdk_dma_memory_begin) {
			zerocopy = 0;
			break;
		}
	}

	if (zerocopy) {
		return spdk_write_zerocopy(cmd, rq, lba, lba_count);
	} else {
		return spdk_write_copy(cmd, rq, lba, lba_count);
	}
}

void spdk_process_request(struct request *rq, struct spdk_poll_ctx *ctx)
{
	struct spdk_nvme_ns *ns = ctx->dev->ns_entry.ns;
	struct spdk_cmd *cmd = blk_mq_rq_to_pdu(rq);
	size_t len = blk_rq_bytes(rq);
	uint32_t lba_count;
	uint64_t lba;
	int sector_size;

	if (!len) {
		blk_mq_end_request(rq, BLK_STS_OK);
		return;
	}
	cmd->req = rq;
	cmd->poll_ctx = ctx;

	sector_size = spdk_nvme_ns_get_extended_sector_size(ns);
	lba_count = len / sector_size;
	lba = blk_rq_pos(rq) * 512 / sector_size;

	//ticks_t tsc = rdtsc_e();
	//rq->bio->ts = tsc;

	switch (req_op(rq)) {
	//case REQ_OP_FLUSH:
	//	fprintf(stderr, "%s() at %s:%d: flush\n", __func__, __FILE__, __LINE__);
	//	//return spdk_flush();
	//case REQ_OP_DISCARD:
	//	fprintf(stderr, "%s() at %s:%d: discard\n", __func__, __FILE__, __LINE__);
	//	//return spdk_discard();
	//	//break;
	case REQ_OP_READ:
		//spdk_read(cmd, rq, lba, lba_count);
		if(sgxlkl_spdk_zerocopy)
			spdk_read_zerocopy(cmd, rq, lba, lba_count);
		else
			spdk_read_copy(cmd, rq, lba, lba_count);
		break;
	case REQ_OP_WRITE:
		spdk_write(cmd, rq, lba, lba_count);
		break;
	}
}

extern int lkl_max_cpu_no;
extern int spdk_shutdown;

int spdk_poll_thread(struct spdk_poll_ctx *ctx)
{
	//struct sched_param sched_priority = { .sched_priority = MAX_RT_PRIO-1 };
	/* Set maximum priority to preempt all other threads on this CPU. */
	//if (sched_setscheduler_nocheck(current, SCHED_FIFO, &sched_priority))
	//	pr_warn("Failed to set suspend thread scheduler on CPU %d\n", smp_processor_id());

	int i = 0;
	while (!kthread_should_stop()) {
		if (ctx->queue_length == 0) {
			wait_event_interruptible(ctx->wait_queue, ctx->queue_length > 0 || kthread_should_stop());
			i = 0;
		}
		int ret = spdk_nvme_qpair_process_completions(ctx->qpair, 0);
		BUG_ON(ret < 0);

		if (i > 1000 && ret == 0) {
			i = 0;
			schedule();
		}
		i++;
	}
	return 0;
}
