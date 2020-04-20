#include "poll.h"
#include "thread.h"

#include <linux/llist.h>
#include <asm/cpu.h>

#include <spdk/stdinc.h>
#include <spdk/nvme.h>
extern struct spdk_mempool *spdk_dma_mempool;

// TODO seem to be the maximum size
#define SPDK_DATA_POOL_MAX_SIZE 1048576

// This code runs in userspace
static void spdk_read_completion_cb(void *ctx, const struct spdk_nvme_cpl *cpl)
{
	struct spdk_cmd *cmd = (struct spdk_cmd *)ctx;
	struct request *req = cmd->req;

	// TODO better error handling
	BUG_ON(spdk_nvme_cpl_is_error(cpl));

	//printk(KERN_INFO "%s() at %s:%d\n", __func__, __FILE__, __LINE__);
	//blk_mq_end_request(req, BLK_STS_OK);

	lkl_cpu_get();
	blk_mq_end_request(req, BLK_STS_OK);
	lkl_cpu_put();
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

static int spdk_read(struct spdk_cmd *cmd, struct request *req, uint64_t lba,
		     uint32_t lba_count)
{
	struct spdk_poll_ctx *ctx = cmd->poll_ctx;

	return spdk_nvme_ns_cmd_readv(ctx->dev->ns_entry.ns, ctx->qpair, lba,
				      lba_count, spdk_read_completion_cb, cmd,
				      0, reset_sgl, next_sgl);
}

// This code runs in userspace
static void spdk_write_completion_cb(void *ctx, const struct spdk_nvme_cpl *cpl)
{
	struct spdk_cmd *cmd = (struct spdk_cmd *)ctx;
	struct request *req = cmd->req;

	if (cmd->spdk_buf) {
		spdk_mempool_put(spdk_dma_mempool, cmd->spdk_buf);
		cmd->spdk_buf = NULL;
	}

	// TODO better error handling
	BUG_ON(spdk_nvme_cpl_is_error(cpl));

	lkl_cpu_get();
	blk_mq_end_request(req, BLK_STS_OK);
	lkl_cpu_put();
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

	switch (req_op(rq)) {
	//case REQ_OP_FLUSH:
	//	fprintf(stderr, "%s() at %s:%d: flush\n", __func__, __FILE__, __LINE__);
	//	//return spdk_flush();
	//case REQ_OP_DISCARD:
	//	fprintf(stderr, "%s() at %s:%d: discard\n", __func__, __FILE__, __LINE__);
	//	//return spdk_discard();
	//	//break;
	case REQ_OP_READ:
		spdk_read(cmd, rq, lba, lba_count);
		break;
	case REQ_OP_WRITE:
		spdk_write(cmd, rq, lba, lba_count);
		break;
	}
}

static void poll_request_queue(struct spdk_poll_ctx *ctx)
{
	struct llist_node *node;
	struct request *req;
	node = llist_del_first(&ctx->request_queue);
	if (node) {
		req = llist_entry(node, struct request, spdk_queue);
		spdk_process_request(req, ctx);
	}
}
extern int lkl_max_cpu_no;

void spdk_poll_thread(struct spdk_poll_ctx *ctx)
{
	unsigned cpu = ((ctx->idx + 1) % lkl_max_cpu_no);
	// bind each queue to a different cpu
	lkl_set_current_cpu(cpu);
	while (!ctx->stop_polling) {
		poll_request_queue(ctx);
		spdk_nvme_qpair_process_completions(ctx->qpair, 0);
		spdk_yield_thread();
	}
}
