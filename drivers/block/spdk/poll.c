#include "poll.h"
#include "thread.h"

#include <linux/llist.h>
#include <asm/cpu.h>

#include <spdk/stdinc.h>
#include <spdk/nvme.h>

// This code runs in userspace
static void spdk_read_completion_cb(void *ctx, const struct spdk_nvme_cpl *cpl)
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

	spdk_dma_free(cmd->spdk_buf);
	cmd->spdk_buf = NULL;
	// TODO error handling: spdk_nvme_cpl_is_error(cpl)

	// The polling loop run in "userspace" and not in the context
	// of lkl. Therefore we need to enter the kernel space to complete
	// our request

	//printk(KERN_INFO "%s() at %s:%d\n", __func__, __FILE__, __LINE__);
	//blk_mq_end_request(req, BLK_STS_OK);
	llist_add(&req->spdk_queue, &cmd->poll_ctx->irq_queue);
	lkl_trigger_irq(-1, cmd->poll_ctx->irq);
}

int spdk_read(struct spdk_cmd *cmd, struct request *req, uint64_t lba,
	      uint32_t lba_count)
{
	int rc;
	struct spdk_poll_ctx *ctx = cmd->poll_ctx;

	rc = spdk_nvme_ns_cmd_read(ctx->dev->ns_entry.ns, ctx->qpair,
				   cmd->spdk_buf, lba, lba_count,
				   spdk_read_completion_cb, cmd, 0);

	if (rc < 0) {
		spdk_dma_free(cmd->spdk_buf);
		cmd->spdk_buf = NULL;
		return rc;
	}

	return 0;
}

// This code runs in userspace
static void spdk_write_completion_cb(void *ctx, const struct spdk_nvme_cpl *cpl)
{
	struct spdk_cmd *cmd = (struct spdk_cmd *)ctx;
	struct request *req = cmd->req;

	spdk_dma_free(cmd->spdk_buf);
	cmd->spdk_buf = NULL;
	// TODO error handling: spdk_nvme_cpl_is_error(cpl)
	// what to set in req->status / req->result ?

	//printk(KERN_INFO "%s() at %s:%d\n", __func__, __FILE__, __LINE__);
	//blk_mq_end_request(req, BLK_STS_OK);
	//fprintf(stderr, "%s() at %s:%d -->\n", __func__, __FILE__, __LINE__);
	//BUG_ON(ioctl(cmd->poll_ctx->dev->ctl_fd, SPDK_REQ_COMPLETE, (long)req) < 0);
	//fprintf(stderr, "%s() at %s:%d <--\n", __func__, __FILE__, __LINE__);

	llist_add(&req->spdk_queue, &cmd->poll_ctx->irq_queue);
	lkl_trigger_irq(-1, cmd->poll_ctx->irq);
}

int spdk_write(struct spdk_cmd *cmd, struct request *rq, uint64_t lba,
	       uint32_t lba_count)
{
	struct bio_vec bvec;
	struct req_iterator iter;
	struct spdk_poll_ctx *ctx = cmd->poll_ctx;
	int rc;
	char *p = (char *)cmd->spdk_buf;

	rq_for_each_segment (bvec, cmd->req, iter) {
		// Copying from bv_page would not work in systems with MMU.
		// However in lkl memory is always mapped.
		memcpy(p, page_address(bvec.bv_page) + bvec.bv_offset,
		       bvec.bv_len);
		p += bvec.bv_len;
	}

	rc = spdk_nvme_ns_cmd_write(ctx->dev->ns_entry.ns, ctx->qpair,
				    cmd->spdk_buf, lba, lba_count,
				    spdk_write_completion_cb, cmd, 0);

	if (rc < 0) {
		spdk_dma_free(cmd->spdk_buf);
		cmd->spdk_buf = NULL;
		return rc;
	}

	return 0;
}

static void process_request(struct request *rq, struct spdk_poll_ctx *ctx)
{
	struct spdk_nvme_ns *ns = ctx->dev->ns_entry.ns;
	struct spdk_cmd *cmd = blk_mq_rq_to_pdu(rq);
	size_t len = blk_rq_bytes(rq);
	uint32_t lba_count;
	uint64_t lba;
	int status;
	int sector_size;

	if (!len) {
		blk_mq_end_request(rq, BLK_STS_OK);
		return;
	}
	cmd->spdk_buf = spdk_dma_malloc(len, 0x1000, NULL);
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
		status = spdk_read(cmd, rq, lba, lba_count);
		break;
	case REQ_OP_WRITE:
		status = spdk_write(cmd, rq, lba, lba_count);
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
		process_request(req, ctx);
	}
}

void spdk_poll_thread(struct spdk_poll_ctx *ctx)
{
	while (!ctx->stop_polling) {
		poll_request_queue(ctx);
		spdk_nvme_qpair_process_completions(ctx->qpair, 0);
		spdk_yield_thread();
	}
}
