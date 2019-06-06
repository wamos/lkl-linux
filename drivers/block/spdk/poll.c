#include "poll.h"
#include "thread.h"
#include "linux/llist.h"

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
	BUG_ON(ioctl(cmd->dev->ctl_fd, SPDK_REQ_COMPLETE, (long)req) < 0);
}

int spdk_read(struct spdk_cmd *cmd, struct request *req,
	      struct spdk_nvme_ns *ns, struct spdk_nvme_qpair *qpair,
	      uint64_t lba, uint32_t lba_count)
{
	int rc;
	rc = spdk_nvme_ns_cmd_read(ns, qpair, cmd->spdk_buf, lba, lba_count,
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
	BUG_ON(ioctl(cmd->dev->ctl_fd, SPDK_REQ_COMPLETE, (long)req) < 0);
}

int spdk_write(struct spdk_cmd *cmd, struct request *rq,
	       struct spdk_nvme_ns *ns, struct spdk_nvme_qpair *qpair,
	       uint64_t lba, uint32_t lba_count)
{
	struct bio_vec bvec;
	struct req_iterator iter;
	int rc;
	char *p = (char *)cmd->spdk_buf;

	rq_for_each_segment (bvec, cmd->req, iter) {
		// Copying from bv_page would not work in systems with MMU.
		// However in lkl memory is always mapped.
		memcpy(p, page_address(bvec.bv_page) + bvec.bv_offset,
		       bvec.bv_len);
		p += bvec.bv_len;
	}

	rc = spdk_nvme_ns_cmd_write(ns, qpair, cmd->spdk_buf, lba, lba_count,
				    spdk_write_completion_cb, cmd, 0);

	if (rc < 0) {
		spdk_dma_free(cmd->spdk_buf);
		cmd->spdk_buf = NULL;
		return rc;
	}

	return 0;
}

static void process_request(struct request *rq, struct spdk_device *dev,
			    struct spdk_nvme_qpair *qpair)
{
	struct spdk_nvme_ns *ns = dev->ns_entry.ns;
	struct spdk_cmd *cmd = blk_mq_rq_to_pdu(rq);
	size_t len = blk_rq_bytes(rq);
	uint32_t lba_count;
	uint64_t lba;
	int status;
	int sector_size;

	cmd->spdk_buf = spdk_dma_malloc(len, 0x1000, NULL);
	cmd->dev = dev;
	cmd->req = rq;

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
		status = spdk_read(cmd, rq, ns, qpair, lba, lba_count);
		break;
	case REQ_OP_WRITE:
		status = spdk_write(cmd, rq, ns, qpair, lba, lba_count);
		break;
	}

	// TODO: error handling
	return status;
}

static void poll_request_queue(struct spdk_poll_ctx *ctx)
{
	struct llist_node *node;
	struct request *req;
	node = llist_del_first(&ctx->spdk_queue);
	if (node) {
		req = llist_entry(node, struct request, spdk_queue);
		process_request(req, ctx->dev, ctx->qpair);
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
