#include "blk_mq.h"

#include <linux/bvec.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <spdk/stdinc.h>
#include <spdk/nvme.h>

#include "dev.h"

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

blk_status_t spdk_read(struct spdk_cmd *cmd, struct request *req,
		       struct spdk_nvme_ns *ns, struct spdk_nvme_qpair *qpair,
		       uint64_t lba, uint32_t lba_count)
{
	int rc = spdk_nvme_ns_cmd_read(ns, qpair, cmd->spdk_buf, lba, lba_count,
				       spdk_read_completion_cb, cmd, 0);

	if (rc < 0) {
		spdk_dma_free(cmd->spdk_buf);
		cmd->spdk_buf = NULL;
		return rc;
	}

	return 0;
}

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

blk_status_t spdk_write(struct spdk_cmd *cmd, struct request *rq,
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
} //blk_status_t spdk_flush() {
//	return 0;
//}
//
//blk_status_t spdk_discard() {
//	return 0;
//}

static blk_status_t spdk_queue_rq(struct blk_mq_hw_ctx *hctx,
				  const struct blk_mq_queue_data *bd)
{
	struct request *rq = bd->rq;
	struct spdk_device *dev = hctx->queue->queuedata;
	struct spdk_nvme_ns *ns = dev->ns_entry.ns;
	struct spdk_nvme_qpair *qpair = hctx->driver_data;
	struct spdk_cmd *cmd = blk_mq_rq_to_pdu(rq);
	size_t len = blk_rq_bytes(rq);
	uint32_t lba_count;
	uint64_t lba;
	blk_status_t status;
	int sector_size;

	blk_mq_start_request(rq);

	cmd->spdk_buf = spdk_dma_malloc(len, 0x1000, NULL);
	cmd->dev = dev;
	cmd->req = rq;

	sector_size = spdk_nvme_ns_get_extended_sector_size(ns);
	lba_count = len / sector_size;
	lba = blk_rq_pos(rq) * 512 / sector_size;

	status = BLK_STS_IOERR;

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

	return status;
}

static int spdk_init_hctx(struct blk_mq_hw_ctx *hctx, void *data,
			  unsigned int hctx_idx)
{
	struct spdk_device *dev = data;
	struct spdk_nvme_qpair *queue;

	queue = dev->ns_entry.qpairs[hctx_idx];

	BUG_ON(hctx_idx >= dev->ns_entry.qpairs_num);

	hctx->driver_data = queue;
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
