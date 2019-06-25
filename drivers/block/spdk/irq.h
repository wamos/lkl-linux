void spdk_setup_irq(struct spdk_poll_ctx *ctx);

static inline void spdk_teardown_irq(struct spdk_poll_ctx *ctx)
{
	if (ctx->irq != 0) {
		remove_irq(ctx->irq, &ctx->irqaction);
	}
}

static inline void spdk_softirq_done_fn(struct request *rq)
{
	blk_mq_end_request(rq, BLK_STS_OK);
}
