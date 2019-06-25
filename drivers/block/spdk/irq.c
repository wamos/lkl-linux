#include "poll.h"

#include <linux/llist.h>

static irqreturn_t spdk_irq_handler(int irq, void *dev_id)
{
	struct llist_node *node;
	struct request *req;
	struct spdk_poll_ctx *ctx = (struct spdk_poll_ctx *)dev_id;

    for (;;) {
		node = llist_del_first(&ctx->irq_queue);
		if (!node) {
			break;
		}
		req = llist_entry(node, struct request, spdk_queue);
		blk_mq_complete_request(req);
	}

    return IRQ_HANDLED;
}

void spdk_setup_irq(struct spdk_poll_ctx *ctx)
{
	ctx->irqaction.handler = spdk_irq_handler;
	// TODO: do we want flags here?
	// https://elixir.bootlin.com/linux/v5.2-rc4/source/include/linux/interrupt.h
	//dev->spdk_irqaction.flags = IRQF_NOBALANCING,
	ctx->irqaction.name = "timer";
	ctx->irqaction.dev_id = ctx;
	ctx->irq = lkl_get_free_irq("spdk");
	setup_irq(ctx->irq, &ctx->irqaction);
}
