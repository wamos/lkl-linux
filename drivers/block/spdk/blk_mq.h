#ifndef _SPDK_BLK_MQ_H_
#define _SPDK_BLK_MQ_H_

#include "dev.h"

struct spdk_cmd {
	void *spdk_buf;
	struct spdk_device *dev;
	struct request *req;
};

extern const struct blk_mq_ops spdk_mq_ops;

#endif
