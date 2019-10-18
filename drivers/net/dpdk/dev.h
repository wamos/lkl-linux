#ifndef _DPDK_DEV_H_
#define _DPDK_DEV_H_

#include <uapi/linux/dpdk.h>
#include <linux/netdevice.h>

extern struct list_head dpdk_devs;

#define MAX_PKT_BURST 16
struct netdev_dpdk {
	struct task_struct *poll_worker;
	struct net_device *dev;
	struct sk_buff_head sk_buff;
	struct napi_struct napi;
	unsigned long state;

	struct list_head dpdk_node;
	int portid;

	/* burst receive context by rump dpdk code */
	struct rte_mbuf *rcv_mbuf[MAX_PKT_BURST];
	int npkts;
	int bufidx;
	int close : 1;
	int offload;
	int busy_poll;

	struct rte_mempool *rxpool, *txpool; /* ring buffer pool */
};

int dpdk_add(struct dpdk_dev *dev);
void dpdk_remove(struct netdev_dpdk *dev);

#endif // _DPDK_DEV_H_
