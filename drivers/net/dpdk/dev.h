#ifndef _DPDK_DEV_H_
#define _DPDK_DEV_H_

#include <uapi/linux/dpdk.h>
#include <linux/netdevice.h>

// avoid conflict between stdlib.h abs() and the kernel macro
#undef abs
// avoid re-definition of wchar_t in gcc's stddev.h
#define _WCHAR_T_DEFINED_
#include <rte_mbuf.h>

extern struct list_head dpdk_devs;

#define MAX_PKT_BURST 16
struct dpdk_thread {
	lkl_thread_t *thread;
	int queue;
	struct netdev_dpdk *dpdk;
	struct napi_struct napi;
	struct rte_mbuf *rcv_mbuf[MAX_PKT_BURST];
};

struct netdev_dpdk {
	struct task_struct *poll_worker;
	struct net_device *dev;
	struct sk_buff_head sk_buff;
	struct dpdk_thread *threads;
	unsigned n_threads;
	int stop_polling;
	unsigned long state;

	struct list_head dpdk_node;
	int portid;

	int npkts;
	int bufidx;
	int close : 1;
	int offload;
	int busy_poll;

	struct rte_mempool *txpool; /* ring buffer pool */
};

int dpdk_add(struct dpdk_dev *dev);
void dpdk_remove(struct netdev_dpdk *dev);

#endif // _DPDK_DEV_H_
