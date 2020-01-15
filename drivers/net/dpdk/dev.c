#include "dev.h"

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/kthread.h>

#include "net.h"

LIST_HEAD(dpdk_devs);

void spdk_yield_thread(void);

static int poll_thread(void *arg)
{
	struct netdev_dpdk *dpdk = arg;

	while (!kthread_should_stop()) {
		dpdk_rx_poll(dpdk);
		schedule();
	}
	return 0;
}

int dpdk_napi(struct napi_struct *napi, const int budget)
{
	struct net_device *dev = napi->dev;
	struct netdev_dpdk *dpdk = (struct netdev_dpdk *)netdev_priv(dev);

	uint64_t processed = dpdk_rx_poll(dpdk);

	if (processed < budget) {
		napi_complete_done(napi, processed);
	}

	return processed;
}

int dpdk_add(struct dpdk_dev *dev)
{
	struct net_device *netdev;
	struct netdev_dpdk *dpdk;
	int ret;
	netdev = alloc_etherdev_mq(sizeof(*dpdk), num_online_cpus());
	if (!netdev)
		return -ENOMEM;

	dpdk = (struct netdev_dpdk *)netdev_priv(netdev);
	dpdk->dev = netdev;
	dpdk->portid = dev->portid;
	dpdk->rxpool = dev->rxpool;
	dpdk->txpool = dev->txpool;

	strcpy(netdev->name, "dpdk%d");

	dpdk_set_mac(dev->portid, netdev);

	enum { FEATURES = NETIF_F_GRO | NETIF_F_HIGHDMA | NETIF_F_RXCSUM |
			  NETIF_F_HW_CSUM | NETIF_F_SG | NETIF_F_TSO |
			  NETIF_F_TSO_ECN | NETIF_F_TSO6 | 0 };

	netdev->features |= FEATURES;
	netdev->hw_features |= FEATURES;
	netdev->hw_enc_features |= FEATURES;

	netdev->netdev_ops = &dpdk_netdev_ops;

	skb_queue_head_init(&dpdk->sk_buff);

	ret = register_netdev(netdev);

	if (ret) {
		printk(KERN_WARNING "failed to register dpdk device: %d\n",
		       ret);
		goto error;
	}

	list_add_tail(&dpdk->dpdk_node, &dpdk_devs);

	netif_napi_add(netdev, &dpdk->napi, dpdk_napi, NAPI_POLL_WEIGHT);

	dpdk->poll_worker = kthread_run(poll_thread, dpdk, "dpdk-poll-thread");

	if (!dpdk->poll_worker) {
		printk(KERN_WARNING "failed to spawn dpdk poll thread\n");
		ret = -ENOMEM;
		goto error;
	}

	return netdev->ifindex;

error:
	free_netdev(netdev);
	return ret;
}

void dpdk_remove(struct netdev_dpdk *dev)
{
	unregister_netdev(dev->dev);
	free_netdev(dev->dev);
}
