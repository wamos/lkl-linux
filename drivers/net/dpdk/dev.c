#include "dev.h"

#include "linux/slab.h"
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/kthread.h>

#include "net.h"
#include "thread.h"

extern int sgxlkl_gso_offload;
extern int sgxlkl_chksum_offload;

int dpdk_add(struct dpdk_dev *dev)
{
	unsigned i;
	struct net_device *netdev;
	struct netdev_dpdk *dpdk;
	int ret;

	netdev = alloc_etherdev_mq(sizeof(*dpdk), num_online_cpus());
	if (!netdev)
		return -ENOMEM;

	dpdk = (struct netdev_dpdk *)netdev_priv(netdev);
	dpdk->dev = netdev;
	dpdk->portid = dev->portid;
	dpdk->txpool = dev->txpool;

	strcpy(netdev->name, "dpdk%d");

	dpdk_set_mac(dev->portid, netdev);

	u64 FEATURES = NETIF_F_GRO | NETIF_F_HIGHDMA |
			  NETIF_F_SG | NETIF_F_TSO_ECN | 0 ;

	if(sgxlkl_gso_offload)
		FEATURES |= (NETIF_F_TSO | NETIF_F_TSO6);

	if(sgxlkl_gso_offload)
		FEATURES |= (NETIF_F_RXCSUM | NETIF_F_HW_CSUM);

	netdev->features |= FEATURES;
	netdev->hw_features |= FEATURES;
	netdev->hw_enc_features |= FEATURES;

	netdev->netdev_ops = &dpdk_netdev_ops;

	skb_queue_head_init(&dpdk->sk_buff);

	ret = register_netdev(netdev);

	if (ret) {
		printk(KERN_WARNING "failed to register dpdk device: %d\n",
		       ret);
		goto free_netdev;
	}

	dpdk->n_threads = dpdk_num_queues(dpdk);
	dpdk->threads = kmalloc_array(dpdk->n_threads, sizeof(*dpdk->threads),
				      __GFP_ZERO);
	if (!dpdk->threads) {
		goto unregister_netdev;
	}
	for (i = 0; i < dpdk->n_threads; i++) {
		struct dpdk_thread *thread = &dpdk->threads[i];
		thread->queue = i;
		thread->dpdk = dpdk;
		netif_napi_add(netdev, &thread->napi, NULL, NAPI_POLL_WEIGHT);
		ret = dpdk_spawn_poll_thread(
			&thread->thread, (void (*)(void *))(dpdk_poll_thread),
			thread);
		if (ret != 0) {
			printk(KERN_WARNING
			       "failed to spawn dpdk poll thread\n");
			goto free_threads;
		}
	}

	return netdev->ifindex;

free_threads:
	dpdk->stop_polling = 1;
	for (i = 0; i < 4; i++) {
		if (dpdk->threads[i].thread) {
			dpdk_join_poll_thread(dpdk->threads[i].thread);
		}
	}
	kfree(dpdk->threads);
unregister_netdev:
	unregister_netdev(netdev);
free_netdev:
	free_netdev(netdev);
	return ret;
}

void dpdk_remove(struct netdev_dpdk *dev)
{
	unsigned i;
	unregister_netdev(dev->dev);
	free_netdev(dev->dev);

	dev->stop_polling = 1;
	for (i = 0; i < dev->n_threads; i++) {
		if (dev->threads[i].thread) {
			netif_napi_del(&dev->threads[i].napi);
			dpdk_join_poll_thread(dev->threads[i].thread);
		}
	}
	kfree(dev->threads);
}
