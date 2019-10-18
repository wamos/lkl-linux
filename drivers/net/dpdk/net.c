#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include "dev.h"

// avoid conflict between stdlib.h abs() and the kernel macro
#undef abs
// avoid re-definition of wchar_t in gcc's stddev.h
#define	_WCHAR_T_DEFINED_
#include <rte_net.h>
#include <rte_ethdev.h>

#define DPDK_SENDING	        1 /* Bit 1 = 0x02*/

static int dpdk_open(struct net_device *netdev)
{
	printk(KERN_INFO "%s() at %s:%d\n", __func__, __FILE__, __LINE__);
	netif_tx_start_all_queues(netdev);
	return 0;
}

static int dpdk_close(struct net_device *netdev)
{
	printk(KERN_INFO "%s() at %s:%d\n", __func__, __FILE__, __LINE__);
	netif_tx_stop_all_queues(netdev);
  return 0;
}

static netdev_tx_t handle_tx(struct net_device *netdev) {
  struct netdev_dpdk* dpdk = netdev_priv(netdev);
  struct rte_mbuf *rm;
	struct sk_buff *skb;
  unsigned int length;
  void *pkt;

	/* Enter critical section */
	if (test_and_set_bit(DPDK_SENDING, &dpdk->state))
		return NETDEV_TX_OK;

	while ((skb = skb_peek(&dpdk->sk_buff)) != NULL) {
		rm = rte_pktmbuf_alloc(dpdk->txpool);

		pkt = rte_pktmbuf_append(rm, skb->len);
		if (!pkt) {
			break;
		}
		length += skb->len;

		// TODO: zero-copy
		memcpy(pkt, skb->data, skb->len);

		skb = skb_dequeue(&dpdk->sk_buff);
		kfree_skb(skb);
	}

	if (!length) {
		if (skb) {
			printk(KERN_WARNING "dpdk-tx: Unable to send packet (len=%u)", skb->len);
		}
		goto cleanup;
	}

	if (rte_eth_tx_prepare(dpdk->portid, 0, &rm, 1) != 1) {
		printk(KERN_WARNING "dpdk: tx_prep failed\n");
		goto cleanup;
	}

	rte_eth_tx_burst(dpdk->portid, 0, &rm, 1);

 cleanup:
	rte_pktmbuf_free(rm);
	clear_bit(DPDK_SENDING, &dpdk->state);

	return NETDEV_TX_OK;
}
 
static netdev_tx_t dpdk_start_xmit(struct sk_buff *skb,
				   struct net_device *netdev)
{

  struct netdev_dpdk* dpdk = netdev_priv(netdev);
  skb_queue_tail(&dpdk->sk_buff, skb);

  return handle_tx(netdev);
}

struct net_device_ops dpdk_netdev_ops = {
	.ndo_open = dpdk_open,
	.ndo_stop = dpdk_close,
	.ndo_start_xmit = dpdk_start_xmit,
	//.ndo_do_ioctl   = dpdk_ioctl,
	//.ndo_tx_timeout = dpdk_tx_timeout,
};

int dpdk_rx_poll(struct netdev_dpdk *dpdk) {
	int i;
	uint32_t len;
	struct sk_buff *skb;
	void *data;
	struct rte_mbuf *m;
	char filename[50];
	int nb_rx = rte_eth_rx_burst(dpdk->portid, 0, dpdk->rcv_mbuf, MAX_PKT_BURST);

	/* Forward remaining prefetched packets */
	for (i = 0; i < nb_rx; i++) {
		m = dpdk->rcv_mbuf[i];
		data = rte_pktmbuf_mtod(m, void*);
		len = rte_pktmbuf_data_len(m);

		// use napi_alloc_skb instead?
		// skb = napi_alloc_skb(&priv->napi, size);
		skb = netdev_alloc_skb(dpdk->dev, len);
		if (skb == NULL) {
			printk(KERN_WARNING "dpdk-rx: Cannot alloc sk_buff");
			rte_pktmbuf_free(m);
			continue;
		}

		skb_put_data(skb, data, len);
		skb->protocol = eth_type_trans(skb, dpdk->dev);

		rte_pktmbuf_free(m);
		// TODO: Replace with faster
		// napi_gro_receive(&priv->napi, skb);
		if (netif_rx_ni(skb) != NET_RX_SUCCESS) {
			printk(KERN_WARNING "%s() at %s:%d: pkt dropped\n", __func__, __FILE__, __LINE__);
		};
	}
}
