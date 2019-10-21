#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include "dev.h"

// avoid conflict between stdlib.h abs() and the kernel macro
#undef abs
// avoid re-definition of wchar_t in gcc's stddev.h
#define _WCHAR_T_DEFINED_
#include <rte_net.h>
#include <rte_ethdev.h>

#define DPDK_SENDING 1 /* Bit 1 = 0x02*/

static int dpdk_open(struct net_device *netdev)
{
	struct netdev_dpdk *dpdk = netdev_priv(netdev);
	printk(KERN_INFO "%s() at %s:%d\n", __func__, __FILE__, __LINE__);
	napi_enable(&dpdk->napi);
	netif_tx_start_all_queues(netdev);
	return 0;
}

static int dpdk_close(struct net_device *netdev)
{
	struct netdev_dpdk *dpdk = netdev_priv(netdev);
	printk(KERN_INFO "%s() at %s:%d\n", __func__, __FILE__, __LINE__);
	napi_disable(&dpdk->napi);
	netif_tx_stop_all_queues(netdev);
	return 0;
}

static netdev_tx_t handle_tx(struct net_device *netdev)
{
	struct netdev_dpdk *dpdk = netdev_priv(netdev);
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

		// TODO make this zero-copy
		skb_copy_bits(skb, 0, pkt, skb->len);

		skb = skb_dequeue(&dpdk->sk_buff);
		kfree_skb(skb);
	}

	if (!length) {
		if (skb) {
			printk(KERN_WARNING
			       "dpdk-tx: Unable to send packet (len=%u)",
			       skb->len);
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
	struct netdev_dpdk *dpdk = netdev_priv(netdev);
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

static void set_rx_hash(struct rte_mbuf *rm, struct sk_buff *skb)
{
	enum pkt_hash_types hash_type = PKT_HASH_TYPE_NONE;
	uint32_t ptype, l4_proto, l3_proto;
	struct rte_net_hdr_lens hdr_lens;

	if (unlikely(rm->ol_flags & PKT_RX_RSS_HASH == 0))
		return;

	ptype = rte_net_get_ptype(rm, &hdr_lens, RTE_PTYPE_ALL_MASK);
	l3_proto = ptype & RTE_PTYPE_L3_MASK;
	l4_proto = ptype & RTE_PTYPE_L4_MASK;

	if (likely((l3_proto == RTE_PTYPE_L3_IPV4 ||
		    l3_proto == RTE_PTYPE_L3_IPV6) &&
		   (l4_proto == RTE_PTYPE_L4_TCP ||
		    l4_proto == RTE_PTYPE_L4_UDP ||
		    l4_proto == RTE_PTYPE_L4_SCTP))) {
		// we could also set PKT_HASH_TYPE_L3..., but nobody got time for that.
		hash_type = PKT_HASH_TYPE_L4;
	}

	skb_set_hash(skb, rm->hash.rss, hash_type);
}

int dpdk_rx_poll(struct netdev_dpdk *dpdk)
{
	int i;
	uint32_t len, total_len;
	struct sk_buff *skb;
	void *data;
	struct rte_mbuf *m;
	int nb_rx = rte_eth_rx_burst(dpdk->portid, 0, dpdk->rcv_mbuf,
				     MAX_PKT_BURST);

	/* Forward remaining prefetched packets */
	for (i = 0; i < nb_rx; i++) {
		m = dpdk->rcv_mbuf[i];
		data = rte_pktmbuf_mtod(m, void *);
		len = rte_pktmbuf_data_len(m);
		total_len += len;

		// Check if this is faster!
		skb = napi_alloc_skb(&dpdk->napi, len);
		if (skb == NULL) {
			printk(KERN_WARNING "dpdk-rx: Cannot alloc sk_buff");
			rte_pktmbuf_free(m);
			continue;
		}

		skb_put_data(skb, data, len);
		// This currently makes performance worse...
		//set_rx_hash(m, skb);
		skb->protocol = eth_type_trans(skb, dpdk->dev);

		rte_pktmbuf_free(m);

		// TODO: Replace with faster
		napi_gro_receive(&dpdk->napi, skb);
	}

	napi_gro_flush(&dpdk->napi, false);

	return total_len;
}
