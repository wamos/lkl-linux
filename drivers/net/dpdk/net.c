#include "linux/kern_levels.h"
#include "linux/skbuff.h"
#include "linux/types.h"
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/sctp.h>

#include "dev.h"
#include "arp.h"
#include "pcap_server.h"

// avoid conflict between stdlib.h abs() and the kernel macro
#undef abs
// avoid re-definition of wchar_t in gcc's stddev.h
#define _WCHAR_T_DEFINED_
#include <rte_net.h>
#include <rte_ethdev.h>

// avoid include spdk header, which causes conflicts with Linux's headers
uint64_t spdk_vtophys(void *buf, uint64_t *size);

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

static u16 skb_ip_proto(struct sk_buff *skb)
{
	return (ip_hdr(skb)->version == 4) ? ip_hdr(skb)->protocol :
					     ipv6_hdr(skb)->nexthdr;
}

static void tx_prep(struct rte_mbuf *rm, struct sk_buff *skb)
{
	u16 protocol;
	u32 l4_offset;
	u8 hdr_len;
	union {
		struct iphdr *v4;
		struct ipv6hdr *v6;
		unsigned char *hdr;
	} l3;

	union {
		struct tcphdr *tcp;
		struct udphdr *udp;
		struct gre_base_hdr *gre;
		unsigned char *hdr;
	} l4;

	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		return;
	}

	l3.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);

	protocol = skb_ip_proto(skb);

	rm->outer_l2_len = 0;
	rm->outer_l3_len = 0;
	rm->l2_len = l3.hdr - skb->data;
	rm->l3_len = l4.hdr - l3.hdr;

	if (ip_hdr(skb)->version == 4) {
		rm->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
	} else {
		rm->ol_flags |= PKT_TX_IPV6;
	}

	if (protocol == IPPROTO_TCP) {
		rm->ol_flags |= PKT_TX_TCP_CKSUM;
		rm->l4_len = l4.tcp->doff * 4;
		rm->tso_segsz = skb_shinfo(skb)->gso_size;

		if (skb_is_gso(skb)) {
			rm->ol_flags |= PKT_TX_TCP_SEG;
		}
	} else if (protocol == IPPROTO_UDP) {
		rm->l4_len = sizeof(struct udphdr);
		rm->ol_flags |= PKT_TX_UDP_CKSUM;
	} else if (protocol == IPPROTO_SCTP) {
		rm->l4_len = sizeof(struct sctphdr);

		rm->ol_flags |= PKT_TX_SCTP_CKSUM;
	} else {
		skb_checksum_help(skb);
	}
}

static void free_skb_cb(void *addr, void *skb_ptr)
{
	struct sk_buff *skb = skb_ptr;
	dev_kfree_skb_any(skb);
}

static struct rte_mbuf_ext_shared_info dpdk_shinfo = {
	.free_cb = free_skb_cb,
	.fcb_opaque = NULL,
	// prevent DPDK from freeing this
	.refcnt_atomic = 1,
};

// We don't need to free frags
static void noop_cb(void *addr, void *skb_ptr)
{
}

static struct rte_mbuf_ext_shared_info dpdk_frag_shinfo = {
	.free_cb = noop_cb,
	.fcb_opaque = NULL,
	// prevent DPDK from freeing this
	.refcnt_atomic = 1,
};

static zero_copy_skb(struct netdev_dpdk *dpdk, struct sk_buff *skb,
		     struct rte_mbuf *rm)
{
	struct rte_mbuf *seg, *previous_seg;
	void *addr;
	int i;
	size_t size = skb_is_nonlinear(skb) ? skb_headlen(skb) : skb->len;

	rm->userdata = skb;
	rte_pktmbuf_attach_extbuf(rm, skb->data, spdk_vtophys(skb->data, NULL),
				  size, &dpdk_shinfo);
	rm->pkt_len = skb->len;
	rm->data_len = size;
	rm->ol_flags |= EXT_USERDATA_ON_FREE;

	previous_seg = rm;
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		const struct skb_frag_struct *frag;
		seg = rte_pktmbuf_alloc(dpdk->txpool);
		if (!seg) {
			return -1;
		}
		previous_seg->next = seg;
		previous_seg = seg;
		rm->nb_segs += 1;

		frag = &skb_shinfo(skb)->frags[i];
		addr = lowmem_page_address(skb_frag_page(frag)) +
		       frag->page_offset;
		BUG_ON(addr < dpdk_dma_memory_start ||
		       addr >= dpdk_dma_memory_end);
		rte_pktmbuf_attach_extbuf(seg, addr, spdk_vtophys(addr, NULL),
					  skb_frag_size(frag),
					  &dpdk_frag_shinfo);
		seg->data_len = skb_frag_size(frag);
	}

	skb = skb_dequeue(&dpdk->sk_buff);
	return 0;
}

static int copy_skb(struct netdev_dpdk *dpdk, struct sk_buff *skb,
		    struct rte_mbuf *rm)
{
	int res = 0;
	void *pkt = rte_pktmbuf_append(rm, skb->len);
	if (!pkt) {
		res = -1;
		goto free;
	}
	skb_copy_bits(skb, 0, pkt, skb->len);

free:
	skb = skb_dequeue(&dpdk->sk_buff);
	kfree_skb(skb);
	return 0;
}

extern struct spdk_mem_map *g_vtophys_map;
static netdev_tx_t handle_tx(struct net_device *netdev)
{
	struct netdev_dpdk *dpdk = netdev_priv(netdev);
	struct rte_mbuf *rm;
	struct sk_buff *skb;
	int n_tx;

	/* Enter critical section */
	if (test_and_set_bit(DPDK_SENDING, &dpdk->state))
		return NETDEV_TX_OK;

	while ((skb = skb_peek(&dpdk->sk_buff)) != NULL) {
		rm = rte_pktmbuf_alloc(dpdk->txpool);
		tx_prep(rm, skb);

		if (0 && skb->len > 10000 && g_vtophys_map) {
			if (zero_copy_skb(dpdk, skb, rm) < 0) {
				break;
			};
		} else {
			if (copy_skb(dpdk, skb, rm) < 0) {
				break;
			};
		}

		if (rte_eth_tx_prepare(dpdk->portid, 0, &rm, 1) != 1) {
			printk(KERN_WARNING "dpdk: tx_prep failed\n");
			rte_pktmbuf_free(rm);
			// TODO free skb
			break;
		}
		n_tx = rte_eth_tx_burst(dpdk->portid, 0, &rm, 1);
		if (unlikely(n_tx != 1)) {
			rte_pktmbuf_free(rm);
			// TODO free skb
		}
	}

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

void dpdk_set_mac(int portid, struct net_device *netdev)
{
	rte_eth_macaddr_get(portid, (struct ether_addr *)netdev->dev_addr);
	ether_addr_copy(netdev->perm_addr, netdev->dev_addr);
	printk(KERN_INFO "%s() at %s:%d: MAC: %pM\n", __func__, __FILE__,
	       __LINE__, netdev->dev_addr);
}

static void set_rx_hash(struct rte_mbuf *rm, struct sk_buff *skb)
{
	enum pkt_hash_types hash_type = PKT_HASH_TYPE_NONE;
	uint32_t ptype, l4_proto, l3_proto;
	struct rte_net_hdr_lens hdr_lens;

	if (unlikely((rm->ol_flags & PKT_RX_RSS_HASH) == 0))
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

static void dpdk_zerocopy_callback(struct ubuf_info *ubuf, bool success)
{
	rte_pktmbuf_free(ubuf->ctx);
}

int dpdk_rx_poll(struct netdev_dpdk *dpdk)
{
	int i;
	uint32_t len, total_len;
	struct sk_buff *skb;
	struct ubuf_info *ubuf;
	void *data;
	struct rte_mbuf *rm;
	int nb_rx = rte_eth_rx_burst(dpdk->portid, 0, dpdk->rcv_mbuf,
				     MAX_PKT_BURST);

	if (nb_rx == 0) {
		return 0;
	}

	for (i = 0; i < nb_rx; i++) {
		rm = dpdk->rcv_mbuf[i];
		data = rte_pktmbuf_mtod(rm, void *);

		// Access headroom of mbuf: https://doc.dpdk.org/guides/prog_guide/mbuf_lib.html
		// FIXME storing skbuf metadata in headroom is insecure (b.c of pointers)
		BUILD_BUG_ON(sizeof(*ubuf) > RTE_PKTMBUF_HEADROOM);
		ubuf = (struct ubuf_info *)(&(
			(uint8_t *)(rm))[sizeof(struct rte_mbuf)]);
		ubuf->callback = dpdk_zerocopy_callback;
		ubuf->ctx = rm;

		len = rte_pktmbuf_data_len(rm);
		total_len += len;

		// We are very spacious in the pool allocator, but just in case.
		BUG_ON(SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) >
		       rte_pktmbuf_tailroom(rm));
		memset(rm->buf_addr + rm->data_off + rm->data_len, 0,
		       sizeof(SKB_DATA_ALIGN(sizeof(struct skb_shared_info))));
		skb = build_skb(data, len + SKB_DATA_ALIGN(sizeof(
						    struct skb_shared_info)));
		if (skb == NULL) {
			printk(KERN_WARNING "dpdk-rx: Cannot alloc sk_buff");
			rte_pktmbuf_free(rm);
			continue;
		}
		skb_zcopy_set(skb, ubuf);

		skb_put(skb, len);
		// This currently makes performance worse...
		//set_rx_hash(m, skb);
		skb->protocol = eth_type_trans(skb, dpdk->dev);
		skb->ip_summed = CHECKSUM_UNNECESSARY;

		napi_gro_receive(&dpdk->napi, skb);
	}

	napi_gro_flush(&dpdk->napi, false);

	return total_len;
}

int i40e_attach_skb_to_rx_queue(struct rte_eth_dev *dev, uint16_t rx_queue_id);
void dpdk_initialize_skb_function(void)
{
	int portid;
	rte_attach_skb = dpdk_attach_skb;
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		struct rte_eth_dev *device = &rte_eth_devices[portid];
		if (!device->device) {
			continue;
		}
		i40e_attach_skb_to_rx_queue(device, 0);
	}
}
