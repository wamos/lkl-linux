#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/sctp.h>

#include "debug.h"

void dump_tcp_pkt(struct sk_buff *skb)
{
	typedef union {
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

	l3.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);

	if (skb->protocol != htons(ETH_P_IP) ||
	    l3.v4->protocol != IPPROTO_TCP) {
		return;
	}

	printk(KERN_INFO
	       "RX: %pI4 -> %pI4 %u -> %u Seq=%u Ack=%u Win=%u Len=%u [%s %s %s %s %s]\n",
	       l3.v4->saddr, l3.v4->daddr, be16_to_cpu(l4.tcp->source),
	       be16_to_cpu(l4.tcp->dest), be32_to_cpu(l4.tcp->seq),
	       be32_to_cpu(l4.tcp->ack_seq), be16_to_cpu(l4.tcp->window),
	       ntohs(l3.v4->tot_len) - (l4.tcp->doff * 4) - (l3.v4->ihl * 4),
	       l4.tcp->fin ? "FIN" : "", l4.tcp->syn ? "SYN" : "",
	       l4.tcp->ack ? "ACK" : "", l4.tcp->rst ? "RST" : "",
	       l4.tcp->urg ? "URG" : "");
}
