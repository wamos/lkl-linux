#ifndef _DPDK_DEBUG_H_
#define _DPDK_DEBUG_H_

#include <linux/skbuff.h>

void dump_tcp_pkt(struct sk_buff *skb);

#endif
