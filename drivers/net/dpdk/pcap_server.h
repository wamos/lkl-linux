#ifndef _DPDK_PCAP_SERVER_H_
#define _DPDK_PCAP_SERVER_H_

#include <linux/types.h>

void pcap_server_start(void);
void pcap_server_stop(void);
void pcap_enqueue_packet(void *pkt, size_t len);

#endif
