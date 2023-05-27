#ifndef _DPDK_STATS_H_
#define _DPDK_STATS_H_

#include <linux/types.h>

void nic_stats_display(u16 port_id);
void nic_xstats_display(u16 port_id);

#endif
