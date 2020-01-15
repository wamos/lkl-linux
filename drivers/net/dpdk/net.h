#ifndef _DPDK_NET_H_
#define _DPDK_NET_H_

extern struct net_device_ops dpdk_netdev_ops;
int dpdk_rx_poll(struct netdev_dpdk *dpdk);
void dpdk_set_mac(int portid, struct net_device *netdev);
void dpdk_initialize_skb_function(void);

#endif
