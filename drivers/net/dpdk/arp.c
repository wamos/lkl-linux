#include <net/arp.h>
#include <linux/inet.h>

void set_static_arp(void)
{
	struct net *net;
	struct arpreq req = {};
	char mac[6] = { 0x3c, 0xfd, 0xfe, 0x9e, 0x97, 0x58 };
	char *iface = "dpdk0";

	req.arp_flags = ATF_PERM;
	memcpy(&req.arp_dev, iface, sizeof(iface));
	req.arp_pa.sa_family = AF_INET;

	((struct sockaddr_in *)&req.arp_pa)->sin_addr.s_addr =
		in_aton("10.0.2.2");

	printk(KERN_INFO "%s() at %s:%d: set mac address\n", __func__, __FILE__,
	       __LINE__);

	req.arp_ha.sa_family = ARPHRD_ETHER;
	memcpy(&req.arp_ha.sa_data, mac, sizeof(mac));

	rcu_read_lock();
	for_each_net_rcu (net) {
		int r = arp_ioctl(net, SIOCSARP, &req);
		printk(KERN_INFO "%s() at %s:%d: r=%d\n", __func__, __FILE__,
		       __LINE__, r);
		BUG_ON(r != 0);
	}
	rcu_read_unlock();
}
