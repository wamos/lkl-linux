#include "pcap_server.h"

#include <linux/kernel.h>
#include <linux/kthread.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include <net/ip.h>

#include "net.h"

#include "stats.h"

//#define ENABLE_PCAPSERVER

#ifdef ENABLE_PCAPSERVER
int write_pcap_filev(const char *filename, struct iovec *pkts, size_t len);

static struct iovec queue[1000];
static size_t queue_pos = 0;
static size_t file_counter = 0;

static struct task_struct *task = NULL;

void pcap_flush_queue(void)
{
	char filename[256];
	size_t i;
	snprintf(filename, sizeof(filename), "/tmp/lkl-%ld.pcap",
		 file_counter++);

	printk(KERN_INFO "%s() at %s:%d: write %s\n", __func__, __FILE__,
	       __LINE__, filename);
	write_pcap_filev(filename, queue, queue_pos);
	for (i = 0; i < queue_pos; i++) {
		kfree(queue[i].iov_base);
	}
	queue_pos = 0;
}

void pcap_enqueue_packet(void *pkt, size_t len)
{
	void *p;
	if (queue_pos >= (sizeof(queue) / sizeof(queue[0]))) {
		pcap_flush_queue();
	}

	p = kmalloc(len, GFP_KERNEL);

	if (!p) {
		printk(KERN_WARNING
		       "%s(): failed to record pkt of size: %ld: Out of memory",
		       __func__, len);
	}

	memcpy(p, pkt, len);

	queue[queue_pos].iov_base = p;
	queue[queue_pos].iov_len = len;
	queue_pos++;
};

static int server_start(void *ptr)
{
	int ret = 0;
	struct kvec vec;
	struct msghdr hdr;
	struct sockaddr_in sin;
	struct socket *ssk = NULL;
	mm_segment_t oldmm;
	int flag = 1;
	char buf[256];

	ret = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &ssk);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(4500);
	sin.sin_addr.s_addr = INADDR_ANY;

	ret = ssk->ops->bind(ssk, (struct sockaddr *)&sin, sizeof(sin));
	ret = ssk->ops->listen(ssk, 1);

	oldmm = get_fs();
	set_fs(KERNEL_DS);
	kernel_setsockopt(ssk, SOL_SOCKET, SO_REUSEADDR, (char *)&flag,
			  sizeof(int));
	kernel_setsockopt(ssk, SOL_SOCKET, SO_REUSEPORT, (char *)&flag,
			  sizeof(int));
	set_fs(oldmm);

	vec.iov_len = sizeof(buf);
	vec.iov_base = buf;

	while (!kthread_should_stop()) {
		oldmm = get_fs();
		set_fs(KERNEL_DS);
		// MSG_DONTWAIT: nonblocking operation: as soon as the packet is read, the call returns
		// MSG_WAITALL: blocks until it does not receive size_buff bytes OR the SO_RCVTIMEO expires.
		ret = kernel_recvmsg(ssk, &hdr, &vec, 1, sizeof(buf),
				     MSG_WAITALL);
		set_fs(oldmm);

		pcap_flush_queue();
		struct net *net = get_net_ns_by_pid(1);
		u64 retrans = snmp_fold_field(net->mib.tcp_statistics,
					      TCP_MIB_RETRANSSEGS);
		printk(KERN_INFO "##### retransmission: %d #####", retrans);
		nic_stats_display(0);
		nic_xstats_display(0);
	}

	sock_release(ssk);

	return 0;
}

void pcap_server_start(void)
{
	task = kthread_run(server_start, (void *)NULL, "pcap_flush_server");
}

void pcap_server_stop(void)
{
	if (task) {
		kthread_stop(task);
	}
}
#else

void pcap_server_start(void)
{
}
void pcap_server_stop(void)
{
}

#endif
