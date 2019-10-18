#ifndef _UAPI_LINUX_DPDK_H
#define _UAPI_LINUX_DPDK_H

#define DPDK_CTL_ADD 0x4C80

struct dpdk_dev {
    int portid;
    char mac[6];

    struct rte_mempool *rxpool, *txpool; /* ring buffer pool */
};

#endif /* _UAPI_LINUX_DPDK_H */
