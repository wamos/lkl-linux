#ifndef _UAPI_LINUX_SPDK_H
#define _UAPI_LINUX_SPDK_H

#include <stddef.h>

#define SPDK_CTL_ADD 0x4C80
#define SPDK_REQ_COMPLETE 0x4C81

// Same definition as spdk_ctrlr_entry in spdk_context.h.
// Copied here to break dependency cycles.
struct lkl_spdk_ctrlr_entry {
	struct spdk_nvme_ctrlr *ctrlr;
	struct spdk_ctrlr_entry *next;
	char name[1024];
};

struct lkl_spdk_ns_entry {
	struct spdk_nvme_ctrlr *ctrlr;
	struct spdk_nvme_ns *ns;
	struct spdk_ns_entry *next;
	struct spdk_nvme_qpair **qpairs;
	size_t qpairs_num;
	int ctl_fd;
};

#endif /* _UAPI_LINUX_SPDK_H */
