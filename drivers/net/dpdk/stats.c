// avoid conflict between stdlib.h abs() and the kernel macro
#undef abs
// avoid re-definition of wchar_t in gcc's stddev.h
#define _WCHAR_T_DEFINED_

#include <rte_net.h>
#include <rte_ethdev.h>

#define PRIu64 "u"

void nic_stats_display(u16 port_id)
{
	struct rte_eth_stats stats;
	uint8_t i;

	static const char *nic_stats_border = "########################";

	rte_eth_stats_get(port_id, &stats);
	printf("\n  %s NIC statistics for port %-2d %s\n", nic_stats_border,
	       port_id, nic_stats_border);

	printf("  RX-packets: %-10" PRIu64 "  RX-errors:  %-10" PRIu64
	       "  RX-bytes:  %-10" PRIu64 "\n",
	       stats.ipackets, stats.ierrors, stats.ibytes);
	printf("  RX-nombuf:  %-10" PRIu64 "\n", stats.rx_nombuf);
	printf("  TX-packets: %-10" PRIu64 "  TX-errors:  %-10" PRIu64
	       "  TX-bytes:  %-10" PRIu64 "\n",
	       stats.opackets, stats.oerrors, stats.obytes);

	printf("\n");
	for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS; i++) {
		printf("  Stats reg %2d RX-packets: %-10" PRIu64
		       "  RX-errors: %-10" PRIu64 "  RX-bytes: %-10" PRIu64
		       "\n",
		       i, stats.q_ipackets[i], stats.q_errors[i],
		       stats.q_ibytes[i]);
	}

	printf("\n");
	for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS; i++) {
		printf("  Stats reg %2d TX-packets: %-10" PRIu64
		       "  TX-bytes: %-10" PRIu64 "\n",
		       i, stats.q_opackets[i], stats.q_obytes[i]);
	}

	printf("  %s############################%s\n", nic_stats_border,
	       nic_stats_border);
}

void nic_xstats_display(u16 port_id)
{
	struct rte_eth_xstat_name *xstats_names;
	uint64_t *values;
	int len, ret, i;
	static const char *nic_stats_border = "########################";

	len = rte_eth_xstats_get_names_by_id(port_id, NULL, 0, NULL);
	if (len < 0) {
		printf("Cannot get xstats count\n");
		return;
	}
	values = malloc(sizeof(*values) * len);
	if (values == NULL) {
		printf("Cannot allocate memory for xstats\n");
		return;
	}

	xstats_names = malloc(sizeof(struct rte_eth_xstat_name) * len);
	if (xstats_names == NULL) {
		printf("Cannot allocate memory for xstat names\n");
		free(values);
		return;
	}
	if (len !=
	    rte_eth_xstats_get_names_by_id(port_id, xstats_names, len, NULL)) {
		printf("Cannot get xstat names\n");
		goto err;
	}

	printf("###### NIC extended statistics for port %-2d #########\n",
	       port_id);
	printf("%s############################\n", nic_stats_border);
	ret = rte_eth_xstats_get_by_id(port_id, NULL, values, len);
	if (ret < 0 || ret > len) {
		printf("Cannot get xstats\n");
		goto err;
	}

	for (i = 0; i < len; i++) {
		printf("%s: %" PRIu64 "\n", xstats_names[i].name, values[i]);
	}

	printf("%s############################\n", nic_stats_border);
err:
	free(values);
	free(xstats_names);
}
