#include <linux/mmzone.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include "slab.h"

static void
memcg_accumulate_slabinfo(struct kmem_cache *s, struct slabinfo *info)
{
	struct kmem_cache *c;
	struct slabinfo sinfo;

	if (!is_root_cache(s))
		return;

	for_each_memcg_cache(c, s) {
		memset(&sinfo, 0, sizeof(sinfo));
		get_slabinfo(c, &sinfo);

		info->active_slabs += sinfo.active_slabs;
		info->num_slabs += sinfo.num_slabs;
		info->shared_avail += sinfo.shared_avail;
		info->active_objs += sinfo.active_objs;
		info->num_objs += sinfo.num_objs;
	}
}

static int meminfo_proc_show(void)
{
	struct sysinfo i;
	unsigned long committed;
	long cached;
	long available;
	unsigned long pages[NR_LRU_LISTS];
	unsigned long sreclaimable, sunreclaim;
	int lru;

	si_meminfo(&i);
	si_swapinfo(&i);
	committed = percpu_counter_read_positive(&vm_committed_as);

	cached = global_node_page_state(NR_FILE_PAGES) -
			total_swapcache_pages() - i.bufferram;
	if (cached < 0)
		cached = 0;

	for (lru = LRU_BASE; lru < NR_LRU_LISTS; lru++)
		pages[lru] = global_node_page_state(NR_LRU_BASE + lru);

	available = si_mem_available();
	sreclaimable = global_node_page_state(NR_SLAB_RECLAIMABLE);
	sunreclaim = global_node_page_state(NR_SLAB_UNRECLAIMABLE);

	printk(KERN_INFO "MemTotal:       %ld", i.totalram);
	printk(KERN_INFO "MemFree:        %ld", i.freeram);
	printk(KERN_INFO "MemAvailable:   %ld", available);
	printk(KERN_INFO "Buffers:        %ld", i.bufferram);
	printk(KERN_INFO "Cached:         %ld", cached);
	printk(KERN_INFO "SwapCached:     %ld", total_swapcache_pages());
	printk(KERN_INFO "Active:         %ld", pages[LRU_ACTIVE_ANON] +
					   pages[LRU_ACTIVE_FILE]);
	printk(KERN_INFO "Inactive:       %ld", pages[LRU_INACTIVE_ANON] +
					   pages[LRU_INACTIVE_FILE]);
	printk(KERN_INFO "Active(anon):   %ld", pages[LRU_ACTIVE_ANON]);
	printk(KERN_INFO "Inactive(anon): %ld", pages[LRU_INACTIVE_ANON]);
	printk(KERN_INFO "Active(file):   %ld", pages[LRU_ACTIVE_FILE]);
	printk(KERN_INFO "Inactive(file): %ld", pages[LRU_INACTIVE_FILE]);
	printk(KERN_INFO "Unevictable:    %ld", pages[LRU_UNEVICTABLE]);
	printk(KERN_INFO "Mlocked:        %ld", global_zone_page_state(NR_MLOCK));

#ifdef CONFIG_HIGHMEM
	printk(KERN_INFO "HighTotal:      %ld", i.totalhigh);
	printk(KERN_INFO "HighFree:       %ld", i.freehigh);
	printk(KERN_INFO "LowTotal:       %ld", i.totalram - i.totalhigh);
	printk(KERN_INFO "LowFree:        %ld", i.freeram - i.freehigh);
#endif

#ifndef CONFIG_MMU
	printk(KERN_INFO "MmapCopy:       %ld",
		    (unsigned long)atomic_long_read(&mmap_pages_allocated));
#endif

	printk(KERN_INFO "SwapTotal:      %ld", i.totalswap);
	printk(KERN_INFO "SwapFree:       %ld", i.freeswap);
	printk(KERN_INFO "Dirty:          %ld",
		    global_node_page_state(NR_FILE_DIRTY));
	printk(KERN_INFO "Writeback:      %ld",
		    global_node_page_state(NR_WRITEBACK));
	printk(KERN_INFO "AnonPages:      %ld",
		    global_node_page_state(NR_ANON_MAPPED));
	printk(KERN_INFO "Mapped:         %ld",
		    global_node_page_state(NR_FILE_MAPPED));
	printk(KERN_INFO "Shmem:          %ld", i.sharedram);
	printk(KERN_INFO "Slab:           %ld", sreclaimable + sunreclaim);
	printk(KERN_INFO "SReclaimable:   %ld", sreclaimable);
	printk(KERN_INFO "SUnreclaim:     %ld", sunreclaim);
	printk(KERN_INFO "KernelStack:    %8lu kB\n",
		   global_zone_page_state(NR_KERNEL_STACK_KB));
	printk(KERN_INFO "PageTables:     %ld",
		    global_zone_page_state(NR_PAGETABLE));
#ifdef CONFIG_QUICKLIST
	printk(KERN_INFO "Quicklists:     %ld", quicklist_total_size());
#endif

	printk(KERN_INFO "NFS_Unstable:   %ld",
		    global_node_page_state(NR_UNSTABLE_NFS));
	printk(KERN_INFO "Bounce:         %ld",
		    global_zone_page_state(NR_BOUNCE));
	printk(KERN_INFO "WritebackTmp:   %ld",
		    global_node_page_state(NR_WRITEBACK_TEMP));
	printk(KERN_INFO "CommitLimit:    %ld", vm_commit_limit());
	printk(KERN_INFO "Committed_AS:   %ld", committed);
	printk(KERN_INFO "VmallocTotal:   %8lu kB\n",
		   (unsigned long)VMALLOC_TOTAL >> 10);
	printk(KERN_INFO "VmallocUsed:    %ld", 0ul);
	printk(KERN_INFO "VmallocChunk:   %ld", 0ul);

	return 0;
}

static void print_slabinfo(struct kmem_cache *cachep)
{
#if STATS
	{			/* node stats */
		unsigned long high = cachep->high_mark;
		unsigned long allocs = cachep->num_allocations;
		unsigned long grown = cachep->grown;
		unsigned long reaped = cachep->reaped;
		unsigned long errors = cachep->errors;
		unsigned long max_freeable = cachep->max_freeable;
		unsigned long node_allocs = cachep->node_allocs;
		unsigned long node_frees = cachep->node_frees;
		unsigned long overflows = cachep->node_overflow;

		printk(KERN_CONT " : globalstat %7lu %6lu %5lu %4lu %4lu %4lu %4lu %4lu %4lu",
			   allocs, high, grown,
			   reaped, errors, max_freeable, node_allocs,
			   node_frees, overflows);
	}
	/* cpu stats */
	{
		unsigned long allochit = atomic_read(&cachep->allochit);
		unsigned long allocmiss = atomic_read(&cachep->allocmiss);
		unsigned long freehit = atomic_read(&cachep->freehit);
		unsigned long freemiss = atomic_read(&cachep->freemiss);

		printk(KERN_CONT " : cpustat %6lu %6lu %6lu %6lu",
			   allochit, allocmiss, freehit, freemiss);
	}
#endif
}

static void cache_show(struct kmem_cache *s) {
	struct slabinfo sinfo;

	memset(&sinfo, 0, sizeof(sinfo));
	get_slabinfo(s, &sinfo);

	memcg_accumulate_slabinfo(s, &sinfo);

	printk(KERN_INFO "%-17s %6lu %6lu %6u %4u %4d",
		   cache_name(s), sinfo.active_objs, sinfo.num_objs, s->size,
		   sinfo.objects_per_slab, (1 << sinfo.cache_order));

	printk(KERN_CONT " : tunables %4u %4u %4u",
		   sinfo.limit, sinfo.batchcount, sinfo.shared);
	printk(KERN_CONT " : slabdata %6lu %6lu %6lu",
		   sinfo.active_slabs, sinfo.num_slabs, sinfo.shared_avail);
	print_slabinfo(s);
	printk(KERN_CONT "\n");
}

static void print_slabinfo_header(void)
{
	/*
	 * Output format version, so at least we can change it
	 * without _too_ many complaints.
	 */
#ifdef CONFIG_DEBUG_SLAB
	printk(KERN_INFO "slabinfo - version: 2.1 (statistics)\n");
#else
	printk(KERN_INFO "slabinfo - version: 2.1\n");
#endif
	printk(KERN_INFO "# name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab>");
	printk(KERN_CONT " : tunables <limit> <batchcount> <sharedfactor>");
	printk(KERN_CONT " : slabdata <active_slabs> <num_slabs> <sharedavail>");
#ifdef CONFIG_DEBUG_SLAB
	printk(KERN_CONT " : globalstat <listallocs> <maxobjs> <grown> <reaped> <error> <maxfreeable> <nodeallocs> <remotefrees> <alienoverflow>");
	printk(KERN_CONT " : cpustat <allochit> <allocmiss> <freehit> <freemiss>");
#endif
	printk(KERN_CONT "\n");
}

static int slab_show(void)
{
	struct kmem_cache *s;
	int ret = 0;

	list_for_each_entry(s, &slab_root_caches, root_caches_node) {
    if (s == slab_root_caches.next)
      print_slabinfo_header();
    cache_show(s);
  }
	return 0;
}

void dump_memory_stats(void) {
  slab_show();
  meminfo_proc_show();

	nodemask_t mask;
	init_nodemask_of_node(&mask, DMA_ZONE_SGX|DMA_ZONE_SPDK|DMA_ZONE_DPDK);
	show_free_areas(0, &mask);
}
