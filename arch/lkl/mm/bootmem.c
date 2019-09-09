#include <linux/bootmem.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/dma-alloc.h>

unsigned long memory_start, memory_end;
static unsigned long _memory_start, mem_size;

unsigned long dpdk_dma_memory_start = 0;
unsigned long dpdk_dma_memory_end = 0;
extern unsigned long spdk_dma_memory_start;
extern unsigned long spdk_dma_memory_end;
unsigned int spdk_gfp_flags = GFP_SPDK_DMA;
unsigned int spdk_slab_flags = SLAB_SPDK_DMA;

void *empty_zero_page;

void init_spdk_mem(void)
{
	unsigned long bootmap_size, mem_size;
	unsigned long min_low_pfn, max_low_pfn;

	BUG_ON(!spdk_dma_memory_start || !spdk_dma_memory_end);
	BUG_ON(PAGE_ALIGN(spdk_dma_memory_start) != spdk_dma_memory_start);

	pr_info("spdk bootmem address range: 0x%lx - 0x%lx\n", spdk_dma_memory_start,
		spdk_dma_memory_end);

	/*
	 * Give all the memory to the bootmap allocator, tell it to put the
	 * boot mem_map at the start of memory.
	 */
	min_low_pfn = virt_to_pfn(spdk_dma_memory_start);
	max_low_pfn = virt_to_pfn(spdk_dma_memory_end);

	bootmap_size = init_bootmem_node(&dma_zones_page_data[DMA_ZONE_SPDK],
					 min_low_pfn, min_low_pfn, max_low_pfn);

	mem_size = spdk_dma_memory_end - spdk_dma_memory_start;
	/*
	 * Free the usable memory, we have to make sure we do not free
	 * the bootmem bitmap so we then reserve it after freeing it :-)
	 */
	free_bootmem(spdk_dma_memory_start, mem_size);
	reserve_bootmem(spdk_dma_memory_start, bootmap_size, BOOTMEM_DEFAULT);

	{
		unsigned long zones_size[MAX_NR_ZONES] = {
			0,
		};

		zones_size[ZONE_NORMAL] = (mem_size) >> PAGE_SHIFT;
		free_area_init_node(DMA_ZONE_SPDK, zones_size, min_low_pfn, NULL);
	}
}

void __init bootmem_init(unsigned long mem_sz)
{
	unsigned long bootmap_size;

	if (strstr(boot_command_line, "spdk_dma_alloc=no")) {
		spdk_gfp_flags = 0;
		spdk_slab_flags = 0;
	} else {
		init_spdk_mem();
	}

	mem_size = 1024 * 1024 * 128;
	//mem_size = mem_sz;

	_memory_start = (unsigned long)lkl_ops->mem_alloc(mem_size);
	memory_start = _memory_start;
	BUG_ON(!memory_start);
	memory_end = memory_start + mem_size;

	if (PAGE_ALIGN(memory_start) != memory_start) {
		mem_size -= PAGE_ALIGN(memory_start) - memory_start;
		memory_start = PAGE_ALIGN(memory_start);
		mem_size = (mem_size / PAGE_SIZE) * PAGE_SIZE;
	}
	pr_info("bootmem address range: 0x%lx - 0x%lx\n", memory_start,
		memory_start+mem_size);
	/*
	 * Give all the memory to the bootmap allocator, tell it to put the
	 * boot mem_map at the start of memory.
	 */
	max_low_pfn = virt_to_pfn(memory_end);
	min_low_pfn = virt_to_pfn(memory_start);
	bootmap_size = init_bootmem_node(NODE_DATA(0), min_low_pfn, min_low_pfn,
					 max_low_pfn);

	/*
	 * Free the usable memory, we have to make sure we do not free
	 * the bootmem bitmap so we then reserve it after freeing it :-)
	 */
	free_bootmem(memory_start, mem_size);
	reserve_bootmem(memory_start, bootmap_size, BOOTMEM_DEFAULT);

	empty_zero_page = alloc_bootmem_node(NODE_DATA(DMA_ZONE_SPDK), PAGE_SIZE);

	{
		unsigned long zones_size[MAX_NR_ZONES] = {0, };

		zones_size[ZONE_NORMAL] = (mem_size) >> PAGE_SHIFT;
		free_area_init(zones_size);
	}
}

void __init mem_init(void)
{
	max_mapnr = (((unsigned long)high_memory) - PAGE_OFFSET) >> PAGE_SHIFT;
	/* this will put all memory onto the freelists */
	totalram_pages = free_all_bootmem();
	pr_info("Memory available: %luk/%luk RAM\n",
		(nr_free_pages() << PAGE_SHIFT) >> 10, mem_size >> 10);
}

/*
 * In our case __init memory is not part of the page allocator so there is
 * nothing to free.
 */
void free_initmem(void)
{
}

void free_mem(void)
{
	lkl_ops->mem_free((void *)_memory_start);
}
