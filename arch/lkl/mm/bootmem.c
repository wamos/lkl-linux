#include <linux/bootmem.h>
#include <linux/mm.h>
#include <linux/swap.h>

unsigned long memory_start, memory_end;
static unsigned long _memory_start, mem_size;

unsigned long dpdk_dma_memory_start = 0;
unsigned long dpdk_dma_memory_end = 0;
unsigned long spdk_dma_memory_start = 0;
unsigned long spdk_dma_memory_end = 0;

void *empty_zero_page;

void init_spdk_mem(void)
{
	unsigned long bootmap_size;
	unsigned long memory_start, memory_end, mem_size;
	mem_size = 1024 * 1024 * 800;
	memory_start = (unsigned long)lkl_ops->spdk_malloc(mem_size);
	memory_end = memory_start + mem_size;

	if (PAGE_ALIGN(memory_start) != memory_start) {
		mem_size -= PAGE_ALIGN(memory_start) - memory_start;
		memory_start = PAGE_ALIGN(memory_start);
		mem_size = (mem_size / PAGE_SIZE) * PAGE_SIZE;
	}

	pr_info("spdk bootmem address range: 0x%lx - 0x%lx\n", memory_start,
		memory_start + mem_size);

	/*
	 * Give all the memory to the bootmap allocator, tell it to put the
	 * boot mem_map at the start of memory.
	 */
	max_low_pfn = virt_to_pfn(memory_end);
	min_low_pfn = virt_to_pfn(memory_start);

	spdk_dma_memory_start = memory_start;
	spdk_dma_memory_end = memory_end;

	bootmap_size = init_bootmem_node(&dma_zones_page_data[DMA_ZONE_SPDK],
					 min_low_pfn, min_low_pfn, max_low_pfn);

	/*
	 * Free the usable memory, we have to make sure we do not free
	 * the bootmem bitmap so we then reserve it after freeing it :-)
	 */
	free_bootmem(memory_start, mem_size);
	reserve_bootmem(memory_start, bootmap_size, BOOTMEM_DEFAULT);

	{
		unsigned long zones_size[MAX_NR_ZONES] = {
			0,
		};

		zones_size[ZONE_NORMAL] = (mem_size) >> PAGE_SHIFT;
		free_area_init_node(DMA_ZONE_SPDK, zones_size,
				    __pa(PAGE_OFFSET) >> PAGE_SHIFT, NULL);
	}
}

void __init bootmem_init(unsigned long mem_sz)
{
	unsigned long bootmap_size;
	init_spdk_mem();

	mem_size = mem_sz;

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
	lkl_ops->spdk_free((void *)spdk_dma_memory_start);
}
