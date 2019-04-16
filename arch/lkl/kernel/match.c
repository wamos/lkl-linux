// SPDX-License-Identifier: GPL-2.0
//#include <asm/cpu_device_id.h>
//#include <asm/cpufeature.h>
#include <linux/cpu.h>
#include <linux/export.h>
#include <linux/slab.h>

void kernel_fpu_begin(void);
void kernel_fpu_end(void);

bool irq_fpu_usable(void)
{
        return 1;
}
EXPORT_SYMBOL(irq_fpu_usable);

/**
 * x86_match_cpu - match current CPU again an array of x86_cpu_ids
 * @match: Pointer to array of x86_cpu_ids. Last entry terminated with
 *         {}.
 *
 * Return the entry if the current CPU matches the entries in the
 * passed x86_cpu_id match table. Otherwise NULL.  The match table
 * contains vendor (X86_VENDOR_*), family, model and feature bits or
 * respective wildcard entries.
 *
 * A typical table entry would be to match a specific CPU
 * { X86_VENDOR_INTEL, 6, 0x12 }
 * or to match a specific CPU feature
 * { X86_FEATURE_MATCH(X86_FEATURE_FOOBAR) }
 *
 * Fields can be wildcarded with %X86_VENDOR_ANY, %X86_FAMILY_ANY,
 * %X86_MODEL_ANY, %X86_FEATURE_ANY or 0 (except for vendor)
 *
 * Arrays used to match for this should also be declared using
 * MODULE_DEVICE_TABLE(x86cpu, ...)
 *
 * This always matches against the boot cpu, assuming models and features are
 * consistent over all CPUs.
 */
//const struct x86_cpu_id *x86_match_cpu(const struct x86_cpu_id *match)
const void *x86_match_cpu(void *match)
{
	return match;
	//const struct x86_cpu_id *m;
	//struct cpuinfo_x86 *c = &boot_cpu_data;

	//for (m = match; m->vendor | m->family | m->model | m->feature; m++) {
	//	if (m->vendor != X86_VENDOR_ANY && c->x86_vendor != m->vendor)
	//		continue;
	//	if (m->family != X86_FAMILY_ANY && c->x86 != m->family)
	//		continue;
	//	if (m->model != X86_MODEL_ANY && c->x86_model != m->model)
	//		continue;
	//	if (m->feature != X86_FEATURE_ANY && !cpu_has(c, m->feature))
	//		continue;
	//	return m;
	//}
	//return NULL;
}
EXPORT_SYMBOL(x86_match_cpu);


/*
 * Defines x86 CPU feature bits
 */
#define NCAPINTS                        19         /* N 32-bit words worth of info */
#define NBUGINTS                        1          /* N 32-bit bug flags */

struct cpuinfo_x86 {
    __u8            x86;        /* CPU family */
    __u8            x86_vendor; /* CPU vendor */
    __u8            x86_model;
    __u8            x86_stepping;
    /* Number of 4K pages in DTLB/ITLB combined(in pages): */
    int         x86_tlbsize;
    __u8            x86_virt_bits;
    __u8            x86_phys_bits;
    /* CPUID returned core id bits: */
    __u8            x86_coreid_bits;
    __u8            cu_id;
    /* Max extended CPUID function supported: */
    __u32           extended_cpuid_level;
    /* Maximum supported CPUID level, -1=no CPUID: */
    int         cpuid_level;
    __u32           x86_capability[NCAPINTS + NBUGINTS];
    char            x86_vendor_id[16];
    char            x86_model_id[64];
    /* in KB - valid for CPUS which support this call: */
    unsigned int        x86_cache_size;
    int         x86_cache_alignment;    /* In bytes */
    /* Cache QoS architectural values: */
    int         x86_cache_max_rmid; /* max index */
    int         x86_cache_occ_scale;    /* scale to bytes */
    int         x86_power;
    unsigned long       loops_per_jiffy;
    /* cpuid returned max cores value: */
    u16          x86_max_cores;
    u16         apicid;
    u16         initial_apicid;
    u16         x86_clflush_size;
    /* number of cores as seen by the OS: */
    u16         booted_cores;
    /* Physical processor id: */
    u16         phys_proc_id;
    /* Logical processor id: */
    u16         logical_proc_id;
    /* Core id: */
    u16         cpu_core_id;
    /* Index into per_cpu list: */
    u16         cpu_index;
    u32         microcode;
    /* Address space bits used by the cache internally */
    u8          x86_cache_bits;
    unsigned        initialized : 1;
};

#define X86_VENDOR_INTEL 0
#define INTEL_FAM6_SKYLAKE_X 0x55

struct cpuinfo_x86 boot_cpu_data = {
    .x86 = 0xFF,
    .x86_vendor = X86_VENDOR_INTEL,
    .x86_model = INTEL_FAM6_SKYLAKE_X,
    .x86_capability[0] = 0xFFFFFFFF,
    .x86_capability[1] = 0xFFFFFFFF,
    .x86_capability[2] = 0xFFFFFFFF,
    .x86_capability[3] = 0xFFFFFFFF,
    .x86_capability[4] = 0xFFFFFFFF,
    .x86_capability[5] = 0xFFFFFFFF,
    .x86_capability[6] = 0xFFFFFFFF,
    .x86_capability[7] = 0xFFFFFFFF,
    .x86_capability[8] = 0xFFFFFFFF,
    .x86_capability[9] = 0xFFFFFFFF,
    .x86_capability[10] = 0xFFFFFFFF,
    .x86_capability[11] = 0xFFFFFFFF,
    .x86_capability[12] = 0xFFFFFFFF,
    .x86_capability[13] = 0xFFFFFFFF,
    .x86_capability[14] = 0xFFFFFFFF,
    .x86_capability[15] = 0xFFFFFFFF,
    .x86_capability[16] = 0xFFFFFFFF,
    .x86_capability[17] = 0xFFFFFFFF,
    .x86_capability[18] = 0xFFFFFFFF
};
EXPORT_SYMBOL(boot_cpu_data);

void kernel_fpu_begin(void) {}
EXPORT_SYMBOL(kernel_fpu_begin);
void kernel_fpu_end(void) {}
EXPORT_SYMBOL(kernel_fpu_end);


/*
 * Return whether the system supports a given xfeature.
 *
 * Also return the name of the (most advanced) feature that the caller requested:
 */
int cpu_has_xfeatures(u64 xfeatures_needed, const char **feature_name)
{
    return 1;
}
EXPORT_SYMBOL_GPL(cpu_has_xfeatures);
