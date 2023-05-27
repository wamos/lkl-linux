#ifndef _ASM_LKL_SMP_H
#define _ASM_LKL_SMP_H
#ifndef __ASSEMBLY__

#ifdef CONFIG_SMP

struct task_struct;
struct cpumask;

static inline void smp_prepare_boot_cpu(void) { }
extern void smp_prepare_cpus(unsigned int max_cpus);

extern int __cpu_up(unsigned int cpu, struct task_struct *idle);
static inline void smp_send_stop(void) { }
static inline void smp_cpus_done(unsigned int max_cpus) { }

extern void smp_send_reschedule(int cpu);
extern void arch_send_call_function_single_ipi(int cpu);
extern void arch_send_call_function_ipi_mask(const struct cpumask *mask);

extern void lkl_smp_enter_secondary_idle(void);

//extern int __thread lkl_tls_cpu;
extern int lthread_get_sched_id(void);
extern struct lkl_tls_key *cpu_key;
extern int lkl_get_current_cpu(void);
//#define raw_smp_processor_id()	(lthread_get_sched_id())
#define raw_smp_processor_id()	(lkl_get_current_cpu())

#else

#define raw_smp_processor_id()	0

#endif

#endif /* __ASSEMBLY__ */
#endif /* _ASM_LKL_SMP_H */
