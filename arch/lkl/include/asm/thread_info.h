#ifndef _ASM_LKL_THREAD_INFO_H
#define _ASM_LKL_THREAD_INFO_H

#define THREAD_SIZE	       (4096)

#ifndef __ASSEMBLY__
#include <asm/types.h>
#include <asm/processor.h>
#include <asm/smp.h>
#include <asm/host_ops.h>

struct thread_info {
	struct task_struct *task;
	unsigned long flags;
	int preempt_count;
	struct lkl_sem *sched_sem;
	struct lkl_jmp_buf sched_jb;
	bool dead;
	lkl_thread_t tid;
	struct task_struct *prev_sched;
	unsigned long stackend;
#ifdef CONFIG_SMP
	int cpu;
#endif
};

#define INIT_THREAD_INFO(tsk)				\
{							\
	.task		= &tsk,				\
	.preempt_count	= INIT_PREEMPT_COUNT,		\
	.flags		= 0,				\
}

/* how to get the thread information struct from C */
extern struct thread_info *_current_thread_info[CONFIG_NR_CPUS];
static inline struct thread_info *current_thread_info(void)
{
	return _current_thread_info[raw_smp_processor_id()];
}

void lkl_set_current(int cpu, struct task_struct *task);

/* thread information allocation */
unsigned long *arch_alloc_thread_stack_node(struct task_struct *, int node);
void arch_free_thread_stack(struct task_struct *tsk);

void threads_init(void);
void threads_cleanup(void);

#define TIF_SYSCALL_TRACE		0
#define TIF_NOTIFY_RESUME		1
#define TIF_SIGPENDING			2
#define TIF_NEED_RESCHED		3
#define TIF_RESTORE_SIGMASK		4
#define TIF_MEMDIE			5
#define TIF_NOHZ			6
#define TIF_SCHED_JB			7
#define TIF_HOST_THREAD			8
#define TIF_NOTIFY_SIGNAL		9

#define __HAVE_THREAD_FUNCTIONS

#define task_thread_info(task)	((struct thread_info *)(task)->stack)
#define task_stack_page(task)	((task)->stack)
void setup_thread_stack(struct task_struct *p, struct task_struct *org);
#define end_of_stack(p) (&task_thread_info(p)->stackend)

#endif /* __ASSEMBLY__ */

#endif
