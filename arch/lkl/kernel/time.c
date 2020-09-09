#include <linux/irqreturn.h>
#include <linux/smp.h>
#include <linux/clocksource.h>
#include <linux/clockchips.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/tick.h>
#include <linux/cpumask.h>
#include <asm/host_ops.h>
#include <asm/cpu.h>

static unsigned long long boot_time;

void __ndelay(unsigned long nsecs)
{
	unsigned long long start = lkl_ops->time();

	while (lkl_ops->time() < start + nsecs)
		;
}

void __udelay(unsigned long usecs)
{
	__ndelay(usecs * NSEC_PER_USEC);
}

void __const_udelay(unsigned long xloops)
{
	__udelay(xloops / 0x10c7ul);
}

void calibrate_delay(void)
{
}

void read_persistent_clock(struct timespec *ts)
{
	*ts = ns_to_timespec(lkl_ops->time());
}

/*
 * Scheduler clock - returns current time in nanosec units.
 *
 */
unsigned long long sched_clock(void)
{
	if (!boot_time)
		return 0;

	return lkl_ops->time() - boot_time;
}

static u64 clock_read(struct clocksource *cs)
{
	return lkl_ops->time();
}

static struct clocksource clocksource = {
	.name	= "lkl",
	.rating = 499,
	.read	= clock_read,
	.flags	= CLOCK_SOURCE_IS_CONTINUOUS,
	.mask	= CLOCKSOURCE_MASK(64),
};

static void *timer;

static int timer_irq;

static void timer_fn(void *arg)
{
	/* TODO: irq affinity? */
	lkl_trigger_irq(0, timer_irq);
}

static int clockevent_set_state_shutdown(struct clock_event_device *evt)
{
	if (timer) {
		lkl_ops->timer_free(timer);
		timer = NULL;
	}

	return 0;
}

static irqreturn_t timer_irq_handler(int irq, void *dev_id)
{
	struct clock_event_device *dev = (struct clock_event_device *)dev_id;

	dev->event_handler(dev);

	return IRQ_HANDLED;
}

static void clockevent_broadcast(const struct cpumask *mask)
{
#ifdef CONFIG_SMP
	int cpu;

	for_each_cpu(cpu, mask) {
		lkl_tick_broadcast(cpu);
	}
#endif
}

static struct clock_event_device clockevent = {
	.name = "lkl",
	.features = CLOCK_EVT_FEAT_PERIODIC,
	.broadcast = clockevent_broadcast,
	.set_state_shutdown = clockevent_set_state_shutdown,
};

static struct irqaction irq0  = {
	.handler = timer_irq_handler,
	.flags = IRQF_NOBALANCING | IRQF_TIMER,
	.dev_id = &clockevent,
	.name = "timer"
};

#define CLOCKEVENT_NAMELEN	64
#define CLOCK_FREQ 50
static char clockevent_names[NR_CPUS][CLOCKEVENT_NAMELEN];
static struct clock_event_device clockevent_loc[NR_CPUS];

static int timer_initialized = 0;

void lkl_cpu_clock_init(int cpu)
{
	struct clock_event_device *ce = &clockevent_loc[cpu];

	memcpy(ce, &clockevent, sizeof(struct clock_event_device));
	snprintf(&clockevent_names[cpu][0], CLOCKEVENT_NAMELEN, "lkl-%d", cpu);
	ce->name = (const char*)&clockevent_names[cpu][0];
	ce->features |= CLOCK_EVT_FEAT_C3STOP|CLOCK_EVT_FEAT_DUMMY;

	ce->cpumask = cpumask_of(cpu);
	tick_broadcast_control(TICK_BROADCAST_ON);
	// timer goes of once every 0.02s == 50 HZ
	clockevents_config_and_register(ce, CLOCK_FREQ, 1, ULONG_MAX);
	if ((cpu == 0 || cpu == 1) && !timer_initialized) {
		// secondary cpus, i.e. cpu1 get initialized before cpu0,
		// however we need the timer before cpu0 is initalized in the smp case.
		timer_initialized = 1;
		lkl_ops->timer_start(timer);
	}
}

void __init time_init(void)
{
	struct cpumask zero;
	int ret;

	if (!lkl_ops->timer_alloc || !lkl_ops->timer_free || !lkl_ops->time) {
		pr_err("lkl: no time or timer support provided by host\n");
		return;
	}

	timer_irq = lkl_get_free_irq("timer");
	setup_irq(timer_irq, &irq0);

	ret = clocksource_register_khz(&clocksource, 1000000);
	if (ret)
		pr_err("lkl: unable to register clocksource\n");

	cpumask_clear(&zero);
	clockevent.cpumask = &zero;
	clockevents_config_and_register(&clockevent, CLOCK_FREQ, 0, 0);

	boot_time = lkl_ops->time();

	timer = lkl_ops->timer_alloc(timer_fn, NULL);

	if (!timer)
		pr_err("lkl: unable to allocate timer");
	pr_info("lkl: time and timers initialized (irq%d)\n", timer_irq);
}
