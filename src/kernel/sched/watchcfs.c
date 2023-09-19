#define pr_fmt(fmt) "watchcfs: " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/smpboot.h>
#include <linux/tick.h>
#include <linux/cpu.h>
#include <linux/hrtimer.h>
#include <linux/moduleparam.h>
#include <linux/sched/clock.h>
#include <linux/sched/isolation.h>
#include <linux/workqueue.h>
#include <linux/cpuhotplug.h>

#define	ALERT_LIMIT	3
#define ALERT_INTERVAL_S 60
static DEFINE_MUTEX(watchcfs_mutex);

static void watchcfs_update(void);
static int param_set_common_bool(const char *val, const struct kernel_param *kp);
static int param_set_common_uint(const char *val, const struct kernel_param *kp);
static int param_set_cpumask(const char *val, const struct kernel_param *kp);
static int param_get_cpumask(char *buffer, const struct kernel_param *kp);

static bool __read_mostly watchcfs_enabled = true;
static const struct kernel_param_ops watchcfs_enabled_param_ops =
{
	.set = param_set_common_bool,
	.get = param_get_bool
};
module_param_cb(watchcfs_enabled, &watchcfs_enabled_param_ops, &watchcfs_enabled, 0644);
MODULE_PARM_DESC(watchcfs_enabled,"Enable watchcfs.");

static uint __read_mostly watchcfs_thresh = 10;
static const struct kernel_param_ops thresh_param_ops =
{
	.set = param_set_common_uint,
	.get = param_get_uint
};
module_param_cb(watchcfs_thresh, &thresh_param_ops, &watchcfs_thresh, 0644);
MODULE_PARM_DESC(watchcfs_thresh,"Threshold of watchcfs.");

static u64 __read_mostly sample_period;
static uint __read_mostly sample_interval = 5;
static const struct kernel_param_ops sample_interval_param_ops =
{
	.set = param_set_common_uint,
	.get = param_get_uint
};
module_param_cb(sample_interval, &sample_interval_param_ops, &sample_interval, 0644);
MODULE_PARM_DESC(sample_interval,"Sampling interval of watchcfs. sample_period = watchcfs_thresh / sample_interval");

static struct cpumask __read_mostly watchcfs_cpumask;
static struct cpumask __read_mostly watchcfs_allowed_mask;
static unsigned long *watchcfs_cpumask_bits = cpumask_bits(&watchcfs_cpumask);
static const struct kernel_param_ops cpumask_param_ops =
{
	.set = param_set_cpumask,
	.get = param_get_cpumask
};
module_param_cb(watchcfs_cpumask_bits, &cpumask_param_ops, &watchcfs_cpumask_bits, 0644);
MODULE_PARM_DESC(watchcfs_cpumask_bits,"CPU mask of watchcfs.");

static int watchcfs_cpuhp_state;
static DEFINE_PER_CPU(unsigned long, watchcfs_touch_ts);
static DEFINE_PER_CPU(struct hrtimer, watchcfs_hrtimer);
static DEFINE_PER_CPU(struct work_struct, watchcfs_work);
static DEFINE_PER_CPU(uint, alert_count);
static DEFINE_PER_CPU(unsigned long, alert_start_time);

static int param_set_common_bool(const char *val, const struct kernel_param *kp)
{
	int ret;
	bool old, *param = kp->arg;

	mutex_lock(&watchcfs_mutex);

	old = READ_ONCE(*param);
	ret = param_set_bool(val, kp);
	if (!ret && old != READ_ONCE(*param))
		watchcfs_update();

	mutex_unlock(&watchcfs_mutex);
	return ret;
}

static int param_set_common_uint(const char *val, const struct kernel_param *kp)
{
	int ret;
	uint old, new;
	uint *param = kp->arg;

	mutex_lock(&watchcfs_mutex);

	ret = kstrtouint(val, 0, &new);
	if (!ret && new == 0) {
		pr_emerg("Please enter a number greater than 0.\n");
		mutex_unlock(&watchcfs_mutex);
		return ret;
	}

	old = READ_ONCE(*param);
	ret = param_set_uint(val, kp);
	if (!ret && old != READ_ONCE(*param))
		watchcfs_update();

	mutex_unlock(&watchcfs_mutex);
	return ret;
}

static int param_set_cpumask(const char *val, const struct kernel_param *kp)
{
	int ret;
	unsigned long new, old;
	unsigned long *cpumask = *(unsigned long **)kp->arg;;

	mutex_lock(&watchcfs_mutex);

	old = READ_ONCE(*cpumask);
	ret = kstrtoul(val, 0, &new);

	if (!ret && old != new) {
		*cpumask = new;
		watchcfs_update();
	}

	mutex_unlock(&watchcfs_mutex);
	return ret;
}

static int param_get_cpumask(char *buffer, const struct kernel_param *kp)
{
    unsigned long *cpumask = *(unsigned long **)kp->arg;
    return scnprintf(buffer, PAGE_SIZE, "%lu\n", *cpumask);
}

/* Returns seconds, approximately. */
static unsigned long get_timestamp(void)
{
	return local_clock() >> 30LL;  /* 2^30 ~= 10^9 */
}

static void set_sample_period(void)
{
	/*
	 * convert watchcfs_thresh from seconds to ns
	 * the divide by sample_interval is to give hrtimer several chances to increment
	 */
	sample_period = watchcfs_thresh * ((u64)NSEC_PER_SEC / sample_interval);
}

static void __touch_watchcfs(void)
{
	__this_cpu_write(watchcfs_touch_ts, get_timestamp());
}

static void watchcfs_work_handler(struct work_struct *data)  
{  
	__touch_watchcfs();
}

static int is_soft_starve(unsigned long touch_ts)
{
	unsigned long now = get_timestamp();

	if (time_after(now, touch_ts + watchcfs_thresh))
		return now - touch_ts;
	
	return 0;
}

static enum hrtimer_restart watchcfs_timer_fn(struct hrtimer *hrtimer)
{
	int duration;
	unsigned long now = get_timestamp();
	unsigned long touch_ts = __this_cpu_read(watchcfs_touch_ts);

	queue_work_on(smp_processor_id(), system_wq, this_cpu_ptr(&watchcfs_work));

	/* .. and repeat */
	hrtimer_forward_now(hrtimer, ns_to_ktime(sample_period));

	if (time_after(now, __this_cpu_read(alert_start_time) + ALERT_INTERVAL_S)) {
		__this_cpu_write(alert_count, 0);
		__this_cpu_write(alert_start_time, now);
	}

	duration = is_soft_starve(touch_ts);
	if (unlikely(duration)) {
		/* Start period for the next softstarve warning. */
		__touch_watchcfs();

		if (__this_cpu_read(alert_count) >= ALERT_LIMIT) {
			pr_emerg("The alarm count limit has been reached on CPU#%d.\n", smp_processor_id());
		} else {
			pr_emerg("BUG: soft starve - CPU#%d stuck for %us! [%s:%d]\n",
				smp_processor_id(), duration,
				current->comm, task_pid_nr(current));
			dump_stack();
			__this_cpu_inc(alert_count);
		}
	}

	return HRTIMER_RESTART;
}

static int softstarve_stop_fn(void *data)
{
	struct hrtimer *hrtimer = this_cpu_ptr(&watchcfs_hrtimer);
	hrtimer_cancel(hrtimer);
	return 0;
}

static void softstarve_stop_all(void)
{
	int cpu;

	for_each_cpu(cpu, &watchcfs_allowed_mask)
		smp_call_on_cpu(cpu, softstarve_stop_fn, NULL, false);

	cpumask_clear(&watchcfs_allowed_mask);
}

static int softstarve_start_fn(void *data)
{
	struct hrtimer *hrtimer = this_cpu_ptr(&watchcfs_hrtimer);
	struct work_struct *work= this_cpu_ptr(&watchcfs_work);

	__this_cpu_write(alert_start_time, get_timestamp());

	INIT_WORK(work, watchcfs_work_handler);

	hrtimer_init(hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	hrtimer->function = watchcfs_timer_fn;
	hrtimer_start(hrtimer, ns_to_ktime(sample_period), 
				HRTIMER_MODE_REL_PINNED);

	/* Initialize timestamp */
	__touch_watchcfs();
	return 0;
}

static void softstarve_start_all(void)
{
	int cpu;

	cpumask_copy(&watchcfs_allowed_mask, &watchcfs_cpumask);
	for_each_cpu(cpu, &watchcfs_allowed_mask)
		smp_call_on_cpu(cpu, softstarve_start_fn, NULL, false);
}

static void starve_detector_reconfigure(void)
{
	cpus_read_lock();

	softstarve_stop_all();
	set_sample_period();
	if (watchcfs_enabled && watchcfs_thresh)
		softstarve_start_all();

	cpus_read_unlock();
}

/* Propagate any changes to the watchcfs module */
static void watchcfs_update(void)
{
	cpumask_and(&watchcfs_cpumask, &watchcfs_cpumask, cpu_possible_mask);
	starve_detector_reconfigure();
}

/* Handling CPU online situation */
static int watchcfs_cpu_online(unsigned int cpu) {
	return softstarve_start_fn(NULL);
}

/* Handling CPU offline situation */
static int watchcfs_cpu_offline(unsigned int cpu) {
	return softstarve_stop_fn(NULL);
}

static int __init starve_detector_init(void)
{
	if (!(watchcfs_enabled && watchcfs_thresh))
		return 0;

	set_sample_period();

	cpumask_copy(&watchcfs_cpumask,
		     housekeeping_cpumask(HK_FLAG_TIMER));
	cpumask_copy(&watchcfs_allowed_mask, &watchcfs_cpumask);

	watchcfs_cpuhp_state = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "watchcfs:online", watchcfs_cpu_online,
                                    watchcfs_cpu_offline);
    if (watchcfs_cpuhp_state < 0) {
		pr_err("Failed to register 'dyn' cpuhp callbacks in starve_detector_init()");
        return watchcfs_cpuhp_state;
    }

	return 0;
}
module_init(starve_detector_init);

static void __exit starve_detector_exit(void) {
	cpuhp_remove_state(watchcfs_cpuhp_state);
}
module_exit(starve_detector_exit);

MODULE_AUTHOR("Zhenhao Guo");
MODULE_DESCRIPTION("A module to monitor cfs task starvation");
MODULE_LICENSE("GPL");