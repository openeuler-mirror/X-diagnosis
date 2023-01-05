#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/profile.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/rwsem.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/vmalloc.h>
#include <linux/ktime.h>
#include <linux/stacktrace.h>
#include <linux/ratelimit.h>
#include <linux/fs.h>

#include "show_bt.h"

#define MAX_MONITOR_NUM			(3)
#define MAX_STACK_TRACE_DEPTH   (64)
#define NS_TO_MS(ns)			((u32)((ns) / (s64)1000000))


#define DUMP_WSEM_HOLDER	(0x1)
#define DUMP_RSEM_HOLDER	(0x2)
#define DUMP_MM_FAULT		(0x4)
#define DUMP_ALL (DUMP_WSEM_HOLDER | DUMP_RSEM_HOLDER | DUMP_MM_FAULT)

#define DBG_LV0			(0x40000000)	/* default */
#define DBG_LV1			(0x1)	/* 全局控制数据 */
#define DBG_LV2			(0x2)	/* 读写锁相关 */
#define DBG_LV3			(0x4)	/* workqueue */
#define DBG_LV4			(0x8)	/* mm_fault */
#define DBG_LV5			(0x10)	/* wait on rwsem */
#define DBG_LV6			(0x20)	/* 进程退出 */
#define DBG_LV7			(0x40)	/* dump obj */
#define DBG_LV8			(0x80)	/* init log */

static char *proc[MAX_MONITOR_NUM];
static int proc_num = 0;
module_param_array(proc, charp, &proc_num, 0400);

static char *comm[MAX_MONITOR_NUM];
static int comm_num = 0;
module_param_array(comm, charp, &comm_num, 0400);

static unsigned int uid[MAX_MONITOR_NUM];
static unsigned int uid_num = 0;
module_param_array(uid, uint, &uid_num, 0400);

/* find interval ms */
static unsigned int fims = 10000;
module_param(fims, uint, 0400);
static struct delayed_work fmp_dw;

/* dump interval ms */
static unsigned int dims = 1000;
module_param(dims, uint, 0400);
static struct delayed_work dumptask_dw;

/* tolerate time ms */
static unsigned int ttms = 1000;
module_param(ttms, uint, 0400);

/* short for slow on panic */
static unsigned int sop = 0;
module_param(sop, uint, 0400);

/* short for dump calltrace */
static unsigned int dc = 1;
module_param(dc, uint, 0400);

static unsigned int debug = 0;
module_param(debug, uint, 0400);

static unsigned int dump_scope = DUMP_ALL;
module_param(dump_scope, uint, 0400);

struct monitor_proc {
	pid_t tgid;
	struct rw_semaphore *sem;
	spinlock_t lock;
};

struct task_monitor {
	struct monitor_proc tsk[MAX_MONITOR_NUM];
	atomic_t num_of_found;
} mon;

#define MON_NUM_OF_FOUND()	(&(mon.num_of_found))
#define MON_TASK_TGID(i)	(mon.tsk[i].tgid)
#define MON_TASK_SEM(i)		(mon.tsk[i].sem)
#define MON_TASK_LOCK(i)	(&(mon.tsk[i].lock))

struct my_data {
	struct rw_semaphore *sem;
	ktime_t down_time;
};

struct my_vma {
	struct vm_area_struct *vma;
	unsigned long address;
	unsigned int flags;
};

/*
 * the rw_semaphore used may not belong to monitor task. such as ps/pidof
 */
struct dump_object {
	struct task_struct *caller;
	struct rw_semaphore *tsk_sem;
	ktime_t start;
	spinlock_t lock;
};

struct dump_mngr {
	struct dump_object *obj;
	char *obj_name;
	int obj_cnt;
	int is_dump;
};

static struct dump_mngr rsem_holder = {.obj_name = "rsem holder", .is_dump = DUMP_RSEM_HOLDER};
static struct dump_mngr wsem_holder = {.obj_name = "wsem holder", .is_dump = DUMP_WSEM_HOLDER};
static struct dump_mngr mmfault_caller = {.obj_name = "mm fault", .is_dump = DUMP_MM_FAULT};

static atomic_t mod_exiting = ATOMIC_INIT(0);

#define kinfos(_level, fmt, ...)	({				\
	if ((_level) & debug) {							\
		pr_info(LOG_PFX pr_fmt(fmt), ##__VA_ARGS__);}})

#define kwarns(_level, fmt, ...) ({					\
	if ((_level) & debug) {							\
		pr_warning(LOG_PFX pr_fmt(fmt), ##__VA_ARGS__);}})

#define kerrs(_level, fmt, ...) ({					\
	if ((_level) & debug) {							\
		pr_err(LOG_PFX pr_fmt(fmt), ##__VA_ARGS__);}})

#define kinfo(_level, fmt, ...) kinfos(_level, "[cpu%03d]" pr_fmt(fmt), smp_processor_id(), ##__VA_ARGS__)
#define kwarn(_level, fmt, ...) kwarns(_level, "[cpu%03d]" pr_fmt(fmt), smp_processor_id(), ##__VA_ARGS__)
#define kerr(_level, fmt, ...)   kerrs(_level, "[cpu%03d]" pr_fmt(fmt), smp_processor_id(), ##__VA_ARGS__)

/*
 * down_read/down_read_killable
 * 1. task 等待读锁的时间: [down_read.entry_handler - down_read.handler] 此场景只支持打印等待时长。
 * 2. task 持有读锁的时间: [up_read - down_read.handler] ，当持有锁时间超过阈值，支持打内核栈。
 */
static int down_read_acquire(struct kretprobe_instance *ri, struct pt_regs *regs);
static int down_read_acquired(struct kretprobe_instance *ri, struct pt_regs *regs);
static struct kretprobe kretprobe_down_read = {
	.kp.symbol_name = "down_read",
	.entry_handler = down_read_acquire,
	.handler = down_read_acquired,
	.data_size = sizeof(struct my_data),
};

static struct kretprobe kretprobe_down_read_killable = {
	.kp.symbol_name = "down_read_killable",
	.entry_handler = down_read_acquire,
	.handler = down_read_acquired,
	.data_size = sizeof(struct my_data),
};

static int down_read_trylock_acquire(struct kretprobe_instance *ri, struct pt_regs *regs);
static int down_read_trylock_acquired(struct kretprobe_instance *ri, struct pt_regs *regs);
static struct kretprobe kretprobe_down_read_trylock = {
	.kp.symbol_name = "down_read_trylock",
	.entry_handler = down_read_trylock_acquire,
	.handler = down_read_trylock_acquired,
	.data_size = sizeof(struct my_data),
};

static int down_read_acquired_release(struct kprobe *p, struct pt_regs *regs);
static struct kprobe kp_up_read = {
	.symbol_name = "up_read",
	.pre_handler = down_read_acquired_release,
};

static int down_write_acquire(struct kretprobe_instance *ri, struct pt_regs *regs);
static int down_write_acquired(struct kretprobe_instance *ri, struct pt_regs *regs);
static struct kretprobe kretprobe_down_write = {
	.kp.symbol_name = "down_write",
	.entry_handler = down_write_acquire,
	.handler = down_write_acquired,
	.data_size = sizeof(struct my_data),
};

static struct kretprobe kretprobe_down_write_killable = {
	.kp.symbol_name = "down_write_killable",
	.entry_handler = down_write_acquire,
	.handler = down_write_acquired,
	.data_size = sizeof(struct my_data),
};

static int down_write_trylock_acquire(struct kretprobe_instance *ri, struct pt_regs *regs);
static int down_write_trylock_acquired(struct kretprobe_instance *ri, struct pt_regs *regs);
static struct kretprobe kretprobe_down_write_trylock = {
	.kp.symbol_name = "down_write_trylock",
	.entry_handler = down_write_trylock_acquire,
	.handler = down_write_trylock_acquired,
	.data_size = sizeof(struct my_data),
};

static int down_write_acquired_release(struct kprobe *p, struct pt_regs *regs);
static struct kprobe kp_up_write = {
	.symbol_name = "up_write",
	.pre_handler = down_write_acquired_release,
};

/*
 * 监控进程退出后，需要清理监控信息
 */
static int enter_do_exit(struct kprobe *p, struct pt_regs *regs);
static struct kprobe kp_do_exit = {
	.symbol_name = "do_exit",
	.pre_handler = enter_do_exit,
};

/*
 * 用来观察 do_page_fault 卡在什么流程。常见以下2种场景：
 * 1. 等读锁
 * 2. 持有锁后，内存申请走slow path流程
 */
static int enter_mmfault(struct kretprobe_instance *ri, struct pt_regs *regs);
static int return_mmfault(struct kretprobe_instance *ri, struct pt_regs *regs);
static struct kretprobe kretprobe_mmfault = {
	.kp.symbol_name = "handle_mm_fault",
	.entry_handler = enter_mmfault,
	.handler = return_mmfault,
	.data_size = sizeof(struct my_vma),
};

/*
 * 因为 mmap_sem 是进程共享，所以rw_semaphore个数与被监控的进程个数一致
 */
static int find_rwsem(struct rw_semaphore *sem)
{
	int i;
	for (i = 0; i < MAX_MONITOR_NUM; i++) {
		spin_lock(MON_TASK_LOCK(i));
		if (MON_TASK_SEM(i) != NULL && MON_TASK_SEM(i) == sem) {
			spin_unlock(MON_TASK_LOCK(i));
			return i;
		}
		spin_unlock(MON_TASK_LOCK(i));
	}

	return -1;
}

/*
 * 周期性激活 workqueue 用来 dump 正在被监控的线程
 */
static void fire_dmp_dw(struct task_struct *caller, const char *kp_name)
{
	if (!delayed_work_pending(&dumptask_dw)) {
		DUMP_QUEUE_DELAYED_WORK(&dumptask_dw, msecs_to_jiffies(dims));

		kinfo(DBG_LV3, "[%s][%d:%s:%d] fire dwork\n",
			kp_name, caller->tgid, caller->comm, caller->pid);
	} else {
		kinfo(DBG_LV3, "[%s][%d:%s:%d] dwork is pending\n",
			kp_name, caller->tgid, caller->comm, caller->pid);
	}
}

static void dump_rwsem_owner(void)
{
	int i;
	struct task_struct *owner;

	for (i = 0; i < MAX_MONITOR_NUM; i++) {
		spin_lock(MON_TASK_LOCK(i));
		if (MON_TASK_SEM(i) == NULL) {
			spin_unlock(MON_TASK_LOCK(i));
			continue;
		}

		owner = get_rwsem_owner(MON_TASK_SEM(i));
		if (owner)
			kwarns(DBG_LV0, "monitor[%d] tgid: %d owner=>[%d:%s:%d]\n",
				i, MON_TASK_TGID(i), owner->tgid, owner->comm, owner->pid);
		else
			kwarns(DBG_LV0, "monitor[%d] tgid: %d owner=>reader\n", i, MON_TASK_TGID(i));
		spin_unlock(MON_TASK_LOCK(i));
	}
}

static void show_dump_obj(struct dump_mngr *mngr)
{
	int i;
	int obj_cnt;
	struct dump_object *obj;

	if (!mngr->is_dump) {
		kinfo(DBG_LV7, "[%s] %s dump is off. dump_scope: 0x%x\n",
				__FUNCTION__, mngr->obj_name, dump_scope);
		return;
	}

	obj_cnt = mngr->obj_cnt;
	kinfo(DBG_LV7, "[%s] %s has %d objs (0x%lx)\n",
			__FUNCTION__, mngr->obj_name, obj_cnt, (unsigned long)mngr->obj);

	for (i = 0; i < obj_cnt; i++) {
		struct task_struct *o;
		obj = mngr->obj + i;

		spin_lock(&obj->lock);
		o = obj->caller;
		if (o) {
			kinfo(DBG_LV7, "[%s] obj[%d][%d:%s:%d] tsk_sem: 0x%lx\n",
				__FUNCTION__, i, o->tgid, o->comm, o->pid,
				(unsigned long)obj->tsk_sem);
		} else {
			kinfo(DBG_LV7, "[%s] obj[%d] caller: 0x%lx, tsk_sem: 0x%lx\n",
				__FUNCTION__, i,
				(unsigned long)obj->caller, (unsigned long)obj->tsk_sem);
		}
		spin_unlock(&obj->lock);
	}
}

static void show_all_dump_obj(void)
{
	show_dump_obj(&rsem_holder);
	show_dump_obj(&wsem_holder);
	show_dump_obj(&mmfault_caller);
}

static void down_rwsem_acquire(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct my_data *data;
	struct rw_semaphore *sem;
#ifdef CONFIG_X86_64
	sem = (struct rw_semaphore *)regs->di;
#endif
#ifdef CONFIG_ARM64
	sem = (struct rw_semaphore *)regs->regs[0];
#endif

	data = (struct my_data *)ri->data;
	data->sem = sem;
	data->down_time = ktime_get();
}

static int down_read_acquire(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	down_rwsem_acquire(ri, regs);
	return 0;
}

static int down_write_acquire(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	down_rwsem_acquire(ri, regs);
	return 0;
}

static inline int get_dump_obj(struct dump_mngr *mngr,
							   struct task_struct *expect,
							   struct task_struct *new)
{
	int i;
	struct dump_object *obj;

	for (i = 0; i < mngr->obj_cnt; i++) {
		obj = mngr->obj + i;
		spin_lock(&obj->lock);

		if (obj->caller == expect) {
			if (!expect) {
				obj->caller = new;
				obj->start = ktime_get();
			}
			spin_unlock(&obj->lock);
			return i;
		}
		spin_unlock(&obj->lock);
	}

	return -1;
}

/*
 * now the rw_semaphore has been hold by task, we record the task info for dump later.
 */
static int down_rwsem_done(struct dump_mngr *mngr,
						   struct rw_semaphore *sem,
						   struct task_struct *caller,
						   const char *kp_name)
{
	int i;
	struct dump_object *obj;
	char *obj_name = mngr->obj_name;

	/* add caller to dump objects */
	i = get_dump_obj(mngr, NULL, caller);
	if (-1 == i) {
		kwarn(DBG_LV2, "[%s][%d:%s:%d] exceed limit(%d) not be dump\n",
			obj_name, caller->tgid, caller->comm, caller->pid,
			mngr->obj_cnt);
		return 0;
	}

	obj = mngr->obj + i;
	obj->tsk_sem = sem;

	fire_dmp_dw(caller, kp_name);
	return 0;
}

static void down_rwsem_acquired(struct kretprobe_instance *ri, struct dump_mngr *mngr)
{
	struct my_data *data = (struct my_data *)ri->data;
	const char *kp_name = ri->rp->kp.symbol_name;
	unsigned int wait_rwsem_ms;

	if (-1 == find_rwsem(data->sem))
		return;

	wait_rwsem_ms = NS_TO_MS(ktime_to_ns(ktime_sub(ktime_get(), data->down_time)));
	/* 长时间等锁的task（受害者） */
	if (wait_rwsem_ms > ttms) {
		kwarn(DBG_LV5, "[%d:%s:%d] wait on %s for %u ms\n",
			current->tgid, current->comm, current->pid,
			kp_name, wait_rwsem_ms);
	}

	/* down的返回点是获取到锁的开始，开始记录持有锁的时间点 */
	down_rwsem_done(mngr, data->sem, current, kp_name);
	return;
}

static int down_read_acquired(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	down_rwsem_acquired(ri, &rsem_holder);
	return 0;
}

static int down_write_acquired(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	down_rwsem_acquired(ri, &wsem_holder);
	return 0;
}

static int down_read_trylock_acquire(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	down_rwsem_acquire(ri, regs);
	return 0;
}

static int down_write_trylock_acquire(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	down_rwsem_acquire(ri, regs);
	return 0;
}

static int down_rwsem_trylock_acquired(struct kretprobe_instance *ri,
										  struct pt_regs *regs,
										  struct dump_mngr *mngr)
{
	unsigned long retval;
	struct my_data *data = (struct my_data *)ri->data;
	const char *kp_name = ri->rp->kp.symbol_name;

	if (-1 == find_rwsem(data->sem))
		return 0;

	retval = regs_return_value(regs);
	/* trylock for reading -- returns 1 if successful, 0 if contention */
	if (retval == 1) {
		down_rwsem_done(mngr, data->sem, current, kp_name);
	} else {
		kinfo(DBG_LV2, "[%s] contention [%d:%s:%d] retval: %lu\n",
				kp_name, current->tgid, current->comm, current->pid, retval);
	}
	return 0;
}

static int down_read_trylock_acquired(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	down_rwsem_trylock_acquired(ri, regs, &rsem_holder);
	return 0;
}

static int down_write_trylock_acquired(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	down_rwsem_trylock_acquired(ri, regs, &wsem_holder);
	return 0;
}

/*
 * 不支持跟踪 A 线程 down_rwsem，B 线程 up_rwsem 的场景
 */
static int down_rwsem_acquired_release(struct kprobe *p, struct pt_regs *regs, struct dump_mngr *mngr)
{
	int i;
	unsigned int hold_ms;
	struct rw_semaphore *sem;
	struct dump_object *obj;
	const char *symbol_name = p->symbol_name;
	struct task_struct *task = current;
#ifdef CONFIG_X86_64
	sem = (struct rw_semaphore *)regs->di;
#endif
#ifdef CONFIG_ARM64
	sem = (struct rw_semaphore *)regs->regs[0];
#endif

	if (-1 == find_rwsem(sem))
		return 0;

	/* find current task */
	i = get_dump_obj(mngr, task, task);
	if (-1 == i) {
		kwarn(DBG_LV2, "[%s][%d:%s:%d] not found in %s\n", symbol_name,
			task->tgid, task->comm, task->pid, mngr->obj_name);
		return 0;
	}

	obj = mngr->obj + i;
	hold_ms = NS_TO_MS(ktime_to_ns(ktime_sub(ktime_get(), obj->start)));
	if (hold_ms > ttms) {
		kwarn(DBG_LV0, " warning! [%d:%s:%d] finally %s cost %u ms\n",
				task->tgid, task->comm, task->pid, mngr->obj_name, hold_ms);
	}

	obj->start = ktime_set(0, 0);
	obj->tsk_sem = NULL;
	obj->caller = NULL;	/* avoid pick up this obj early */
	return 0;
}

static int down_read_acquired_release(struct kprobe *p, struct pt_regs *regs)
{
	down_rwsem_acquired_release(p, regs, &rsem_holder);
	return 0;
}

static int down_write_acquired_release(struct kprobe *p, struct pt_regs *regs)
{
	down_rwsem_acquired_release(p, regs, &wsem_holder);
	return 0;
}

static void do_task_dumpstack(struct task_struct *task, const int seq)
{
	static unsigned long entries[MAX_STACK_TRACE_DEPTH * sizeof(unsigned long)];
	struct stack_trace trace;

	trace.nr_entries = 0;
	trace.max_entries = MAX_STACK_TRACE_DEPTH;
	trace.entries = entries;
	trace.skip = 0;

	if (_lock_trace(task)) {
		unsigned int i;

		kwarns(DBG_LV0, " {%d} Call trace:\n", seq);
		save_stack_trace_tsk(task, &trace);

		for (i = 0; i < trace.nr_entries; i++) {
			PRINT_ADDRESS(seq, (void *)entries[i]);
		}

		_unlock_trace(task);
	} else {
		kwarns(DBG_LV0, " {%d} [cpu%02d] mutex_trylock failed for dump [%d:%s:%d]\n",
			seq, smp_processor_id(), task->tgid, task->comm, task->pid);
	}
	return;
}

static int dump_task(struct dump_mngr *mngr)
{
	int i = 0;
	int count = 0;
	int obj_cnt = 0;
	int print_end_mark = 0;
	struct task_struct *task;
	struct dump_object *obj;
	unsigned int cost_ms;

	if (!mngr->is_dump || !atomic_read(MON_NUM_OF_FOUND()) || atomic_read(&mod_exiting))
		goto out;

	obj_cnt = mngr->obj_cnt;
	for (i = 0; i < obj_cnt; i++) {
		obj = mngr->obj + i;
		spin_lock(&obj->lock);
		if (!obj->caller || !ktime_to_ns(obj->start)) {
			spin_unlock(&obj->lock);
			continue;
		}

		count++;
		task = obj->caller;
		spin_unlock(&obj->lock);

		get_task_struct(task);
		cost_ms = NS_TO_MS(ktime_to_ns(ktime_sub(ktime_get(), obj->start)));
		if (cost_ms > ttms) {
			if (count == 1) {
				kinfos(DBG_LV0, "--------------- [cpu%02d] begin to dump %s ---------------\n",
					smp_processor_id(), mngr->obj_name);
				print_end_mark = 1;
			}

			kwarns(DBG_LV0, " {%d} warning! [%d:%s:%d] %s cost %u ms",
				count, task->tgid, task->comm, task->pid, mngr->obj_name, cost_ms);
			
			if (dc)
				do_task_dumpstack(task, count);

			if (sop) {
				panic("%s blocked %u ms", mngr->obj_name, cost_ms);
			}
		}
		put_task_struct(task);
	}

	if (count) {
		if (print_end_mark) {
			kinfos(DBG_LV0, " dump %d task%s\n", count, (count == 1 ? "" : "s"));
			kinfos(DBG_LV0, "--------------- [cpu%02d]   end to dump %s ---------------\n\n",
				smp_processor_id(), mngr->obj_name);
		}
	} else {
		kinfo(DBG_LV3, "[%s] %11s no task dumped in dwork\n",
			__FUNCTION__, mngr->obj_name);
	}
out:
	return count;
}

static int dump_tasks(void)
{
	int i, j;
	int n = 0;
	struct task_struct *p;
	struct task_struct *t;

	if (atomic_read(&mod_exiting))
		goto out;

	n = 1;
	for (i = 0; i < proc_num; i++) {
		rcu_read_lock();
		for_each_process(p) {
			if (0 != strcmp(proc[i], p->comm))
				continue;

			kinfo(DBG_LV0, "---------------- [cpu%02d] begin to dump[%d][%d:%s:%d] ----------------\n",
					smp_processor_id(), n, p->tgid, p->comm, p->pid);
			get_task_struct(p);
			j = 1;
			dump_each_thread(j, p, t, do_task_dumpstack);
			put_task_struct(p);
			kinfo(DBG_LV0, "---------------- [cpu%02d]  end  to dump[%d][%d:%s:%d] ----------------\n\n",
				smp_processor_id(), n, p->tgid, p->comm, p->pid);
			n++;
		}
		rcu_read_unlock();
	}

out:
	return (n > 1 ? 1: 0);
}

static void dump_task_dwork(struct work_struct *work)
{
	int f1, f2, f3, f4;

	f1 = dump_task(&rsem_holder);
	f2 = dump_task(&wsem_holder);
	f3 = dump_task(&mmfault_caller);
	f4 = dump_tasks();

	if (f1 || f2 || f3 || f4) {
		// dump_rwsem_owner();
		DUMP_QUEUE_DELAYED_WORK(&dumptask_dw, msecs_to_jiffies(dims));
	}

	return;
}

static void add_task_to(struct dump_mngr *mngr,
						struct task_struct * const caller,
						const char *kp_name)
{
	int i;
	struct dump_object *obj;

	if (!mngr->is_dump)
		return;

	/* add caller to dump objects */
	i = get_dump_obj(mngr, NULL, caller);
	if (-1 == i) {
		kwarn(DBG_LV4, "[%s][%d:%s:%d] exceed limit(%d) not be dump\n",
			mngr->obj_name, caller->tgid, caller->comm, caller->pid,
			mngr->obj_cnt);
		return;
	}

	obj = mngr->obj + i;
	obj->tsk_sem = (caller->mm ? &(caller->mm->mmap_sem) : NULL);

	fire_dmp_dw(caller, kp_name);
	return;
}

static int rmv_task_from(struct dump_mngr *mngr,
						 struct task_struct *task,
						 const char *kp_name)
{
	int i;
	int ret = 0;
	unsigned int cost_ms;
	struct dump_object *obj;

	if (!mngr->is_dump)
		return 0;

	/* find current task */
	i = get_dump_obj(mngr, task, task);
	if (-1 == i) {
		kwarn(DBG_LV4, "[%s][%d:%s:%d] not found in %s\n", kp_name,
			task->tgid, task->comm, task->pid, mngr->obj_name);
		return 0;
	}

	obj = mngr->obj + i;
	cost_ms = NS_TO_MS(ktime_to_ns(ktime_sub(ktime_get(), obj->start)));
	if (cost_ms > ttms) {
		kwarn(DBG_LV0, " warning! [%d:%s:%d] finally %s cost %u ms\n",
			task->tgid, task->comm, task->pid, mngr->obj_name, cost_ms);
		ret = 1;
	}

	obj->start = ktime_set(0, 0);
	obj->tsk_sem = NULL;
	obj->caller = NULL;
	return ret;
}

static int find_proc(struct task_struct *task)
{
	int i;
	for (i = 0; i < MAX_MONITOR_NUM; i++) {
		spin_lock(MON_TASK_LOCK(i));
		if (task->tgid == MON_TASK_TGID(i)) {
			spin_unlock(MON_TASK_LOCK(i));
			return i;
		}

		spin_unlock(MON_TASK_LOCK(i));
	}
	return -1;
}

static int enter_mmfault(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int i = find_proc(current);
	if (-1 != i) {
		const char *kp_name = ri->rp->kp.symbol_name;
		struct my_vma *data = (struct my_vma *)ri->data;

#ifdef CONFIG_X86_64
		data->vma = (struct vm_area_struct *)regs->di;
		data->address = regs->si;
		data->flags = regs->dx;
#endif
#ifdef CONFIG_ARM64
		data->vma = (struct vm_area_struct *)regs->regs[0];
		data->address = regs->regs[1];
		data->flags = regs->regs[2];
#endif
		add_task_to(&mmfault_caller, current, kp_name);
	}

	return 0;
}

static void show_file_mapping(struct kretprobe_instance *ri, struct task_struct *task)
{
	struct my_vma *data = (struct my_vma *)ri->data;
	unsigned long vm_start = 0;
	unsigned long vm_end = 0;
	char *name = "anon";
	if (data && data->vma) {
		struct vm_area_struct *vma = data->vma;
		struct file *vm_file = vma->vm_file;
		vm_start = vma->vm_start;
		vm_end = vma->vm_end;
		if (vm_file) {
			struct dentry* d = vm_file->f_path.dentry;
			name = "file?";
			if (d) {
				name = d->d_iname;
			}
		}
		kwarn(DBG_LV0, " warning! [%d:%s:%d] finally %s [%lx-%lx:%lx:0x%x:%s]\n",
				task->tgid, task->comm, task->pid, mmfault_caller.obj_name,
				vm_start, vm_end, data->address, data->flags, name);
	}
	return;
}

static int return_mmfault(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	const char *kp_name = ri->rp->kp.symbol_name;
	int i = find_proc(current);
	if (-1 == i)
		return 0;

	if (rmv_task_from(&mmfault_caller, current, kp_name)) {
		show_file_mapping(ri, current);
	}
	return 0;
}

static void clear_dump_obj(struct dump_mngr *mngr,
						struct task_struct *cur,
						struct task_struct *tsk,
						struct rw_semaphore *sem)
{
	int i;
	int clear = 0;
	int obj_cnt;
	struct dump_object *obj;

	if (!mngr->is_dump)
		return;

	obj_cnt = mngr->obj_cnt;
	for (i = 0; i < obj_cnt; i++) {
		obj = mngr->obj + i;
		spin_lock(&obj->lock);
		if (tsk && tsk == obj->caller) {
			clear = 1;
			kinfo(DBG_LV7, "[%s by tsk] %s obj[%d][%d:%s:%d] tsk_sem: 0x%lx\n",
				__FUNCTION__, mngr->obj_name, i, tsk->tgid, tsk->comm, tsk->pid,
				(unsigned long)obj->tsk_sem);
		}
		if (!clear && (sem && sem == obj->tsk_sem)) {
			clear = 1;
			kinfo(DBG_LV7, "[%s by sem] %s obj[%d][%d:%s:%d] tsk_sem: 0x%lx\n",
				__FUNCTION__, mngr->obj_name, i, cur->tgid, cur->comm, cur->pid,
				(unsigned long)sem);
		}
	
		if (clear) {
			obj->start = ktime_set(0, 0);
			obj->tsk_sem = NULL;
			obj->caller = NULL;
		}
		spin_unlock(&obj->lock);
	}
}

static void clear_dump_objs(struct task_struct *cur, const int by_rwsem)
{
	struct rw_semaphore *sem = NULL;
	struct task_struct  *tsk = NULL;
	if (by_rwsem)
		sem = (cur->mm ? &(cur->mm->mmap_sem) : NULL);
	else
		tsk = cur;

	clear_dump_obj(&rsem_holder, cur, tsk, sem);
	clear_dump_obj(&wsem_holder, cur, tsk, sem);
	clear_dump_obj(&mmfault_caller, cur, tsk, sem);
}

/*
 * task A 是被监控进程
 * 场景1: “其它” task 持有 task A 的 rwsem 锁，“其它” task 未释放锁就退出（实际属于bug场景或者是测试场景）。
 * 当“其它” task 退出时，需要清除 objs 里的“其它” task 信息。
 *
 * 场景2: “其它” task 持有 task A 的 rwsem 锁，task A 退出。
 * task A 退出时，需要清理 objs 里所有涉及 task A 的 rwsem 锁的信息。
 */
static int enter_do_exit(struct kprobe *p, struct pt_regs *regs)
{
	int i;
	int main_exit = 0;
#ifdef CONFIG_X86_64
	long exit_code = regs->di;
#endif
#ifdef CONFIG_ARM64
	long exit_code = regs->regs[0];
#endif

	i = find_proc(current);
	if (-1 != i) {
		if (current->pid == current->tgid) {
			main_exit = 1;
			kinfo(DBG_LV0, "[do_exit][%d:%s:%d] main exit(%ld)\n",
					current->tgid, current->comm, current->pid, exit_code);

			atomic_dec(MON_NUM_OF_FOUND());

			spin_lock(MON_TASK_LOCK(i));
			MON_TASK_TGID(i) = 0;
			MON_TASK_SEM(i) = NULL;
			spin_unlock(MON_TASK_LOCK(i));

			clear_dump_objs(current, 1);
		} else {
			kinfo(DBG_LV6, "[do_exit][%d:%s:%d] child exit(%ld)\n",
					current->tgid, current->comm, current->pid, exit_code);
		}
	}

	if (main_exit)
		show_all_dump_obj();
	else
		clear_dump_objs(current, 0);

	return 0;
}

static void unregister_kretprobe_down_read(void)
{
	unregister_kretprobe(&kretprobe_down_read);
	kinfo(DBG_LV8, " unregistered %s\n", kretprobe_down_read.kp.symbol_name);
}

static void unregister_kprobe_down_read_killable(void)
{
	unregister_kretprobe(&kretprobe_down_read_killable);
	kinfo(DBG_LV8, " unregistered %s\n", kretprobe_down_read_killable.kp.symbol_name);
}

static void unregister_kretprobe_down_read_trylock(void)
{
	unregister_kretprobe(&kretprobe_down_read_trylock);
	kinfo(DBG_LV8, " unregistered %s\n", kretprobe_down_read_trylock.kp.symbol_name);
}

static void unregister_kprobe_up_read(void)
{
	unregister_kprobe(&kp_up_read);
	kinfo(DBG_LV8, " unregistered %s\n", kp_up_read.symbol_name);
}

static void unregister_kretprobe_down_write(void)
{
	unregister_kretprobe(&kretprobe_down_write);
	kinfo(DBG_LV8, " unregistered %s\n", kretprobe_down_write.kp.symbol_name);
}

static void unregister_kprobe_down_write_killable(void)
{
	unregister_kretprobe(&kretprobe_down_write_killable);
	kinfo(DBG_LV8, " unregistered %s\n", kretprobe_down_write_killable.kp.symbol_name);
}

static void unregister_kretprobe_down_write_trylock(void)
{
	unregister_kretprobe(&kretprobe_down_write_trylock);
	kinfo(DBG_LV8, " unregistered %s\n", kretprobe_down_write_trylock.kp.symbol_name);
}

static void unregister_kprobe_up_write(void)
{
	unregister_kprobe(&kp_up_write);
	kinfo(DBG_LV8, " unregistered %s\n", kp_up_write.symbol_name);
}

static void unregister_kprobe_do_exit(void)
{
	unregister_kprobe(&kp_do_exit);
	kinfo(DBG_LV8, " unregistered %s\n", kp_do_exit.symbol_name);
}

static void unregister_kretprobe_mmfault(void)
{
	unregister_kretprobe(&kretprobe_mmfault);
	kinfo(DBG_LV8, " unregistered %s\n", kretprobe_mmfault.kp.symbol_name);
}

static int register_kp_readsem(void)
{
	int ret = 0;

	/* up_read */
	ret = register_kprobe(&kp_up_read);
	if (ret < 0) {
		kerr(DBG_LV0, " kprobe failed: %s\n", kp_up_read.symbol_name);
		goto out;
	}
	kinfo(DBG_LV8, " kprobe success: %s\n", kp_up_read.symbol_name);

	/* down_read */
	ret = register_kretprobe(&kretprobe_down_read);
	if (ret < 0) {
		kerr(DBG_LV0, " kretprobe failed: %s\n", kretprobe_down_read.kp.symbol_name);
		goto unreg_up_read;
	}
	kinfo(DBG_LV8, " kretprobe success: %s\n", kretprobe_down_read.kp.symbol_name);

	/* down_read_trylock */
	ret = register_kretprobe(&kretprobe_down_read_trylock);
	if (ret < 0) {
		kerr(DBG_LV0, " kretprobe failed: %s\n", kretprobe_down_read_trylock.kp.symbol_name);
		goto unreg_down_read;
	}
	kinfo(DBG_LV8, " kretprobe success: %s\n", kretprobe_down_read_trylock.kp.symbol_name);

	/* down_read_killable */
	if (is_symbol_kprobe_support(kretprobe_down_read_killable.kp.symbol_name)) {
		ret = register_kretprobe(&kretprobe_down_read_killable);
		if (ret < 0) {
			kerr(DBG_LV0, " kretprobe failed: %s\n", kretprobe_down_read_killable.kp.symbol_name);
			goto unreg_down_read_trylock;
		} else {
			kinfo(DBG_LV8, " kretprobe success: %s\n", kretprobe_down_read_killable.kp.symbol_name);
		}
	}

	return 0;

unreg_down_read_trylock:
	unregister_kretprobe_down_read_trylock();
unreg_down_read:
	unregister_kretprobe_down_read();
unreg_up_read:
	unregister_kprobe_up_read();
out:
	return ret;
}

static int register_kp_writesem(void)
{
	int ret = 0;

	/* up_write */
	ret = register_kprobe(&kp_up_write);
	if (ret < 0) {
		kerr(DBG_LV0, " kprobe failed: %s\n", kp_up_write.symbol_name);
		goto out;
	}
	kinfo(DBG_LV8, " kprobe success: %s\n", kp_up_write.symbol_name);

	/* down_write */
	ret = register_kretprobe(&kretprobe_down_write);
	if (ret < 0) {
		kerr(DBG_LV0, " kretprobe failed: %s\n", kretprobe_down_write.kp.symbol_name);
		goto unreg_up_write;
	}
	kinfo(DBG_LV8, " kretprobe success: %s\n", kretprobe_down_write.kp.symbol_name);

	/* down_write_trylock */
	ret = register_kretprobe(&kretprobe_down_write_trylock);
	if (ret < 0) {
		kerr(DBG_LV0, " kretprobe failed: %s\n", kretprobe_down_write_trylock.kp.symbol_name);
		goto unreg_down_write;
	}
	kinfo(DBG_LV8, " kretprobe success: %s\n", kretprobe_down_write_trylock.kp.symbol_name);

	/* down_write_killable */
	if (is_symbol_kprobe_support(kretprobe_down_write_killable.kp.symbol_name)) {
		ret = register_kretprobe(&kretprobe_down_write_killable);
		if (ret < 0) {
			kerr(DBG_LV0, " kretprobe failed: %s\n", kretprobe_down_write_killable.kp.symbol_name);
			goto unreg_down_write_trylock;
		} else {
			kinfo(DBG_LV8, " kretprobe success: %s\n", kretprobe_down_write_killable.kp.symbol_name);
		}
	}

	return 0;

unreg_down_write_trylock:
	unregister_kretprobe_down_write_trylock();
unreg_down_write:
	unregister_kretprobe_down_write();
unreg_up_write:
	unregister_kprobe_up_write();
out:
	return ret;
}

static void unregister_kp(void)
{
	unregister_kretprobe_down_read();
	unregister_kprobe_down_read_killable();
	unregister_kretprobe_down_read_trylock();
	unregister_kprobe_up_read();

	unregister_kretprobe_down_write();
	unregister_kprobe_down_write_killable();
	unregister_kretprobe_down_write_trylock();
	unregister_kprobe_up_write();

	unregister_kprobe_do_exit();
	unregister_kretprobe_mmfault();
}

static int register_kp(void)
{
	int ret = 0;

	ret = register_kp_readsem();
	if (ret < 0)
		goto out;

	ret = register_kp_writesem();
	if (ret < 0)
		goto out;

	/* do_exit */
	ret = register_kprobe(&kp_do_exit);
	if (ret < 0) {
		kerr(DBG_LV0, " kprobe failed: %s\n", kp_do_exit.symbol_name);
		goto out;
	}
	kinfo(DBG_LV8, " kprobe success: %s\n", kp_do_exit.symbol_name);

	/* handle_mm_fault */
	ret = register_kretprobe(&kretprobe_mmfault);
	if (ret < 0) {
		kerr(DBG_LV0, " kretprobe failed: %s\n", kretprobe_mmfault.kp.symbol_name);
		goto unreg_do_exit;
	}
	kinfo(DBG_LV8, " kretprobe success: %s\n", kretprobe_mmfault.kp.symbol_name);

	return 0;

unreg_do_exit:
	unregister_kprobe_do_exit();
out:
	return ret;
}

static uid_t _uid(struct task_struct *task)
{
	const struct cred *cred = __task_cred(task);
	return _UID_VALUE(cred);
}

/*
 * return 1 all monitor processes have been found, else return 0
 */
static int if_all_procs_found(const int tell_miss)
{
	static int print_all_found = 1;
	int found_num = 0;
	int i = 0;

	for (i = 0; i < comm_num; i++) {
		spin_lock(MON_TASK_LOCK(i));
		if (MON_TASK_TGID(i)) {
			found_num++;
		} else {
			if (tell_miss)
				kinfo(DBG_LV6, " not found [%d] %s(%d)\n", i, comm[i], uid[i]);
		}
		spin_unlock(MON_TASK_LOCK(i));
	}

	atomic_set(MON_NUM_OF_FOUND(), found_num);
	if (found_num == comm_num) {
		if (print_all_found)
			kinfo(DBG_LV0, " all %d %s found\n",
					found_num, (found_num > 1 ? "tasks" : "task"));
		print_all_found = 0;
		return 1;
	} else {
		print_all_found = 1;
	}

	return 0;
}

static void do_find_monitor_process(void)
{
	int i = 0;
	int lv;
	struct task_struct *p;
	char *state = "found";

	for (i = 0; i < comm_num; i++) {
		rcu_read_lock();
		for_each_process(p) {
			get_task_struct(p);
			/* task cred protect by rcu read lock */
			if (0 == strcmp(comm[i], p->comm) && uid[i] == _uid(p)) {
				if (unlikely(p->flags & PF_EXITING)) {
					kinfo(DBG_LV0, " found [%d][%d:%s](%d) but exiting\n",
							i, p->tgid, comm[i], uid[i]);
				} else {
					spin_lock(MON_TASK_LOCK(i));
					if (0 != MON_TASK_TGID(i)) {
						state = "saved";
						lv = DBG_LV6;
					} else {
						MON_TASK_TGID(i) = p->tgid;
						MON_TASK_SEM(i) = (p->mm ? &(p->mm->mmap_sem) : NULL);
						state = "found";
						lv = DBG_LV0;
					}
					spin_unlock(MON_TASK_LOCK(i));
					put_task_struct(p);
					kinfo(lv, " %s [%d][%d:%s](%d) %s task(sem: 0x%lx)\n",
							state, i, MON_TASK_TGID(i), comm[i], uid[i],
							(p->mm ? "user" : "kernel"), (unsigned long)MON_TASK_SEM(i));
					break;
				}
			}
			put_task_struct(p);
		}
		rcu_read_unlock();
	}
}

static void rwsem_fmp_dwork(void)
{
	/* avoid unnecessary find after all monitor tasks found */
	if (if_all_procs_found(0))
		goto fire;

	do_find_monitor_process();

	if_all_procs_found(1);
fire:
	/* in case task exit */
	schedule_delayed_work(&fmp_dw, msecs_to_jiffies(fims));
}

static void showbt_fmp_dwork(void)
{
	fire_dmp_dw(current, "dump call trace");
}

static void find_monitor_proc_dwork(struct work_struct *work)
{
	if (comm_num) {
		rwsem_fmp_dwork();
	} else {
		showbt_fmp_dwork();
	}
}

static int check_rwsem_param(void)
{
	int i;
	if (comm_num != uid_num || comm_num == 0) {
		kerr(DBG_LV0, "[%s] the number of comm should be equal to uid\n", __FUNCTION__);
		return -EINVAL;
	}

	for (i = 0; i < comm_num; i++) {
		if (strlen(comm[i] - 1) > TASK_COMM_LEN) {
			kerr(DBG_LV0, "[%s] comm[%d]:%s exceeds max limit %d\n",
					__FUNCTION__, i, comm[i], TASK_COMM_LEN - 1);
			return -EINVAL;
		}
	}

	if (!ttms)
		ttms = dims / 2;
	kinfo(DBG_LV0, "[%s] dump interval: %u ms, tolerate time: %u ms\n",
			__FUNCTION__, dims, ttms);
	return 0;
}

static int check_showbt_param(void)
{
	int i;
	if (proc_num == 0) {
		kerr(DBG_LV0, "[%s] the number of proc is 0\n", __FUNCTION__);
		return -EINVAL;
	}

	for (i = 0; i < proc_num; i++) {
		if (strlen(proc[i] - 1) > TASK_COMM_LEN) {
			kerr(DBG_LV0, "[%s] proc[%d]:%s exceeds max limit %d\n",
					__FUNCTION__, i, proc[i], TASK_COMM_LEN - 1);
			return -EINVAL;
		}
	}
	return 0;
}

static int check_parameters(void)
{
	if (comm_num)
		return check_rwsem_param();
	else
		return check_showbt_param();
}

static void init_dump_manager(struct dump_mngr *mngr)
{
	int i;
	int obj_cnt = mngr->obj_cnt;
	struct dump_object *obj;

	for (i = 0; i < obj_cnt; i++) {
		obj = mngr->obj + i;
		obj->caller = NULL;
		obj->tsk_sem = NULL;
		obj->start = ktime_set(0, 0);
		spin_lock_init(&obj->lock);
	}
}

static void free_dump_manager(struct dump_mngr *mngr)
{
	if (!mngr->is_dump)
		return;

	mngr->is_dump = 0;
	mngr->obj_cnt = 0;
	vfree(mngr->obj);
	mngr->obj = NULL;
}

static void init_monitor_table(const int insmod)
{
	int i;
	atomic_set(MON_NUM_OF_FOUND(), 0);
	for (i = 0; i < MAX_MONITOR_NUM; i++) {
		MON_TASK_TGID(i) = 0;
		MON_TASK_SEM(i) = NULL;
		spin_lock_init(MON_TASK_LOCK(i));
	}

	if (insmod) {
		kinfo(DBG_LV8, "[%s] task monitor: 0x%lx. size: %lu (%lu*%d)\n",
			__FUNCTION__, (unsigned long)&mon,
			sizeof(mon), sizeof(struct monitor_proc), MAX_MONITOR_NUM);
	}
}

/* return 1 success, else 0 failed */
static int alloc_dump_obj(struct dump_mngr *mngr, int obj_cnt)
{
	unsigned long alloc_size;
	mngr->is_dump = dump_scope & mngr->is_dump;
	kinfo(DBG_LV8, "[%s] %11s mngr: 0x%lx %s\n",
			__FUNCTION__, mngr->obj_name,
			(unsigned long)mngr, mngr->is_dump ? "" : "(not set)");
	if (!mngr->is_dump) {
		return 1;
	}

	mngr->obj_cnt = obj_cnt;
	alloc_size = sizeof(struct dump_object) * mngr->obj_cnt;
	mngr->obj = (struct dump_object *)vmalloc(alloc_size);
	if (mngr->obj)
		init_dump_manager(mngr);

	kinfo(DBG_LV8, "[%s] %11s  obj: 0x%lx, size: %lu (%ld*%d)\n",
			__FUNCTION__, mngr->obj_name, (unsigned long)mngr->obj,
			alloc_size, sizeof(struct dump_object), mngr->obj_cnt);
	return (mngr->obj ? 1 : 0);
}

static int init_data(void)
{
	int num_cpus;
	num_cpus = num_online_cpus();

	init_monitor_table(1);

	if (!alloc_dump_obj(&rsem_holder, num_cpus))
		goto out;

	if (!alloc_dump_obj(&wsem_holder, num_cpus))
		goto free_rsem_holder_obj;

	if (!alloc_dump_obj(&mmfault_caller, num_cpus))
		goto free_wsem_holder_obj;

	return 0;

free_rsem_holder_obj:
	free_dump_manager(&rsem_holder);
free_wsem_holder_obj:
	free_dump_manager(&wsem_holder);
out:
	return 1;
}

static int __init show_bt_init(void)
{
	int ret = 0;

	debug |= (DBG_LV0 | DBG_LV1);
	kinfo(DBG_LV8, "[%s] begin\n", __FUNCTION__);

	ret = check_parameters();
	if (ret != 0)
		goto out;

	ret = init_data();
	if (ret != 0)
		goto out;

	/* 注册之前要确保探测点使用的数据已经初始化好 */
	ret = register_kp();
	if (ret != 0)
		goto out;

	/* 现在可以开始搜索监控进程了 */
	INIT_DELAYED_WORK(&fmp_dw, find_monitor_proc_dwork);
	INIT_DELAYED_WORK(&dumptask_dw, dump_task_dwork);
	schedule_delayed_work(&fmp_dw, 0);
	kinfo(DBG_LV0, "[%s] success\n\n", __FUNCTION__);
	return 0;

out:
	kerr(DBG_LV0, "[%s] failed\n\n", __FUNCTION__);
	return ret;
}

static void __exit show_bt_exit(void)
{
	atomic_inc(&mod_exiting);

	unregister_kp();

	cancel_delayed_work_sync(&dumptask_dw);
	cancel_delayed_work_sync(&fmp_dw);

	free_dump_manager(&rsem_holder);
	free_dump_manager(&wsem_holder);
	free_dump_manager(&mmfault_caller);

	init_monitor_table(0);

	kinfo(DBG_LV0, "[%s] success\n\n", __FUNCTION__);
}

module_init(show_bt_init)
module_exit(show_bt_exit)
MODULE_LICENSE("GPL");
