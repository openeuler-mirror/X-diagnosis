#ifndef _KERNEL_TOOLS_SHOW_BT_H_
#define _KERNEL_TOOLS_SHOW_BT_H_

#include <linux/version.h>
#include <linux/workqueue.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
#include <linux/sched/signal.h>
#define OWNER_MASK 				(0xfffffffffffffffc)

#endif /* LINUX_VERSION_CODE */

#elif LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0)
extern struct workqueue_struct *system_highpri_wq;
struct task_struct *get_rwsem_owner(struct rw_semaphore *rwsem)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
	unsigned long owner_addr = ((unsigned long)rwsem->owner) & OWNER_MASK;
	if (owner_addr) {
		return (struct task_struct *)owner_addr;
	} else {
		return NULL;
	}
#elif LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0) || LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 32)
		return NULL;
#else
		/* let the compiler report an error */
#endif
}

int has_rwsem_owner(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
		return 1;
#elif LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0) || LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 32)
		return 0;
#endif
}

#define DOWN_READ_KILLABLE_SYMBOL_NAME	"down_read_killable"
#define DOWN_WRITE_KILLABLE_SYMBOL_NAME	"down_write_killable"
int is_symbol_kprobe_support(const char *name)
{
	if ((0 == strcmp(name, DOWN_READ_KILLABLE_SYMBOL_NAME))
	 || (0 == strcmp(name, DOWN_WRITE_KILLABLE_SYMBOL_NAME))) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
		return 1;
#elif LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0) || LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 32)
		return 0;
#else
		/* let the compiler report an error */
#endif
	} else {
		return 1;
	}
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)  || LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0)
#define DUMP_QUEUE_DELAYED_WORK(dwork, delay)	queue_delayed_work(system_highpri_wq, (dwork), (delay))
#define _UID_VALUE(cred)	(__kuid_val((cred)->uid))
#define PRINT_ADDRESS(seq, addr)	printk(" {%d}    %pB\n", (seq), (addr))
#define dump_each_thread(j, p, t, dump_func)\
	for_each_thread(p, t) {					\
		printk(" {%d} [%d:%s:%d]\n", j, t->tgid, t->comm, t->pid);	\
		dump_func(t, j);					\
		j++;								\
	}

static int _lock_trace(struct task_struct *task) { return mutex_trylock(&task->signal->cred_guard_mutex); }
static void _unlock_trace(struct task_struct *task) { mutex_unlock(&task->signal->cred_guard_mutex); }
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 32)
#define DUMP_QUEUE_DELAYED_WORK(dwork, delay)	schedule_delayed_work((dwork), (delay))
#define _UID_VALUE(cred)	((cred)->uid)
#define PRINT_ADDRESS(seq, addr)	printk(" {%d}    %pS\n", (seq), (addr))
#define dump_each_thread(j, p, t, dump_func)\
	t = p;									\
	do {									\
		printk(" {%d} [%d:%s:%d]\n", j, t->tgid, t->comm, t->pid);	\
		dump_func(t, j);					\
		j++;								\
	} while_each_thread(p, t)

static int _lock_trace(struct task_struct *task) { return 1; }
static void _unlock_trace(struct task_struct *task) {}

#endif

#endif /* _KERNEL_TOOLS_SHOW_BT_H_ */
