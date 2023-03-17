#ifndef __XARPCHECK_H__
#define __XARPCHECK_H__

#define XDIAG_KERN_STACK_DEPTH 64
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#define XDIAG_MAX_CPUS 256

/* ebpf in kernel */
struct args_user {
	unsigned short kstack_enable;
	unsigned short waitsched_enable;
	unsigned int interrupt_enable;
	unsigned long long threshold;
	unsigned char cpu_mask[XDIAG_MAX_CPUS>>3];
};

struct runinfo {
	pid_t pid;
	unsigned int kstackid;
	unsigned long long start_ns;
};

struct irqinfo {
	int irq;
	unsigned long long nr_irqs;
	unsigned long long irq_start_ns;
};

enum event_type{
	EVENT_UNKNOWN,
	EVENT_SWITCH_OVERTIME,
	EVENT_IRQ_OVERTIME,
	EVENT_WAIT_SCHED,
	EVENT_MAX
};

struct event_schedmonitor {
	/* sched_switch, process info */
	pid_t pid;
	char comm[TASK_COMM_LEN];
	pid_t pid_next;
	char comm_next[TASK_COMM_LEN];
	/* irq info */
	int irq;
	char irqname[16];
	/* common data */
	unsigned int cpu;
	unsigned int type;
	unsigned int kstackid;
	unsigned long long start_ns;
	unsigned long long end_ns;
	unsigned long long runtime_ns;
};

#endif
