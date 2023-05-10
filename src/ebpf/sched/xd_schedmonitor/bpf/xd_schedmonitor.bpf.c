#include "common_k.h"
#include "xd_schedmonitor.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef TASK_RUNNING
#define TASK_RUNNING 0
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct args_user));
} args_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, XDIAG_KERN_STACK_DEPTH * sizeof(long));
	__uint(max_entries, XDIAG_MAX_CPUS * 2);
} run_kstackmap SEC(".maps");

/* waiting for scheduling map, max */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, XDIAG_MAX_CPUS * 16); /* max running tasks */
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
} waiting_map SEC(".maps");

/* percpu map, sched_switch data in kernel space */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, XDIAG_MAX_CPUS);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct runinfo));
} runinfo_map SEC(".maps");

/* percpu map, hard irq data in kernel space */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, XDIAG_MAX_CPUS);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct irqinfo));
} irqinfo_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} ev_overrun SEC(".maps");

static inline u32 is_tracing_cpu(u32 cpu, struct args_user *args)
{
	unsigned char cpuid;
	cpuid = (unsigned char)cpu;
	return args->cpu_mask[cpuid>>3] & (1 << (cpuid % 8));
}

static void trace_wait_pid(pid_t pid)
{
	u64 start;
	if(pid == 0)
		return;
	start = bpf_ktime_get_ns();
	bpf_map_update_elem(&waiting_map, &pid, &start, BPF_ANY);
}

static void trace_wakeup(struct bpf_raw_tracepoint_args *ctx)
{
	u32 cpu;
	u32 key = 0;
	pid_t pid;
	struct args_user *args;
	struct task_struct *p;

	args = bpf_map_lookup_elem(&args_map, &key);
	if(!args || args->threshold == 0 || args->waitsched_enable == 0)
		return;

	cpu = bpf_get_smp_processor_id();
	if(!is_tracing_cpu(cpu, args))
		return;
	p = (struct task_struct *)ctx->args[0];
	bpf_probe_read(&pid, sizeof(pid), &p->pid);
	trace_wait_pid(pid);
}

SEC("raw_tracepoint/sched_wakeup")
int tp__sched_wakeup(struct bpf_raw_tracepoint_args *ctx)
{
	trace_wakeup(ctx);
	return 0;
}

SEC("raw_tracepoint/sched_wakeup_new")
int tp__sched_wakeup_new(struct bpf_raw_tracepoint_args *ctx)
{
	trace_wakeup(ctx);
	return 0;
}

SEC("kprobe/update_process_times")
int kp__update_process_times(struct pt_regs *ctx)
{
	u32 filter_key = 0;
	u32 cpu;
	pid_t pid;
	u64 now, delta;
	struct args_user *args;
	struct runinfo *info;

	args = bpf_map_lookup_elem(&args_map, &filter_key);
	if(!args || args->threshold == 0)
		return 0;
	
	pid = bpf_get_current_pid_tgid() >> 32;
	if(pid == 0)
		return 0;
	
	cpu = bpf_get_smp_processor_id();
	if(!is_tracing_cpu(cpu, args))
		return 0;
	info = bpf_map_lookup_elem(&runinfo_map, &cpu);
	if(!info){
		struct runinfo new;
		__builtin_memset(&new, 0, sizeof(new));
		new.pid = pid;
		new.start_ns =  bpf_ktime_get_ns();
		bpf_map_update_elem(&runinfo_map, &cpu, &new, BPF_NOEXIST);
		return 0;
	}
	if(info->kstackid != 0 || args->kstack_enable == 0)
		return 0;
	
	/* start record kernel stack */
	now = bpf_ktime_get_ns();
	delta = now - info->start_ns;
	if(delta > (args->threshold)){
		info->kstackid = bpf_get_stackid(ctx, &run_kstackmap, \
				BPF_F_FAST_STACK_CMP);
	}
	return 0;
}

SEC("raw_tracepoint/sched_switch")
int tp__sched_switch(struct bpf_raw_tracepoint_args *ctx)
{
	u32 key = 0;
	u32 cpu, prev_pid, next_pid;
	u64 now, delta, *value;
	long state;
	struct args_user *args;
	struct runinfo new, *info;
	struct task_struct *prev, *next;

	args = bpf_map_lookup_elem(&args_map, &key);
	if(!args || args->threshold == 0)
		return 0;

	cpu = bpf_get_smp_processor_id();
	if(!is_tracing_cpu(cpu, args))
		return 0;
	/* reference the source code of tracepoint */
	prev = (struct task_struct *)ctx->args[1];
	next = (struct task_struct *)ctx->args[2];
	bpf_probe_read(&prev_pid, sizeof(prev_pid), &prev->pid);
	bpf_probe_read(&next_pid, sizeof(next_pid), &next->pid);

	now = bpf_ktime_get_ns();
	/* check process run overtime */
	info = bpf_map_lookup_elem(&runinfo_map, &cpu);
	if(info) {
		delta = now - info->start_ns;
		if(delta > args->threshold && prev_pid != 0 \
				&& prev_pid == info->pid){
			struct event_schedmonitor event = {0};
			event.cpu = cpu;
			event.type = EVENT_SWITCH_OVERTIME;
			event.start_ns = info->start_ns;
			event.end_ns = now;
			event.runtime_ns = delta;
			event.pid = prev_pid;
			event.kstackid = info->kstackid;
			bpf_get_current_comm(event.comm, sizeof(event.comm));
			bpf_perf_event_output(ctx, &ev_overrun, BPF_F_CURRENT_CPU, \
					&event, sizeof(event));
			/* record stack next tick */
			info->kstackid = 0;
		}
		/* update percpu runinfo map */
		info->start_ns = now;
		info->pid = BPF_PROBE_VAL(next->pid);
	} else {
		__builtin_memset(&new, 0, sizeof(new));
		new.start_ns =  now;
		new.pid = BPF_PROBE_VAL(next->pid);
		bpf_map_update_elem(&runinfo_map, &cpu, &new, BPF_NOEXIST);
	}

	if(args->waitsched_enable == 0 || next_pid == 0)
		return 0;
	/* if prev task state is running, need be sched again */
	bpf_probe_read(&state, sizeof(state), (void *)(&prev->state));
	if(state == TASK_RUNNING)
		trace_wait_pid(prev_pid);
	/* check schedule slow tasks */
	value = bpf_map_lookup_elem(&waiting_map, &next_pid);
	if(!value)
		return 0;
	if((now - *value) > args->threshold){
		struct event_schedmonitor event = {0};
		event.cpu = cpu;
		event.type = EVENT_WAIT_SCHED;
		event.start_ns = *value;
		event.end_ns = now;
		event.runtime_ns = now - *value;
		event.pid = next_pid;
		bpf_probe_read_str(event.comm, sizeof(event.comm), &(next->comm));
		bpf_perf_event_output(ctx, &ev_overrun, BPF_F_CURRENT_CPU, \
				&event, sizeof(event));
	}
	bpf_map_delete_elem(&waiting_map, &next_pid);
	return 0;
}

SEC("raw_tracepoint/irq_handler_entry")
int tp__irq_handler_entry(struct bpf_raw_tracepoint_args *ctx)
{
	int irq;
	u32 cpu;
	u32 filter_key = 0;
	struct args_user *args;
	struct irqinfo *value;

	args = bpf_map_lookup_elem(&args_map, &filter_key);
	if(!args || args->threshold == 0 || args->interrupt_enable == 0)
		return 0;

	irq = (int)ctx->args[0];
	cpu = bpf_get_smp_processor_id();
	if(!is_tracing_cpu(cpu, args))
		return 0;
	value = bpf_map_lookup_elem(&irqinfo_map, &cpu);
	if(value){
		value->irq_start_ns = bpf_ktime_get_ns();
		value->irq = irq;
		value->nr_irqs ++;
	} else {
		struct irqinfo new = {0};
		new.irq_start_ns = bpf_ktime_get_ns();
		new.irq = irq;
		bpf_map_update_elem(&irqinfo_map, &cpu, &new, BPF_ANY);
	}

	return 0;
}

SEC("raw_tracepoint/irq_handler_exit")
int tp__irq_handler_exit(struct bpf_raw_tracepoint_args *ctx)
{
	int irq;
	u32 cpu;
	u32 filter_key = 0;
	u64 now, delta;
	struct args_user *args;
	struct irqinfo *value;
	struct irqaction *action;

	args = bpf_map_lookup_elem(&args_map, &filter_key);
	if(!args || args->threshold == 0 || args->interrupt_enable == 0)
		return 0;

	irq = (int)ctx->args[0];
	action = (struct irqaction *)ctx->args[1];

	cpu = bpf_get_smp_processor_id();
	if(!is_tracing_cpu(cpu, args))
		return 0;
	value = bpf_map_lookup_elem(&irqinfo_map, &cpu);
	if(!value || irq != value->irq)
		return 0;
	now = bpf_ktime_get_ns();
	delta = now - value->irq_start_ns;
	if(delta > args->threshold){
		char *name;
		struct event_schedmonitor event = {0};
		event.cpu = cpu;
		event.type = EVENT_IRQ_OVERTIME;
		event.start_ns = value->irq_start_ns;
		event.end_ns = now;
		event.runtime_ns = delta;
		event.irq = irq;
		bpf_probe_read(&name, sizeof(name), &action->name);
		bpf_probe_read_str(event.irqname, sizeof(event.irqname), name);
		bpf_perf_event_output(ctx, &ev_overrun, BPF_F_CURRENT_CPU, \
				&event, sizeof(event));
	}
	
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
