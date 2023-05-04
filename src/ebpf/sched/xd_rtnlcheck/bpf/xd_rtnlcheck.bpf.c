#include "common_k.h"
#include "xd_rtnlcheck.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} info_event SEC(".maps");

long rtnl_lock_addr = 0;

static __inline int check_lock_info(struct pt_regs *ctx)
{
	long owner;
	struct mutex rtnl_mutex = {0};
	struct task_struct *owner_task = NULL;
	struct event_rtnl event = {0};

	bpf_probe_read(&rtnl_mutex, sizeof(struct mutex), (void *)rtnl_lock_addr);
	bpf_probe_read(&owner, sizeof(long), &rtnl_mutex.owner);
	owner_task = (struct task_struct *)(owner & ~0x07);
	if (owner_task != NULL) {
		bpf_probe_read(&event.pid, sizeof(pid_t), &(owner_task->pid));
		bpf_probe_read(&event.comm, sizeof(event.comm), owner_task->comm);
	}

	bpf_perf_event_output(ctx, &info_event, BPF_F_CURRENT_CPU, \
			&event, sizeof(struct event_rtnl));

	return 0;
}

SEC("kprobe/rtnl_lock")
int rtnl_lock_check(struct pt_regs *ctx)
{
	check_lock_info(ctx);
	return 0;
}

SEC("kprobe/rtnl_trylock")
int rtnl_trylock_check(struct pt_regs *ctx)
{
	check_lock_info(ctx);
	return 0;
}

SEC("kprobe/rtnl_lock_killable")
int rtnl_lock_killable_check(struct pt_regs *ctx)
{
	check_lock_info(ctx);
	return 0;
}

SEC("kprobe/refcount_dec_and_rtnl_lock")
int refcount_dec_and_rtnl_lock_check(struct pt_regs *ctx)
{
	check_lock_info(ctx);
	return 0;
}

char _license[] SEC("license") = "GPL";
