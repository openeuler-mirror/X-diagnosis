#include "common_k.h"
#include "xd_tcphandcheck.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)

#define BPF_PROBE_VAL(P) \
({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})

#define MAX_PROBE_HASH 1024

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct inet_bind_args);
	__uint(max_entries, MAX_PROBE_HASH);
} probe_args SEC(".maps");

struct{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct hook_key);
	__type(value, struct xd_addr_info);
	__uint(max_entries, MAX_PROBE_HASH);
} tw_process_args SEC(".maps");

struct{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct hook_key);
	__type(value, struct xd_addr_info);
	__uint(max_entries, MAX_PROBE_HASH);
} tcp_in_window_args SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, u32);
	__type(value, u32);
} xd_kern_events SEC(".maps");

static __inline int parse_inet_bind_args(struct pt_regs *ctx)
{
	struct inet_bind_args args = {0};
	struct sockaddr_in *uaddr = NULL;
	
	uaddr = (struct sockaddr_in *)PT_REGS_PARM2(ctx);
	if (!uaddr) {
		bpf_printk("tcphandchk: inet_bind uaddr is Null\n");
	}

	args.port = BPF_PROBE_VAL(uaddr->sin_port);
	args.addr = BPF_PROBE_VAL(uaddr->sin_addr.s_addr);

	unsigned long raw_ctx = 0;

	pid_t pid;
	pid = bpf_get_current_pid_tgid();
	
	bpf_map_update_elem(&probe_args, &pid, &args, BPF_NOEXIST);

	return 0;
}

static __inline int chk_inet_bind_ret(struct pt_regs *ctx)
{
	struct inet_bind_args *uaddr = NULL;
	int func_ret = PT_REGS_RC(ctx);

	pid_t pid;
	pid = bpf_get_current_pid_tgid();

	uaddr = bpf_map_lookup_elem(&probe_args, &pid);
	if (!uaddr) {
		return 0;
	}

	struct xd_kern_msg kern_msg = {0};

	kern_msg.addr_info.srcaddr = uaddr->addr;
	kern_msg.addr_info.srcport = uaddr->port;
	kern_msg.retval = func_ret;
	kern_msg.msg_type = __INET_BIND;

	bpf_perf_event_output(ctx, &xd_kern_events, BPF_F_CURRENT_CPU, \
			&kern_msg, sizeof(struct xd_kern_msg));

	bpf_map_delete_elem(&probe_args, &pid);

	return 0;
}

static __inline int chk_sys_socket_ret(struct pt_regs *ctx)
{
	int func_ret = PT_REGS_RC(ctx);
	struct xd_kern_msg kern_msg = {0};

	if (func_ret >= 0) {
		return 0;
	}

	kern_msg.retval = func_ret;
	kern_msg.msg_type = SOCKET_CREATE;

	bpf_perf_event_output(ctx, &xd_kern_events, BPF_F_CURRENT_CPU, \
			&kern_msg, sizeof(struct xd_kern_msg));

	return 0;
}

static __inline int parse_syn_recv_args(struct pt_regs *ctx)
{
	struct sock *sk;
	struct sk_buff *skb;
	unsigned int sk_ack_backlog;
	unsigned int sk_max_ack_backlog;
	struct xd_addr_info backlog_addr;

	sk = (struct sock *)PT_REGS_PARM1(ctx);
	if (!sk) {
		bpf_printk("tcphandchk: syn_recv_sock sk is Null\n");
		return 0;
	}

	skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
	if (!skb) {
		bpf_printk("tcphandchk: syn_recv_sock skb is Null\n");
		return 0;
	}

	sk_ack_backlog = BPF_PROBE_VAL(sk->sk_ack_backlog);
	sk_max_ack_backlog = BPF_PROBE_VAL(sk->sk_max_ack_backlog);

	struct iphdr *xd_iphdr;
	struct tcphdr *xd_tcphdr;

	void *raw_tcphdr = NULL;
	void *raw_iphdr  = NULL;

	raw_tcphdr = BPF_PROBE_VAL(skb->data);
	raw_iphdr = raw_tcphdr - XD_TCPHDR_LENGTH;

	xd_iphdr = (struct iphdr *)BPF_PROBE_VAL(raw_iphdr);
	xd_tcphdr = (struct tcphdr *)BPF_PROBE_VAL(raw_tcphdr);

	backlog_addr.srcaddr = BPF_PROBE_VAL(xd_iphdr->saddr);
	backlog_addr.dstaddr = BPF_PROBE_VAL(xd_iphdr->daddr);
	backlog_addr.srcport = BPF_PROBE_VAL(xd_tcphdr->source);
	backlog_addr.dstport = BPF_PROBE_VAL(xd_tcphdr->dest);

	struct xd_kern_msg kern_msg = {0};

	kern_msg.addr_info = backlog_addr;
	kern_msg.msg_type = TCP_V4_SYN_RECV_SOCK;

	if (sk_ack_backlog >= sk_max_ack_backlog) {
		bpf_perf_event_output(ctx, &xd_kern_events, BPF_F_CURRENT_CPU, \
				&kern_msg, sizeof(struct xd_kern_msg));
	}

	return 0;
}

static __inline int parse_conn_request_args(struct pt_regs *ctx)
{
	struct sock *sk;
	struct sk_buff *skb;
	unsigned int sk_ack_backlog;
	unsigned int sk_max_ack_backlog;
	struct xd_addr_info backlog_addr;

	sk = (struct sock *)PT_REGS_PARM3(ctx);
	if (!sk) {
		bpf_printk("tcphandchk: syn_recv_sock sk is Null\n");
		return 0;
	}

	skb = (struct sk_buff *)PT_REGS_PARM4(ctx);
	if (!skb) {
		bpf_printk("tcphandchk: syn_recv_sock skb is Null\n");
		return 0;
	}

	sk_ack_backlog = BPF_PROBE_VAL(sk->sk_ack_backlog);
	sk_max_ack_backlog = BPF_PROBE_VAL(sk->sk_max_ack_backlog);

	struct iphdr *xd_iphdr;
	struct tcphdr *xd_tcphdr;

	void *raw_tcphdr = NULL;
	void *raw_iphdr  = NULL;

	raw_tcphdr = BPF_PROBE_VAL(skb->data);
	raw_iphdr = raw_tcphdr - XD_TCPHDR_LENGTH;

	xd_iphdr = (struct iphdr *)BPF_PROBE_VAL(raw_iphdr);
	xd_tcphdr = (struct tcphdr *)BPF_PROBE_VAL(raw_tcphdr);

	backlog_addr.srcaddr = BPF_PROBE_VAL(xd_iphdr->saddr);
	backlog_addr.dstaddr = BPF_PROBE_VAL(xd_iphdr->daddr);
	backlog_addr.srcport = BPF_PROBE_VAL(xd_tcphdr->source);
	backlog_addr.dstport = BPF_PROBE_VAL(xd_tcphdr->dest);

	struct xd_kern_msg kern_msg = {0};

	kern_msg.addr_info = backlog_addr;
	kern_msg.msg_type = TCP_V4_SYN_RECV_SOCK;

	if (sk_ack_backlog >= sk_max_ack_backlog) {
		bpf_perf_event_output(ctx, &xd_kern_events, BPF_F_CURRENT_CPU, \
				&kern_msg, sizeof(struct xd_kern_msg));
	}

	return 0;
}

static __inline int parse_timewait_process_args(struct pt_regs *ctx)
{
	struct hook_key key = {0};
	struct sk_buff *skb;
	struct xd_addr_info backlog_addr = {0};

	skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
	if (!skb) {
		bpf_printk("tcphandchk: tw process skb is Null\n");
		return 0;
	}

	struct iphdr *xd_iphdr;
	struct tcphdr *xd_tcphdr;

	void *raw_tcphdr = NULL;
	void *raw_iphdr  = NULL;

	raw_tcphdr = BPF_PROBE_VAL(skb->data);
	raw_iphdr = raw_tcphdr - XD_TCPHDR_LENGTH;

	xd_iphdr = (struct iphdr *)BPF_PROBE_VAL(raw_iphdr);
	xd_tcphdr = (struct tcphdr *)BPF_PROBE_VAL(raw_tcphdr);

	backlog_addr.srcaddr = BPF_PROBE_VAL(xd_iphdr->saddr);
	backlog_addr.dstaddr = BPF_PROBE_VAL(xd_iphdr->daddr);
	backlog_addr.srcport = BPF_PROBE_VAL(xd_tcphdr->source);
	backlog_addr.dstport = BPF_PROBE_VAL(xd_tcphdr->dest);

	key.cpu = bpf_get_smp_processor_id();
	key.func_type = TCP_TIMEWAIT_STATE_PROCESS;

	bpf_map_update_elem(&tw_process_args, &key, &backlog_addr, BPF_NOEXIST);

	return 0;
}

static __inline int chk_timewait_process_ret(struct pt_regs *ctx)
{
	struct xd_addr_info *addr_info;
	struct hook_key key = {0};
	int func_ret;

	key.cpu = bpf_get_smp_processor_id();
	key.func_type = TCP_TIMEWAIT_STATE_PROCESS;

	addr_info = bpf_map_lookup_elem(&tw_process_args, &key);
	if (!addr_info) {
		return 0;
	}

	func_ret = PT_REGS_RC(ctx);

	struct xd_kern_msg kern_msg = {0};

	kern_msg.addr_info = *addr_info;
	kern_msg.retval = func_ret;
	kern_msg.msg_type = TCP_TIMEWAIT_STATE_PROCESS;

	if (kern_msg.retval == 1 || kern_msg.retval == 2) {
		bpf_perf_event_output(ctx, &xd_kern_events, BPF_F_CURRENT_CPU, \
				&kern_msg, sizeof(struct xd_kern_msg));
	}

	bpf_map_delete_elem(&tw_process_args, &key);

	return 0;
}

static __inline int parse_tcp_in_window_args(struct pt_regs *ctx)
{
	struct hook_key key = {0};
	struct sk_buff *skb;
	struct xd_addr_info backlog_addr = {0};

	skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
	if (!skb) {
		bpf_printk("tcphandchk: tcp_in_window sbk is Null\n");
		return 0;
	}

	struct iphdr *xd_iphdr;
	struct tcphdr *xd_tcphdr;
	unsigned short tcp_flags;
	void *raw_tcphdr = NULL;
	void *raw_iphdr = NULL;
	void *raw_tcpflags = NULL;

	raw_iphdr = BPF_PROBE_VAL(skb->data);
	raw_tcphdr = raw_iphdr + XD_TCPHDR_LENGTH;
	raw_tcpflags = raw_tcphdr + 12;

	xd_iphdr = (struct iphdr *)BPF_PROBE_VAL(raw_iphdr);
	xd_tcphdr = (struct tcphdr *)BPF_PROBE_VAL(raw_tcphdr);

	struct tcphdr tcphdr_data = {0};
	bpf_probe_read(&tcphdr_data, sizeof(tcphdr_data), xd_tcphdr);

	if (tcphdr_data.syn ^ 0x1) {
		return 0;
	}
	
	backlog_addr.srcaddr = BPF_PROBE_VAL(xd_iphdr->saddr);
	backlog_addr.dstaddr = BPF_PROBE_VAL(xd_iphdr->daddr);
	backlog_addr.srcport = BPF_PROBE_VAL(xd_tcphdr->dest);

	key.cpu = bpf_get_smp_processor_id();
	key.func_type = TCP_IN_WINDOW;

	bpf_map_update_elem(&tcp_in_window_args, &key, &backlog_addr, BPF_NOEXIST);

	return 0;
}

static __inline int chk_tcp_in_window_ret(struct pt_regs *ctx)
{
	struct xd_addr_info *addr_info;
	struct hook_key key = {0};
	int func_ret;

	key.cpu = bpf_get_smp_processor_id();
	key.func_type = TCP_IN_WINDOW;

	addr_info = bpf_map_lookup_elem(&tcp_in_window_args, &key);
	if (!addr_info) {
		return 0;
	}

	func_ret = PT_REGS_RC(ctx);

	struct xd_kern_msg kern_msg = {0};

	kern_msg.addr_info = *addr_info;
	kern_msg.msg_type = TCP_IN_WINDOW;
	kern_msg.retval = func_ret;

	if (0 == func_ret) {
		bpf_perf_event_output(ctx, &xd_kern_events, BPF_F_CURRENT_CPU, \
				&kern_msg, sizeof(struct xd_kern_msg));
	}

	bpf_map_delete_elem(&tcp_in_window_args, &key);

	return 0;
}

SEC("kprobe/__inet_bind")
int p_inet_bind(struct pt_regs *ctx)
{
	parse_inet_bind_args(ctx);
	return 0;
}

SEC("kretprobe/__inet_bind")
int r_inet_bind(struct pt_regs *ctx)
{
	chk_inet_bind_ret(ctx);
	return 0;
}

SEC("kretprobe/__sys_socket")
int r_sys_socket(struct pt_regs *ctx)
{
	chk_sys_socket_ret(ctx);
	return 0;
}

SEC("kprobe/tcp_v4_syn_recv_sock")
int p_syn_recv(struct pt_regs *ctx)
{
	parse_syn_recv_args(ctx);
	return 0;
}

SEC("kprobe/tcp_conn_request")
int p_conn_request(struct pt_regs *ctx)
{
	parse_conn_request_args(ctx);
	return 0;
}

SEC("kprobe/tcp_timewait_state_process")
int p_timewait_process_args(struct pt_regs *ctx)
{
	parse_timewait_process_args(ctx);
	return 0;
}

SEC("kretprobe/tcp_timewait_state_process")
int r_timewait_process(struct pt_regs *ctx)
{	
	chk_timewait_process_ret(ctx);
	return 0;
}

SEC("kprobe/tcp_in_window")
int p_tcp_in_window(struct pt_regs *ctx)
{
	parse_tcp_in_window_args(ctx);
	return 0;
}

SEC("kretprobe/tcp_in_window")
int r_tcp_in_window(struct pt_regs *ctx)
{
	chk_tcp_in_window_ret(ctx);
	return 0;
}

char _license[] SEC("license") = "GPL";
