#include "common_k.h"
#include "xd_tcpreststack.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)

#define BPF_PROBE_VAL(P) \
({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __type(key, u32);
    __uint(value_size, XDIAG_KERN_STACK_DEPTH * sizeof(u64));
    /* Number of possible call stacks */
    __uint(max_entries, 256);
} stack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, u32);
    __type(value, u32);
} stackinfo_event SEC(".maps");

static __inline int get_reset_stack(struct pt_regs *ctx)
{
    u32 one = 1;
    u32 *val;
    struct sock *sk;
    struct tcp_sock *tcp_sk;
    struct ipv6_pinfo *pinet6;
    struct inet_connection_sock *icsk;
    struct event_tcpreststack event = {0};

    sk = (struct sock *)PT_REGS_PARM1(ctx);
    if(!sk){
        bpf_printk("tcp_reset_stack: sk is NULL\n");
    }
    tcp_sk = (struct tcp_sock *)sk;
    icsk = (struct inet_connection_sock *)sk;
    pinet6 = BPF_PROBE_VAL(tcp_sk->inet_conn.icsk_inet.pinet6);

    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.kstack_id = bpf_get_stackid(ctx, &stack_map, KERN_STACKID_FLAGS);
    if ((int)event.kstack_id < 0){
        bpf_printk("tcp_reset_stack: bpf_get_stackid failed\n");
        return -1;
    }

    event.sport = BPF_PROBE_VAL(tcp_sk->inet_conn.icsk_inet.inet_sport);
    event.dport = BPF_PROBE_VAL(tcp_sk->inet_conn.icsk_inet.inet_dport);
    event.protocol = 0;
    event.family = BPF_PROBE_VAL(sk->sk_family);

    /* ipv4 */
    if(BPF_PROBE_VAL(sk->sk_family) == AF_INET){
        event.saddr[0] = BPF_PROBE_VAL(tcp_sk->inet_conn.icsk_inet.inet_saddr);
        event.daddr[0] = BPF_PROBE_VAL(tcp_sk->inet_conn.icsk_inet.inet_daddr);
    /* ipv6 */
    } else if (BPF_PROBE_VAL(sk->sk_family) == AF_INET6){
        if(!pinet6){
            bpf_printk("icsk_inet->pinet6 is NULL\n");
            return 0;
        }
        event.saddr[0] = BPF_PROBE_VAL(pinet6->saddr.s6_addr32[0]);
        event.saddr[1] = BPF_PROBE_VAL(pinet6->saddr.s6_addr32[1]);
        event.saddr[2] = BPF_PROBE_VAL(pinet6->saddr.s6_addr32[2]);
        event.saddr[3] = BPF_PROBE_VAL(pinet6->saddr.s6_addr32[3]);

        struct in6_addr       *daddr;
        daddr = (struct in6_addr *)BPF_PROBE_VAL(pinet6->daddr_cache);
        if(daddr){
            event.daddr[0] = BPF_PROBE_VAL(daddr->s6_addr32[0]);
            event.daddr[1] = BPF_PROBE_VAL(daddr->s6_addr32[1]);
            event.daddr[2] = BPF_PROBE_VAL(daddr->s6_addr32[2]);
            event.daddr[3] = BPF_PROBE_VAL(daddr->s6_addr32[3]);
        }
    } else {
        bpf_printk("BPF get_tcp_info family:%d incrrect\n",
                    BPF_PROBE_VAL(sk->sk_family));
        return -1;
    }

    bpf_perf_event_output(ctx, &stackinfo_event, BPF_F_CURRENT_CPU, \
             &event, sizeof(struct event_tcpreststack));
    return 0;
}

SEC("kprobe/tcp_reset")
int tcp_reset_stack(struct pt_regs *ctx)
{
    get_reset_stack(ctx);
    return 0;
}

SEC("kprobe/tcp_send_active_reset")
int tcp_send_active_reset_stack(struct pt_regs *ctx)
{
    get_reset_stack(ctx);
    return 0;
}


SEC("kprobe/tcp_v4_send_reset")
int tcp_v4_send_reset_stack(struct pt_regs *ctx)
{
    get_reset_stack(ctx);
    return 0;
}

SEC("kprobe/tcp_v6_send_reset")
int tcp_v6_send_reset_stack(struct pt_regs *ctx)
{
    get_reset_stack(ctx);
    return 0;
}


char _license[] SEC("license") = "GPL";
