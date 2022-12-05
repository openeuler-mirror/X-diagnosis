#include "common_k.h"
#include "xd_tcpreststack.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)

#define BPF_PROBE_VAL(P) \
({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})


#define bpf_printk(fmt, ...)                    \
({                              \
           char ____fmt[] = fmt;                \
           bpf_trace_printk(____fmt, sizeof(____fmt),   \
                ##__VA_ARGS__);         \
})


struct bpf_map_def SEC("maps") stack_map = {
    .type = BPF_MAP_TYPE_STACK_TRACE,
    .key_size = sizeof(u32),
    .value_size = XDIAG_KERN_STACK_DEPTH * sizeof(u64),
    .max_entries = 10000,
};

struct bpf_map_def SEC("maps") stackinfo_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct key_xd_tcpreststack),
    .value_size = sizeof(u32),
    .max_entries = 10000,
};


static __inline int get_reset_stack(struct pt_regs *ctx)
{
    u32 one = 1;
    u32 *val;
    struct sock *sk;
	struct tcp_sock *tcp_sk;
    struct ipv6_pinfo *pinet6;
    struct inet_connection_sock *icsk;
    struct key_xd_tcpreststack key = {0};

	sk = (struct sock *)PT_REGS_PARM1(ctx);
    if(!sk){
        bpf_printk("tcp_reset_stack: sk is NULL\n");
    }
    tcp_sk = (struct tcp_sock *)sk;
    icsk = (struct inet_connection_sock *)sk;
    pinet6 = BPF_PROBE_VAL(tcp_sk->inet_conn.icsk_inet.pinet6);

    key.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    key.kstack_id = bpf_get_stackid(ctx, &stack_map, KERN_STACKID_FLAGS);
    if ((int)key.kstack_id < 0){
        bpf_printk("tcp_reset_stack: bpf_get_stackid failed\n");
        return -1;
    }

	key.sport = BPF_PROBE_VAL(tcp_sk->inet_conn.icsk_inet.inet_sport);
    key.dport = BPF_PROBE_VAL(tcp_sk->inet_conn.icsk_inet.inet_dport);
    key.protocol = 0;
    key.family = BPF_PROBE_VAL(sk->sk_family);

    /* ipv4 */
    if(BPF_PROBE_VAL(sk->sk_family) == AF_INET){
        key.saddr[0] = BPF_PROBE_VAL(tcp_sk->inet_conn.icsk_inet.inet_saddr);
        key.daddr[0] = BPF_PROBE_VAL(tcp_sk->inet_conn.icsk_inet.inet_daddr);
    /* ipv6 */
    } else if (BPF_PROBE_VAL(sk->sk_family) == AF_INET6){
        if(!pinet6){
            bpf_printk(":::icsk_inet->pinet6 is NULL\n");
            return 0;
        }
        key.saddr[0] = BPF_PROBE_VAL(pinet6->saddr.s6_addr32[0]);
        key.saddr[1] = BPF_PROBE_VAL(pinet6->saddr.s6_addr32[1]);
        key.saddr[2] = BPF_PROBE_VAL(pinet6->saddr.s6_addr32[2]);
        key.saddr[3] = BPF_PROBE_VAL(pinet6->saddr.s6_addr32[3]);

        struct in6_addr       *daddr;
        daddr = (struct in6_addr *)BPF_PROBE_VAL(pinet6->daddr_cache);
        if(daddr){
            key.daddr[0] = BPF_PROBE_VAL(daddr->s6_addr32[0]);
            key.daddr[1] = BPF_PROBE_VAL(daddr->s6_addr32[1]);
            key.daddr[2] = BPF_PROBE_VAL(daddr->s6_addr32[2]);
            key.daddr[3] = BPF_PROBE_VAL(daddr->s6_addr32[3]);
        }
    } else {
        bpf_printk("BPF get_tcp_info family:%d incrrect\n",
                    BPF_PROBE_VAL(sk->sk_family));
        return -1;
    }

    val = bpf_map_lookup_elem(&stackinfo_map, &key);
    if (val)
        (*val) ++;
    else
        bpf_map_update_elem(&stackinfo_map, &key, &one, BPF_NOEXIST);

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
