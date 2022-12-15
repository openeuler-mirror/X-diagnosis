#include "common_k.h"
#include "xd_tcpskinfo.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define BPF_PROBE_VAL(P) \
({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct sock_key);
    __type(value, struct tcpinfo_xdiag);
    /* max socket numbers */
    __uint(max_entries, 65536);
} tcpinfo_map SEC(".maps");

SEC("kprobe/tcp_get_info")
int bpf_tcp_get_info(struct pt_regs *ctx)
{
    struct tcp_sock *tcp_sk;
    struct sock *sk;
    struct ipv6_pinfo *pinet6;
    struct inet_connection_sock *icsk;
    struct sock_key key = {0};
    struct tcpinfo_xdiag diaginfo = {0};
    
    sk = (struct sock *)PT_REGS_PARM1(ctx);
    tcp_sk = (struct tcp_sock *)sk;
    icsk = (struct inet_connection_sock *)sk;
    pinet6 = BPF_PROBE_VAL(tcp_sk->inet_conn.icsk_inet.pinet6);

    /* struct tcp_sock */
    diaginfo.reordering = BPF_PROBE_VAL(tcp_sk->reordering);
    diaginfo.window_clamp = BPF_PROBE_VAL(tcp_sk->window_clamp);
    diaginfo.rcv_nxt = BPF_PROBE_VAL(tcp_sk->rcv_nxt);
    diaginfo.rcv_wup = BPF_PROBE_VAL(tcp_sk->rcv_wup);
    diaginfo.rcv_wnd = BPF_PROBE_VAL(tcp_sk->rcv_wnd);
    diaginfo.rcv_ssthresh = BPF_PROBE_VAL(tcp_sk->rcv_ssthresh);
    diaginfo.copied_seq = BPF_PROBE_VAL(tcp_sk->copied_seq);
    diaginfo.snd_nxt = BPF_PROBE_VAL(tcp_sk->snd_nxt);
    diaginfo.snd_una = BPF_PROBE_VAL(tcp_sk->snd_una);
    diaginfo.snd_wnd = BPF_PROBE_VAL(tcp_sk->snd_wnd);
    diaginfo.snd_cwnd = BPF_PROBE_VAL(tcp_sk->snd_cwnd);
    diaginfo.snd_ssthresh = BPF_PROBE_VAL(tcp_sk->snd_ssthresh);
    diaginfo.write_seq = BPF_PROBE_VAL(tcp_sk->write_seq);
    /* struct sock  */
    diaginfo.sk_forward_alloc = BPF_PROBE_VAL(sk->sk_forward_alloc);
    diaginfo.sk_rcvbuf = BPF_PROBE_VAL(sk->sk_rcvbuf);
    diaginfo.sk_sndbuf = BPF_PROBE_VAL(sk->sk_sndbuf);
    diaginfo.sk_wmem_queued = BPF_PROBE_VAL(sk->sk_wmem_queued);
    //diaginfo.sk_userlocks = BPF_PROBE_VAL(sk->sk_padding);
    bpf_probe_read(&(diaginfo.sk_padding), sizeof(diaginfo.sk_padding), 
                    (void *)((long)(&sk->sk_gso_max_segs) - 2));
    /* struct inet_connection_sock  */
    diaginfo.rcv_mss = BPF_PROBE_VAL(icsk->icsk_ack.rcv_mss);
    //diaginfo.icsk_ca_state = BPF_PROBE_VAL(icsk->icsk_ca_state);
    
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
            bpf_printk("icsk_inet->pinet6 is NULL\n");
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

    bpf_map_update_elem(&tcpinfo_map, &key, &diaginfo, BPF_ANY);

    return 0;
}

char _license[] SEC("license") = "GPL";
