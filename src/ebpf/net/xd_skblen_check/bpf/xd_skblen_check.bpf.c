#include "common_k.h"
#include "xd_skblen_check.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define SKB_FRAGS 17
#define SKB_MAX_COUNT 8

#define BPF_PROBE_VAL(P) \
    ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct skb_diag);
    /* Number of possible packet */
    __uint(max_entries, 65535);
} skbdiag_map SEC(".maps");

struct skb_ctx {
    u64 __do_not_use__;       // First 8 bytes for bpf ctx
    struct sk_buff *skb;
};

static void get_mac_from_skb(struct sk_buff *skb, struct skb_ethhdr *skb_ethhdr) {
    struct ethhdr *ethhdr;

    ethhdr = (struct ethhdr *)(BPF_PROBE_VAL(skb->head) + BPF_PROBE_VAL(skb->mac_header));
    skb_ethhdr->proto = BPF_PROBE_VAL(ethhdr->h_proto);
    bpf_probe_read(&skb_ethhdr->saddr, sizeof(skb_ethhdr->saddr), &ethhdr->h_source);
    bpf_probe_read(&skb_ethhdr->daddr, sizeof(skb_ethhdr->daddr), &ethhdr->h_dest);
}

static int get_skb_datalen(struct sk_buff *skb) {
    int len = 0;
    int frag = 0;
    int nr_frags = 0;
    int nr_skbs = 0;
    struct skb_shared_info *ss;
    struct sk_buff *pskb;
    skb_frag_t askb_frag[SKB_FRAGS];

    len = BPF_PROBE_VAL(skb->tail) - (BPF_PROBE_VAL(skb->data) - BPF_PROBE_VAL(skb->head));
    if (BPF_PROBE_VAL(skb->data_len) != 0) {
        ss = (struct skb_shared_info *)(BPF_PROBE_VAL(skb->head) + BPF_PROBE_VAL(skb->end));
        nr_frags = BPF_PROBE_VAL(ss->nr_frags);
        bpf_probe_read(&askb_frag, sizeof(askb_frag), &ss->frags);
        for (frag = 0; frag < SKB_FRAGS; frag++) {
            if (frag >= nr_frags) {
                break;
            }

            len += askb_frag[frag].bv_len;
        }
        pskb = BPF_PROBE_VAL(ss->frag_list);
        while (NULL != pskb && nr_skbs < SKB_MAX_COUNT) {
            len += BPF_PROBE_VAL(pskb->tail) - (BPF_PROBE_VAL(pskb->data) - BPF_PROBE_VAL(pskb->head));
            if (BPF_PROBE_VAL(pskb->data_len) != 0) {
                ss = (struct skb_shared_info *)(BPF_PROBE_VAL(pskb->head) + BPF_PROBE_VAL(pskb->end));
                nr_frags = BPF_PROBE_VAL(ss->nr_frags);
                bpf_probe_read(&askb_frag, sizeof(askb_frag), &ss->frags);
                for (frag = 0; frag < SKB_FRAGS; frag++) {
                    if (frag >= nr_frags) {
                        break;
                    }

                    len += askb_frag[frag].bv_len;
                }
            }

            pskb = BPF_PROBE_VAL(pskb->next);
            nr_skbs++;
        }
    }

    return len;
}

SEC("tracepoint/net/netif_receive_skb")
int bpf___netif_receive_skb_core(struct skb_ctx *ctx)
{
    int len = 0;
    int data_len = 0;
    unsigned long key;
    struct sk_buff *skb;
    struct skb_diag skb_diag = {0};

    skb = ctx->skb;
    len = BPF_PROBE_VAL(skb->len);
    data_len = get_skb_datalen(skb);
    if (len != data_len) {
        get_mac_from_skb(skb, &skb_diag.ethhdr);
        skb_diag.skblen = len;
        skb_diag.datalen = data_len;
        key = (unsigned long)skb;
        bpf_map_update_elem(&skbdiag_map, &key, &skb_diag, BPF_ANY);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
