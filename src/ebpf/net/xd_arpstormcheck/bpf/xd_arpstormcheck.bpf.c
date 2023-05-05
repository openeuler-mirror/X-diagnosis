#include "common_k.h"
#include "xd_arpstormcheck.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


#define ARPHRD_IEEE1394 24	  /* IEEE 1394 IPv4 - RFC 2734	*/

#define BPF_PROBE_VAL(P) \
({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key_xarp);
	__type(value, u32);
	/* balance between memory usage and monitoring scope */
	__uint(max_entries, 4096);
} arpcheck_map SEC(".maps");

SEC("kprobe/arp_rcv")
int bpf_arp_rcv(struct pt_regs *ctx)
{
	u32 *val;
	u32 one = 1;
	unsigned char *arp_ptr;
	struct sk_buff *skb;
	struct arphdr *arp;
	struct net_device *dev;
	struct key_xarp key = {0};

	skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	dev = BPF_PROBE_VAL(skb->dev);
	arp = (struct arphdr *)(BPF_PROBE_VAL(skb->head) \
					+ BPF_PROBE_VAL(skb->network_header));
	arp_ptr = (unsigned char *)(arp + 1);
	arp_ptr += BPF_PROBE_VAL(dev->addr_len);
	bpf_probe_read_kernel((void *)(&key.sip[0]), sizeof(key.sip[0]), arp_ptr);
	/* skip sip, len=4 */
	arp_ptr += 4;
	arp_ptr += BPF_PROBE_VAL(dev->addr_len);
	bpf_probe_read_kernel((void *)(&key.tip[0]), sizeof(key.tip[0]), arp_ptr);

	key.family = AF_INET;

	val = bpf_map_lookup_elem(&arpcheck_map, &key);
	if (val)
		(*val) ++;
	else
		bpf_map_update_elem(&arpcheck_map, &key, &one, BPF_NOEXIST);

	return 0;
}

SEC("kprobe/icmpv6_rcv")
int bpf_icmpv6_rcv(struct pt_regs *ctx)
{
	u32 *val;
	u32 one = 1;
	struct sk_buff *skb;
	struct ipv6hdr *iph;
	struct key_xarp key = {0};

	skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	iph = (struct ipv6hdr *)(BPF_PROBE_VAL(skb->head) \
					+ BPF_PROBE_VAL(skb->network_header));

	bpf_probe_read_kernel((void *)key.sip, sizeof(key.sip), \
					iph->saddr.in6_u.u6_addr32);
	bpf_probe_read_kernel((void *)key.tip, sizeof(key.sip), \
					iph->daddr.in6_u.u6_addr32);

	key.family = AF_INET6;

	val = bpf_map_lookup_elem(&arpcheck_map, &key);
	if (val)
		(*val) ++;
	else
		bpf_map_update_elem(&arpcheck_map, &key, &one, BPF_NOEXIST);

	return 0;
}


char _license[] SEC("license") = "GPL";
