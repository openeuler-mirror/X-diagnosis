#include "common_k.h"
#include "xd_ntrace.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define ETH_P_8021AD 0x88A8
#define ETH_P_8021Q  0x8100
#define ETH_P_IP     0x0800
#define ETH_P_IPV6   0x86DD

#define IPPROTO_FRAGMENT 44
#define IPPROTO_ICMP	 1
#define IPPROTO_ICMPV6	 58

#define ICMPV6_ECHO_REQUEST 128
#define ICMPV6_ECHO_REPLY   129

#define ICMP_ECHO      8
#define ICMP_ECHOREPLY 0

#define QUEUE_STATE_DRV_XOFF   (1 << __QUEUE_STATE_DRV_XOFF)
#define QUEUE_STATE_STACK_XOFF (1 << __QUEUE_STATE_STACK_XOFF)
#define QUEUE_STATE_FROZEN     (1 << __QUEUE_STATE_FROZEN)

#define QUEUE_STATE_ANY_XOFF (QUEUE_STATE_DRV_XOFF | QUEUE_STATE_STACK_XOFF)
#define QUEUE_STATE_ANY_XOFF_OR_FROZEN                                         \
	(QUEUE_STATE_ANY_XOFF | QUEUE_STATE_FROZEN)

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct ntrace_flow_keys);
	__type(value, struct ntrace_put_user_info);
} sockresult_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct ntrace_filter_info);
} filter_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, u32);
	__type(value, u32);
} net_trace_event SEC(".maps");

static struct ntrace_filter_info *get_filter_info(void)
{
	int key = 0;
	struct ntrace_filter_info *finfo = NULL;
	finfo = bpf_map_lookup_elem(&filter_map, &key);
	if (!finfo)
		return NULL;
	return finfo;
}

static int ipaddr_cmp(__be32 *src, __be32 *dst)
{
	if (src[0] == dst[0] && src[1] == dst[1] && src[2] == dst[2] &&
	    src[3] == dst[3])
		return 0;
	return 1;
}

static bool filter_l3(__be32 saddr[4], __be32 daddr[4])
{
	struct ntrace_filter_info *dinfo = get_filter_info();
	if (!dinfo)
		return false;
	if ((!ipaddr_cmp(daddr, dinfo->hostaddr) ||
	     !ipaddr_cmp(saddr, dinfo->hostaddr))) {
		return true;
	}
	return false;
}

static bool filter_l3_v4(__be32 saddr, __be32 daddr)
{
	struct ntrace_filter_info *info = get_filter_info();
	if (!info)
		return false;
	if (saddr == info->hostaddr[0] || daddr == info->hostaddr[0])
		return true;
	return false;
}

static int read_v4_l3(struct sk_buff *skb, struct ntrace_flow_keys *tuple,
		      int offset, int stage, int *next_off, u8 *protocol)
{
	unsigned char *head;
	u16 l3_offset = 0;
	struct iphdr iph = {0};

	bpf_probe_read(&head, sizeof(head), &skb->head);
	bpf_probe_read(&l3_offset, sizeof(l3_offset), &skb->network_header);
	bpf_probe_read(&iph, sizeof(iph), head + l3_offset + offset);

	if (!filter_l3_v4(iph.saddr, iph.daddr)) {
		return 0;
	}

	if (iph.protocol == IPPROTO_TCP || iph.protocol == IPPROTO_UDP) {
		__builtin_memcpy(tuple->key.tp.saddr, &iph.saddr,
				 sizeof(iph.saddr));
		__builtin_memcpy(tuple->key.tp.daddr, &iph.daddr,
				 sizeof(iph.daddr));
	}

	*next_off = l3_offset + offset + iph.ihl * 4;
	*protocol = iph.protocol;
	return 1;
}

static int read_v6_l3(struct sk_buff *skb, struct ntrace_flow_keys *tuple,
		      int offset, int stage, int *nextoff,
		      unsigned short *protocol)
{
	unsigned char *head;
	u16 l3_offset = 0;
	struct ipv6hdr ip6h = {0};
	int offset_next = 0;
	unsigned short proto;

	bpf_probe_read(&head, sizeof(head), &skb->head);
	bpf_probe_read(&l3_offset, sizeof(l3_offset), &skb->network_header);
	bpf_probe_read(&ip6h, sizeof(ip6h), head + l3_offset + offset);
	proto = ip6h.nexthdr;
	offset_next = l3_offset + offset + sizeof(struct ipv6hdr);
	// not support frag, skb head in non-linear
	if (proto == IPPROTO_FRAGMENT) {
		return 0;
	}
	if (!filter_l3(ip6h.saddr.in6_u.u6_addr32,
		       ip6h.daddr.in6_u.u6_addr32)) {
		return 0;
	}
	if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
		__builtin_memcpy(tuple->key.tp.saddr,
				 ip6h.saddr.in6_u.u6_addr32,
				 sizeof(ip6h.saddr.in6_u.u6_addr32));
		__builtin_memcpy(tuple->key.tp.daddr,
				 ip6h.daddr.in6_u.u6_addr32,
				 sizeof(ip6h.daddr.in6_u.u6_addr32));
		tuple->key.tp.protocol = proto;
	}
	*nextoff = offset_next;
	*protocol = proto;
	return 1;
}

static void parse_icmpv4(void *ctx, struct sk_buff *skb,
			 struct ntrace_flow_keys *tuple, int stage, int offset)
{
	struct icmphdr icmph;
	u16 l4_offset = 0;
	struct ntrace_put_user_info *value = NULL, def_value;
	struct ntrace_put_user_info event = {0};
	unsigned char *skb_head;
	struct net_device *dev;
	int nextoff;
	u8 proto;

	bpf_probe_read(&skb_head, sizeof(skb_head), &skb->head);
	bpf_probe_read(&dev, sizeof(dev), &skb->dev);

	if (offset) {
		bpf_probe_read((void *)&icmph, sizeof(icmph),
			       (void *)(skb_head + offset));
	} else {
		bpf_probe_read(&l4_offset, sizeof(l4_offset),
			       &skb->transport_header);
		bpf_probe_read((void *)&icmph, sizeof(icmph),
			       skb_head + l4_offset);
	}

	if (icmph.type != ICMP_ECHO && icmph.type != ICMP_ECHOREPLY)
		return;
	tuple->key.icmp_key.icmp_id = bpf_htons(icmph.un.echo.id);

	if (!offset && !read_v4_l3(skb, tuple, offset, stage, &nextoff, &proto))
		return;
	value = bpf_map_lookup_elem(&sockresult_map, tuple);
	if (value) {
		if (icmph.type == ICMP_ECHOREPLY &&
		    stage == NET_DEV_START_XMIT) {
			value->ts = (bpf_ktime_get_ns() - value->ts) / 1000;
		}
		if (stage == NET_SKB_RCV && icmph.type == ICMP_ECHO &&
		    value->icmp_type == ICMP_PASSIVE) {
			__builtin_memcpy(&event, value,
					 sizeof(struct ntrace_put_user_info));
			bpf_perf_event_output(
				ctx, &net_trace_event, BPF_F_CURRENT_CPU,
				&event, sizeof(struct ntrace_put_user_info));
			bpf_map_delete_elem(&sockresult_map, tuple);
			goto create_map;
		}
		value->stage = stage;
		value->icmp_seq = bpf_htons(icmph.un.echo.sequence);
	} else {
create_map:
		if (stage != NET_SKB_RCV || icmph.type != ICMP_ECHO)
			return;

		__builtin_memset(&def_value, 0,
				 sizeof(struct ntrace_put_user_info));
		bpf_map_update_elem(&sockresult_map, tuple, &def_value, 0);
		value = bpf_map_lookup_elem(&sockresult_map, tuple);
		if (!value)
			return;
		value->stage = stage;
		bpf_probe_read_str(&value->indev_name,
				   sizeof(value->indev_name), dev->name);
		value->ts = bpf_ktime_get_ns();
		value->icmp_type = ICMP_PASSIVE;
		value->cpuid = bpf_get_smp_processor_id();
		value->icmp_seq = bpf_htons(icmph.un.echo.sequence);
	}
}

static void parse_icmpv6(void *ctx, struct sk_buff *skb,
			 struct ntrace_flow_keys *tuple, int stage, int offset)
{
	struct icmp6hdr icmphdr;
	u16 l4_offset = 0;
	int nextoff = 0;
	struct ntrace_put_user_info *value, def_value;
	struct ntrace_put_user_info event = {0};
	unsigned char *skb_head;
	struct net_device *netdev;
	unsigned short proto = 0xffff;

	bpf_probe_read(&skb_head, sizeof(skb_head), &skb->head);
	bpf_probe_read(&netdev, sizeof(netdev), &skb->dev);
	if (offset) {
		bpf_probe_read((void *)&icmphdr, sizeof(icmphdr),
			       (void *)(skb_head + offset));
	} else {
		bpf_probe_read(&l4_offset, sizeof(l4_offset),
			       &skb->transport_header);
		bpf_probe_read(&icmphdr, sizeof(icmphdr), skb_head + l4_offset);
	}
	if (icmphdr.icmp6_type != ICMPV6_ECHO_REQUEST &&
	    icmphdr.icmp6_type != ICMPV6_ECHO_REPLY)
		return;
	tuple->key.icmp_key.icmp_id =
		bpf_htons(icmphdr.icmp6_dataun.u_echo.identifier);
	if (!offset &&
	    !read_v6_l3(skb, tuple, offset, stage, &nextoff, &proto)) {
		return;
	}
	value = bpf_map_lookup_elem(&sockresult_map, tuple);
	if (value) {
		if (icmphdr.icmp6_type == ICMPV6_ECHO_REPLY &&
		    stage == NET_DEV_START_XMIT) {
			value->ts = (bpf_ktime_get_ns() - value->ts) / 1000;
		}
		if (stage == NET_SKB_RCV &&
		    icmphdr.icmp6_type == ICMPV6_ECHO_REQUEST &&
		    value->icmp_type == ICMP_PASSIVE) {
			__builtin_memcpy(&event, value,
					 sizeof(struct ntrace_put_user_info));
			bpf_perf_event_output(
				ctx, &net_trace_event, BPF_F_CURRENT_CPU,
				&event, sizeof(struct ntrace_put_user_info));
			bpf_map_delete_elem(&sockresult_map, tuple);
			goto create_map;
		}
		value->stage = stage;
		value->icmp_seq =
			bpf_htons(icmphdr.icmp6_dataun.u_echo.sequence);
	} else {
create_map:
		if (stage != NET_SKB_RCV ||
		    icmphdr.icmp6_type != ICMPV6_ECHO_REQUEST)
			return;
		__builtin_memset(&def_value, 0,
				 sizeof(struct ntrace_put_user_info));
		bpf_map_update_elem(&sockresult_map, tuple, &def_value, 0);
		value = bpf_map_lookup_elem(&sockresult_map, tuple);
		if (!value)
			return;
		value->stage = stage;
		bpf_probe_read_str(&value->indev_name,
				   sizeof(value->indev_name), netdev->name);
		value->ts = bpf_ktime_get_ns();
		value->icmp_type = ICMP_PASSIVE;
		value->cpuid = bpf_get_smp_processor_id();
		value->icmp_seq =
			bpf_htons(icmphdr.icmp6_dataun.u_echo.sequence);
	}
	return;
}

static void v6_parse_l3(void *ctx, struct sk_buff *skb,
			struct ntrace_flow_keys *tuple, int stage, int offset)
{
	int offset_next = 0;
	unsigned short protocol = 0xffff;
	if (!read_v6_l3(skb, tuple, offset, stage, &offset_next, &protocol))
		return;
	switch (protocol) {
	case IPPROTO_TCP:
		//parse_tcp(ctx, skb, tuple, stage, offset_next);
		break;
	case IPPROTO_UDP:
		//parse_udp(ctx, skb, tuple, stage, offset_next);
		break;
	case IPPROTO_ICMPV6:
		parse_icmpv6(ctx, skb, tuple, stage, offset_next);
		break;
	default:
		break;
	}
	return;
}

static void v4_parse_l3(void *ctx, struct sk_buff *skb,
			struct ntrace_flow_keys *tuple, int stage, int offset)
{
	int offset_next = 0;
	u8 protocol = 0xff;
	if (!read_v4_l3(skb, tuple, offset, stage, &offset_next, &protocol))
		return;
	switch (protocol) {
	case IPPROTO_TCP:
		//parse_tcp(ctx, skb, tuple, stage, offset_next);
		break;
	case IPPROTO_UDP:
		//parse_udp(ctx, skb, tuple, stage, offset_next);
		break;
	case IPPROTO_ICMP:
		parse_icmpv4(ctx, skb, tuple, stage, offset_next);
		break;
	default:
		break;
	}
	return;
}

typedef void (*parse_layer)(void *ctx, struct sk_buff *skb,
			    struct ntrace_flow_keys *tuple, int stage,
			    int offset);

static void *parse_proto[] = {[0] = v4_parse_l3, [1] = v6_parse_l3};

static void parse_l2(void *ctx, struct sk_buff *skb,
		     struct ntrace_flow_keys *tuple, int stage)
{
	int offset = 0;
	u16 proto;
	char *head;
	u16 network_header;

	bpf_probe_read(&proto, sizeof(proto), &skb->protocol);
	if ((proto == bpf_htons(ETH_P_8021AD)) ||
	    (proto == bpf_htons(ETH_P_8021Q))) {
		bpf_probe_read(&head, sizeof(head), &skb->head);
		bpf_probe_read(&network_header, sizeof(network_header),
			       &skb->network_header);
		bpf_probe_read(&proto, sizeof(proto),
			       head + network_header +
				       offsetof(struct vlan_hdr,
						h_vlan_encapsulated_proto));
		offset = sizeof(struct vlan_hdr);
	}
	switch (bpf_htons(proto)) {
	case ETH_P_IP:
		((parse_layer)parse_proto[0])(ctx, skb, tuple, stage, offset);
		break;
	case ETH_P_IPV6:
		((parse_layer)parse_proto[1])(ctx, skb, tuple, stage, offset);
		break;
	default:
		break;
	}
	return;
}

SEC("kprobe/__sock_queue_rcv_skb")
int ntrace___sock_queue_rcv_skb(struct pt_regs *ctx)
{
	struct sk_buff *skb;
	struct sock *sk;
	int sk_rcvbuf;
	int rmem_alloc;
	struct ntrace_flow_keys tuple = {0};
	struct ntrace_put_user_info *value;
	u16 proto;

	sk = (struct sock *)PT_REGS_PARM1(ctx);
	skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
	bpf_probe_read(&sk_rcvbuf, sizeof(int), &sk->sk_rcvbuf);
	bpf_probe_read(&rmem_alloc, sizeof(int), &sk->sk_backlog.rmem_alloc);

	bpf_probe_read(&proto, sizeof(proto), &skb->protocol);
	switch (bpf_htons(proto)) {
	case ETH_P_IP:
		parse_icmpv4(ctx, skb, &tuple, NET_PING_RCV_SKB, 0);
		break;
	case ETH_P_IPV6:
		parse_icmpv6(ctx, skb, &tuple, NET_PING_RCV_SKB, 0);
		break;
	default:
		break;
	}

	value = bpf_map_lookup_elem(&sockresult_map, &tuple);
	if (!value) {
		return 1;
	}
	if (rmem_alloc >= sk_rcvbuf)
		value->stage = NET_RCV_OVERFLOW;
	else
		value->stage = NET_MAX;
	return 0;
}

SEC("kprobe/rawv6_sendmsg")
int ntrace_rawv6_sendmsg(struct pt_regs *ctx)
{
	struct msghdr *msg = NULL;
	struct iovec *iov = NULL;
	struct icmp6hdr *icmph;
	struct ntrace_flow_keys tuple = {0};
	unsigned long iov_len = 0;
	struct inet_sock *isk;
	struct sock *sk;
	struct ntrace_put_user_info *value, def_value = {};
	struct ntrace_put_user_info event = {0};
	struct ipv6_pinfo *pinet6;
	struct sockaddr_in6 *sin6;
	__be32 daddr[IP_LEN];
	u16 icmp_seq = 0;
	int sk_sndbuf;
	int sk_wmem_alloc;
	struct ntrace_filter_info *dinfo;

	msg = (struct msghdr *)PT_REGS_PARM2(ctx);
	isk = (struct inet_sock *)PT_REGS_PARM1(ctx);
	sk = (struct sock *)isk;
	bpf_probe_read(&sin6, sizeof(sin6), &msg->msg_name);
	bpf_probe_read(daddr, sizeof(daddr), sin6->sin6_addr.in6_u.u6_addr32);
	dinfo = get_filter_info();
	if (!dinfo || ipaddr_cmp(daddr, dinfo->hostaddr))
		return 0;
	bpf_probe_read(&iov, sizeof(iov), &msg->msg_iter.iov);
	bpf_probe_read(&iov_len, sizeof(iov_len), &iov->iov_len);
	bpf_probe_read(&icmph, sizeof(icmph), &iov->iov_base);
	bpf_probe_read(&icmp_seq, sizeof(icmp_seq),
		       &icmph->icmp6_dataun.u_echo.sequence);
	bpf_probe_read(&tuple.key.icmp_key.icmp_id,
		       sizeof(tuple.key.icmp_key.icmp_id),
		       &icmph->icmp6_dataun.u_echo.identifier);
	icmp_seq = bpf_htons(icmp_seq);
	tuple.key.icmp_key.icmp_id = bpf_htons(tuple.key.icmp_key.icmp_id);

	value = bpf_map_lookup_elem(&sockresult_map, &tuple);
	if (value) {
		__builtin_memcpy(&event, value,
				 sizeof(struct ntrace_put_user_info));
		bpf_perf_event_output(ctx, &net_trace_event, BPF_F_CURRENT_CPU,
				      &event,
				      sizeof(struct ntrace_put_user_info));
	}
	__builtin_memset(&def_value, 0, sizeof(struct ntrace_put_user_info));
	bpf_map_update_elem(&sockresult_map, &tuple, &def_value, 0);
	value = bpf_map_lookup_elem(&sockresult_map, &tuple);
	if (!value) {
		return -1;
	}
	bpf_probe_read(&pinet6, sizeof(pinet6), &isk->pinet6);
	bpf_probe_read(value->saddr, sizeof(value->saddr),
		       pinet6->saddr.in6_u.u6_addr32);
	bpf_probe_read(&sk_sndbuf, sizeof(sk_sndbuf), &sk->sk_sndbuf);
	bpf_probe_read(&sk_wmem_alloc, sizeof(sk_wmem_alloc),
		       &sk->sk_wmem_alloc);
	value->stage = NET_RAW_SENDMSG;
	if (sk_wmem_alloc >= sk_sndbuf)
		value->stage = NET_SND_OVERFLOW;
	value->ts = bpf_ktime_get_ns();
	value->icmp_type = ICMP_ACTIVE;
	value->icmp_seq = icmp_seq;
	value->cpuid = bpf_get_smp_processor_id();
	return 0;
}

SEC("kprobe/dev_hard_start_xmit")
int ntrace_dev_hard_start_xmit(struct pt_regs *ctx)
{
	struct ntrace_flow_keys tuple = {0};
	struct netdev_queue *txq = NULL;
	struct Qdisc *qdisc = NULL;
	struct ntrace_put_user_info *value;
	struct sk_buff *skb;
	u16 proto;

	skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	txq = (struct netdev_queue *)PT_REGS_PARM3(ctx);
	if (!txq)
		return 0;

	bpf_probe_read(&qdisc, sizeof(qdisc), &txq->qdisc);

	bpf_probe_read(&proto, sizeof(proto), &skb->protocol);
	switch (bpf_htons(proto)) {
	case ETH_P_IP:
		v4_parse_l3(ctx, skb, &tuple, NET_DEV_START_XMIT, 0);
		break;
	case ETH_P_IPV6:
		v6_parse_l3(ctx, skb, &tuple, NET_DEV_START_XMIT, 0);
		break;
	default:
		break;
	}
	value = bpf_map_lookup_elem(&sockresult_map, &tuple);
	if (value && value->icmp_type == ICMP_PASSIVE) {
		value->stage = NET_MAX;
	}
	return 0;
}

SEC("kprobe/sch_direct_xmit")
int ntrace_sch_direct_xmit(struct pt_regs *ctx)
{
	struct sk_buff *skb;
	unsigned long state;
	struct netdev_queue *txq = NULL;
	struct Qdisc *q = NULL;
	struct ntrace_flow_keys tuple = {0};
	struct ntrace_put_user_info *value;
	u16 proto;

	skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	q = (struct Qdisc *)PT_REGS_PARM2(ctx);
	txq = (struct netdev_queue *)PT_REGS_PARM4(ctx);

	bpf_probe_read(&proto, sizeof(proto), &skb->protocol);
	switch (bpf_htons(proto)) {
	case ETH_P_IP:
		v4_parse_l3(ctx, skb, &tuple, NET_DEV_SCH_DIR_XMIT, 0);
		break;
	case ETH_P_IPV6:
		v6_parse_l3(ctx, skb, &tuple, NET_DEV_SCH_DIR_XMIT, 0);
		break;
	default:
		break;
	}

	value = bpf_map_lookup_elem(&sockresult_map, &tuple);
	if (value && txq) {
		bpf_probe_read(&state, sizeof(txq->state), &txq->state);
		if (state & QUEUE_STATE_ANY_XOFF_OR_FROZEN) {
			value->stage = NET_DEV_SCH_DIR_XMIT;
		} else {
			value->stage = NET_MAX;
		}
		bpf_probe_read(&value->queue, sizeof(skb->queue_mapping),
			       &skb->queue_mapping);
		bpf_probe_read(&value->tc_drop, sizeof(q->qstats.drops),
			       &q->qstats.drops);
	}
	return 0;
}

SEC("tracepoint/net/net_dev_queue")
int ntrace_net_dev_queue(struct ntrace_tp_net_args *args)
{
	struct ntrace_flow_keys tuple = {0};
	struct sk_buff *skb = args->skbaddr;
	u16 proto;

	bpf_probe_read(&proto, sizeof(proto), &skb->protocol);
	switch (bpf_htons(proto)) {
	case ETH_P_IP:
		v4_parse_l3(args, args->skbaddr, &tuple, NET_DEV_QUEUE_XMIT, 0);
		break;
	case ETH_P_IPV6:
		v6_parse_l3(args, args->skbaddr, &tuple, NET_DEV_QUEUE_XMIT, 0);
		break;
	default:
		break;
	}
	return 0;
}

SEC("kprobe/ip6_finish_output2")
int ntrace_ip6_finish_output2(struct pt_regs *ctx)
{
	struct sk_buff *skb;
	struct ntrace_flow_keys tuple = {0};
	skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
	v6_parse_l3(ctx, skb, &tuple, NET_IP_FINISH_OUTPUT2, 0);
	return 0;
}

SEC("kprobe/ip6_finish_output")
int ntrace_ip6_finish_output(struct pt_regs *ctx)
{
	struct sk_buff *skb;
	struct ntrace_flow_keys tuple = {0};
	skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
	v6_parse_l3(ctx, skb, &tuple, NET_IP_FINISH_OUTPUT, 0);
	return 0;
}

SEC("kprobe/ip6_output")
int ntrace_ip6_output(struct pt_regs *ctx)
{
	struct sk_buff *skb;
	struct ntrace_flow_keys tuple = {0};
	skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
	v6_parse_l3(ctx, skb, &tuple, NET_IP_OUTPUT, 0);
	return 0;
}

SEC("kprobe/ip6_local_out")
int ntrace_ip6_local_out(struct pt_regs *ctx)
{
	struct sk_buff *skb;
	struct ntrace_flow_keys tuple = {0};
	skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
	v6_parse_l3(ctx, skb, &tuple, NET_IP_LOCAL_OUTPUT, 0);
	return 0;
}

SEC("kprobe/icmpv6_echo_reply")
int ntrace_icmpv6_echo_reply(struct pt_regs *ctx)
{
	struct sk_buff *skb;
	struct ntrace_flow_keys tuple = {0};
	skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	parse_icmpv6(ctx, skb, &tuple, NET_ICMP_REPLAY, 0);
	return 0;
}

SEC("kprobe/icmpv6_rcv")
int ntrace_icmpv6_rcv(struct pt_regs *ctx)
{
	struct sk_buff *skb;
	struct net_device *dev;
	struct net *net;
	unsigned int icmpv6_echo_ignore_all;
	struct ntrace_flow_keys tuple = {0};
	struct ntrace_put_user_info *value;

	skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	bpf_probe_read(&dev, sizeof(skb->dev), &skb->dev);
	bpf_probe_read(&net, sizeof(dev->nd_net.net), &dev->nd_net.net);
	parse_icmpv6(ctx, skb, &tuple, NET_ICMP_RCV, 0);
	value = bpf_map_lookup_elem(&sockresult_map, &tuple);
	if (value) {
		if (value->icmp_type == ICMP_ACTIVE) {
			value->stage = NET_MAX;
			return 0;
		}
		bpf_probe_read(&icmpv6_echo_ignore_all,
			       sizeof(net->ipv6.sysctl.icmpv6_echo_ignore_all),
			       &net->ipv6.sysctl.icmpv6_echo_ignore_all);
		if (icmpv6_echo_ignore_all == 0)
			value->stage = NET_ICMP_RCV_EXT;
	}
	return 0;
}

SEC("kprobe/ip6_protocol_deliver_rcu")
int ntrace_ip6_protocol_deliver(struct pt_regs *ctx)
{
	struct sk_buff *skb;
	struct ntrace_flow_keys tuple = {0};
	skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
	v6_parse_l3(ctx, skb, &tuple, NET_IP_INPUT_FINISH, 0);
	return 0;
}

SEC("kprobe/ip6_input_finish")
int ntrace_ip6_input_finish(struct pt_regs *ctx)
{
	struct sk_buff *skb;
	struct ntrace_flow_keys tuple = {0};
	skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
	v6_parse_l3(ctx, skb, &tuple, NET_IP_INPUT_FINISH, 0);
	return 0;
}

SEC("kprobe/ip6_input")
int ntrace_ip6_input(struct pt_regs *ctx)
{
	struct sk_buff *skb;
	struct ntrace_flow_keys tuple = {0};
	skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	v6_parse_l3(ctx, skb, &tuple, NET_IP_INPUT, 0);
	return 0;
}

SEC("kprobe/ip6_route_input")
int ntrace_ip6_rcv_finish(struct pt_regs *ctx)
{
	struct sk_buff *skb;
	struct ntrace_flow_keys tuple = {0};
	skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	v6_parse_l3(ctx, skb, &tuple, NET_IP_ROUTE_INPUT, 0);
	return 0;
}

SEC("kprobe/ip6_rcv_core")
int ntrace_ip6_rcv_core(struct pt_regs *ctx)
{
	struct sk_buff *skb;
	struct ntrace_flow_keys tuple = {0};
	skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	v6_parse_l3(ctx, skb, &tuple, NET_IP_RCV_CORE, 0);
	return 0;
}

/* ipv4 */
SEC("kprobe/raw_sendmsg")
int ntrace_raw_sendmsg(struct pt_regs *ctx)
{
	struct msghdr *msg = NULL;
	struct iovec *iov = NULL;
	struct icmphdr *icmph;
	struct ntrace_flow_keys tuple = {0};
	unsigned long iov_len = 0;
	struct sock *sock;
	struct inet_sock *isk;
	struct ntrace_put_user_info *value, def_value;
	struct ntrace_put_user_info event = {0};
	struct sockaddr_in *sin;
	__be32 daddr;
	u16 icmp_seq = 0;
	int sk_sndbuf;
	int sk_wmem_alloc;
	struct ntrace_filter_info *dinfo;

	sock = (struct sock *)PT_REGS_PARM1(ctx);
	msg = (struct msghdr *)PT_REGS_PARM2(ctx);
	isk = (struct inet_sock *)sock;

	bpf_probe_read(&sin, sizeof(sin), &msg->msg_name);
	bpf_probe_read(&daddr, sizeof(daddr), &sin->sin_addr.s_addr);

	dinfo = get_filter_info();
	if (!dinfo || daddr != dinfo->hostaddr[0])
		return 0;

	bpf_probe_read(&iov, sizeof(iov), &msg->msg_iter.iov);
	bpf_probe_read(&iov_len, sizeof(iov_len), &iov->iov_len);

	bpf_probe_read(&icmph, sizeof(icmph), &iov->iov_base);
	bpf_probe_read(&icmp_seq, sizeof(icmp_seq), &icmph->un.echo.sequence);
	bpf_probe_read(&tuple.key.icmp_key.icmp_id,
		       sizeof(tuple.key.icmp_key.icmp_id), &icmph->un.echo.id);
	icmp_seq = bpf_htons(icmp_seq);
	tuple.key.icmp_key.icmp_id = bpf_htons(tuple.key.icmp_key.icmp_id);

	value = bpf_map_lookup_elem(&sockresult_map, &tuple);
	if (value) {
		__builtin_memcpy(&event, value,
				 sizeof(struct ntrace_put_user_info));
		bpf_perf_event_output(ctx, &net_trace_event, BPF_F_CURRENT_CPU,
				      &event,
				      sizeof(struct ntrace_put_user_info));
	}
	__builtin_memset(&def_value, 0, sizeof(struct ntrace_put_user_info));
	bpf_map_update_elem(&sockresult_map, &tuple, &def_value, 0);
	value = bpf_map_lookup_elem(&sockresult_map, &tuple);
	if (!value) {
		return -1;
	}

	bpf_probe_read(value->saddr, sizeof(value->saddr), &isk->inet_saddr);
	bpf_probe_read(&sk_sndbuf, sizeof(sk_sndbuf), &sock->sk_sndbuf);
	bpf_probe_read(&sk_wmem_alloc, sizeof(sk_wmem_alloc),
		       &sock->sk_wmem_alloc);

	value->stage = NET_RAW_SENDMSG;
	if (sk_wmem_alloc >= sk_sndbuf)
		value->stage = NET_SND_OVERFLOW;
	value->ts = bpf_ktime_get_ns();
	value->icmp_type = ICMP_ACTIVE;
	value->icmp_seq = icmp_seq;
	value->cpuid = bpf_get_smp_processor_id();
	return 0;
}

SEC("kprobe/ip_finish_output2")
int ntrace_ip_finish_output2(struct pt_regs *ctx)
{
	struct sk_buff *skb;
	struct ntrace_flow_keys tuple = {0};
	skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
	v4_parse_l3(ctx, skb, &tuple, NET_IP_FINISH_OUTPUT2, 0);
	return 0;
}

SEC("kprobe/ip_finish_output")
int ntrace_ip_finish_output(struct pt_regs *ctx)
{
	struct sk_buff *skb;
	struct ntrace_flow_keys tuple = {0};
	skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
	v4_parse_l3(ctx, skb, &tuple, NET_IP_FINISH_OUTPUT, 0);
	return 0;
}

SEC("kprobe/ip_output")
int ntrace_ip_output(struct pt_regs *ctx)
{
	struct sk_buff *skb;
	struct ntrace_flow_keys tuple = {0};
	skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
	v4_parse_l3(ctx, skb, &tuple, NET_IP_OUTPUT, 0);
	return 0;
}

SEC("kprobe/ip_local_out")
int ntrace_ip_local_out(struct pt_regs *ctx)
{
	struct sk_buff *skb;
	struct ntrace_flow_keys tuple = {0};
	skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
	v4_parse_l3(ctx, skb, &tuple, NET_IP_LOCAL_OUTPUT, 0);
	return 0;
}

SEC("kprobe/icmp_echo")
int ntrace_icmp_echo(struct pt_regs *ctx)
{
	struct sk_buff *skb;
	struct ntrace_flow_keys tuple = {0};
	skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	parse_icmpv4(ctx, skb, &tuple, NET_ICMP_REPLAY, 0);
	return 0;
}

SEC("kprobe/icmp_rcv")
int ntrace_icmp_rcv(struct pt_regs *ctx)
{
	struct sk_buff *skb;
	struct net_device *dev;
	struct net *net;
	unsigned int icmp_echo_ignore_all;
	struct ntrace_flow_keys tuple = {0};
	struct ntrace_put_user_info *value;

	skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	bpf_probe_read(&dev, sizeof(skb->dev), &skb->dev);
	bpf_probe_read(&net, sizeof(dev->nd_net.net), &dev->nd_net.net);
	parse_icmpv4(ctx, skb, &tuple, NET_ICMP_RCV, 0);

	value = bpf_map_lookup_elem(&sockresult_map, &tuple);
	if (value) {
		if (value->icmp_type == ICMP_ACTIVE) {
			value->stage = NET_MAX;
			return 0;
		}
		bpf_probe_read(&icmp_echo_ignore_all,
			       sizeof(net->ipv4.sysctl_icmp_echo_ignore_all),
			       &net->ipv4.sysctl_icmp_echo_ignore_all);
		if (icmp_echo_ignore_all == 0)
			value->stage = NET_ICMP_RCV_EXT;
	}
	return 0;
}

SEC("kprobe/ip_local_deliver_finish")
int ntrace_ip_local_deliver_finish(struct pt_regs *ctx)
{
	struct sk_buff *skb;
	struct ntrace_flow_keys tuple = {0};
	skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
	v4_parse_l3(ctx, skb, &tuple, NET_IP_INPUT_FINISH, 0);
	return 0;
}

SEC("kprobe/ip_local_deliver")
int ntrace_ip_local_deliver(struct pt_regs *ctx)
{
	struct sk_buff *skb;
	struct ntrace_flow_keys tuple = {0};
	skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	v4_parse_l3(ctx, skb, &tuple, NET_IP_INPUT, 0);
	return 0;
}

SEC("kprobe/ip_route_input_noref")
int ntrace_ip_route_input_noref(struct pt_regs *ctx)
{
	struct sk_buff *skb;
	struct ntrace_flow_keys tuple = {0};
	skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	v4_parse_l3(ctx, skb, &tuple, NET_IP_ROUTE_INPUT, 0);
	return 0;
}

SEC("kprobe/ip_rcv_core")
int ntrace_ip_rcv_core(struct pt_regs *ctx)
{
	struct sk_buff *skb;
	struct ntrace_flow_keys tuple = {0};
	skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	v4_parse_l3(ctx, skb, &tuple, NET_IP_RCV_CORE, 0);
	return 0;
}

SEC("tracepoint/net/netif_receive_skb")
int ntrace_netif_receive_skb_core(struct ntrace_tp_net_args *args)
{
	struct ntrace_flow_keys tuple = {0};
	struct sk_buff *skb = args->skbaddr;
	parse_l2(args, skb, &tuple, NET_SKB_RCV);
	return 0;
}
char LICENSE[] SEC("license") = "GPL";
