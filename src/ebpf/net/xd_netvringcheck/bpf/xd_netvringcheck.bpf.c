#include "common_k.h"
#include "xd_netvringcheck.h"
#include "xd_netvringcheck_k.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* only virtual machine */
#define MAX_VIRTNET_RINGS 1024
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, long);
	__type(value, struct value_vring);
	__uint(max_entries, MAX_VIRTNET_RINGS);
} vring_map_rx SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, long);
	__type(value, struct value_vring);
	__uint(max_entries, MAX_VIRTNET_RINGS);
} vring_map_tx SEC(".maps");

SEC("kprobe/receive_buf")
int bpf__receive_buf(struct pt_regs *ctx)
{
	u32 num_uring;
	u32 num;
	long key;
	struct virtnet_info *vi;
	struct net_device *dev;
	struct receive_queue *rq;
	struct virtqueue *vq;
	struct vring_virtqueue *vring_vq;
	struct value_vring new = {0};
	struct value_vring *val;
	vring_used_t *vring_used;

	vi = (struct virtnet_info *)PT_REGS_PARM1(ctx);
	rq = (struct receive_queue *)PT_REGS_PARM2(ctx);
	vq = BPF_PROBE_VAL(rq->vq);
	vring_vq = (struct vring_virtqueue *)vq;
	if(BPF_PROBE_VAL(vring_vq->packed_ring))
		return 0;

	vring_used = BPF_PROBE_VAL(vring_vq->split.vring.used);
	num = BPF_PROBE_VAL(vring_vq->split.vring.num);
	num_uring = ((BPF_PROBE_VAL(vring_used->idx) & (num-1)) + num \
		- (BPF_PROBE_VAL(vring_vq->last_used_idx) & (num-1))) & (num-1);
	key = (u64)vq;

	val = bpf_map_lookup_elem(&vring_map_rx, &key);
	if (val){
		/* Record Max used status of vring */
		if((BPF_PROBE_VAL(vq->num_free) + num_uring) \
			> (val->num_free + val->num_uring)){
			val->num_free = BPF_PROBE_VAL(vq->num_free);
			val->num_uring = num_uring;
		}
	}
	else{
		dev = BPF_PROBE_VAL(vi->dev);
		/* 0:rx0 1:tx0 2:rx1 3:tx1 ... 2N:rxN 2N+1:txN 2N+2:cvq */
		new.queue_idx = BPF_PROBE_VAL(vq->index) / 2;
		new.num_uring = num_uring;
		new.num_free = BPF_PROBE_VAL(vq->num_free);
		new.num_total = BPF_PROBE_VAL(vring_vq->split.vring.num);
		new.num_queues = BPF_PROBE_VAL(dev->num_rx_queues);
		bpf_probe_read_kernel(new.devname, sizeof(new.devname), \
			(void *)(dev->name));
		bpf_map_update_elem(&vring_map_rx, &key, &new, BPF_NOEXIST);
	}

	return 0;
}

SEC("kprobe/start_xmit")
int bpf__start_xmit(struct pt_regs *ctx)
{
	u32 idx;
	u32 num_uring;
	u32 num;
	long key;
	struct virtnet_info *vi;
	struct net_device *dev;
	struct send_queue *sq;
	struct virtqueue *vq;
	struct vring_virtqueue *vring_vq;
	struct sk_buff *skb;
	struct value_vring new = {0};
	struct value_vring *val;
	vring_used_t *vring_used;

	skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	dev = (struct net_device *)PT_REGS_PARM2(ctx);
	vi = (struct virtnet_info *)((char *)dev \
			+ ALIGN(sizeof(struct net_device), NETDEV_ALIGN));
	idx = (u32) BPF_PROBE_VAL(skb->queue_mapping);
	sq = BPF_PROBE_VAL(vi->sq) + idx;
	vq = BPF_PROBE_VAL(sq->vq);
	vring_vq = (struct vring_virtqueue *)vq;
	if(BPF_PROBE_VAL(vring_vq->packed_ring))
		return 0;

	vring_used = BPF_PROBE_VAL(vring_vq->split.vring.used);
	num = BPF_PROBE_VAL(vring_vq->split.vring.num);
	num_uring = ((BPF_PROBE_VAL(vring_used->idx) & (num-1)) + num \
		- (BPF_PROBE_VAL(vring_vq->last_used_idx) & (num-1))) & (num-1);
	key = (u64)vq;

	val = bpf_map_lookup_elem(&vring_map_tx, &key);
	if (val){
		/* Record Max used status of vring */
		if(BPF_PROBE_VAL(vq->num_free) < val->num_free){
			val->num_uring = num_uring;
			val->num_free = BPF_PROBE_VAL(vq->num_free);
		}
	}
	else{
		new.queue_idx = idx;
		new.num_uring = num_uring;
		new.num_free = BPF_PROBE_VAL(vq->num_free);
		new.num_total = BPF_PROBE_VAL(vring_vq->split.vring.num);
		new.num_queues = BPF_PROBE_VAL(dev->num_tx_queues);
		bpf_probe_read_kernel(new.devname, sizeof(new.devname), \
			(void *)(dev->name));
		bpf_map_update_elem(&vring_map_tx, &key, &new, BPF_NOEXIST);
	}

	return 0;
}
char _license[] SEC("license") = "GPL";
