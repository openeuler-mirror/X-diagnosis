#ifndef __XD_NETVRINGCHECK_K_H__
#define __XD_NETVRINGCHECK_K_H__

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#if (65536/PAGE_SIZE + 1) < 16
#define MAX_SKB_FRAGS 16UL
#else
#define MAX_SKB_FRAGS (65536/PAGE_SIZE + 1)
#endif

#ifndef NETDEV_ALIGN
#define	NETDEV_ALIGN 32
#endif
#ifndef ALIGN
#define ALIGN(x, a)   (((x) + (a) - 1) & ~((a) - 1))
#endif

#if defined(__TARGET_ARCH_arm64)
#define VRING_AVAIL_ALIGN_SIZE 2
#define VRING_USED_ALIGN_SIZE 4
#define VRING_DESC_ALIGN_SIZE 16

typedef __u32 __virtio32;
typedef __u64 __virtio64;
/* Virtio ring descriptors: 16 bytes.  These can chain together via "next". */
struct vring_desc {
	/* Address (guest-physical). */
	__virtio64 addr;
	/* Length. */
	__virtio32 len;
	/* The flags as indicated above. */
	__virtio16 flags;
	/* We chain unused descriptors via this, too */
	__virtio16 next;
};

struct vring_avail {
	__virtio16 flags;
	__virtio16 idx;
	__virtio16 ring[];
};

/* u32 is used here for ids for padding reasons. */
struct vring_used_elem {
	/* Index of start of used descriptor chain. */
	__virtio32 id;
	/* Total length of the descriptor chain which was used (written to) */
	__virtio32 len;
};

typedef struct vring_used_elem __attribute__((aligned(VRING_USED_ALIGN_SIZE)))
	vring_used_elem_t;

struct vring_used {
	__virtio16 flags;
	__virtio16 idx;
	vring_used_elem_t ring[];
};

typedef struct vring_desc __attribute__((aligned(VRING_DESC_ALIGN_SIZE)))
	vring_desc_t;
typedef struct vring_avail __attribute__((aligned(VRING_AVAIL_ALIGN_SIZE)))
	vring_avail_t;
typedef struct vring_used __attribute__((aligned(VRING_USED_ALIGN_SIZE)))
	vring_used_t;

struct vring {
	unsigned int num;
	vring_desc_t *desc;
	vring_avail_t *avail;
	vring_used_t *used;
};

/* struct vring_virtqueue */
struct vring_desc_state_split {
	void *data;			/* Data for callback. */
	struct vring_desc *indir_desc;	/* Indirect descriptor, if any. */
};

struct vring_desc_state_packed {
	void *data;			/* Data for callback. */
	struct vring_packed_desc *indir_desc; /* Indirect descriptor, if any. */
	u16 num;			/* Descriptor list length. */
	u16 next;			/* The next desc state in a list. */
	u16 last;			/* The last desc state in a list. */
};

struct vring_desc_extra_packed {
	dma_addr_t addr;		/* Buffer DMA addr. */
	u32 len;			/* Buffer length. */
	u16 flags;			/* Descriptor flags. */
};

struct vring_virtqueue {
	struct virtqueue vq;
	/* Is this a packed ring? */
	bool packed_ring;
	/* Is DMA API used? */
	bool use_dma_api;
	/* Can we use weak barriers? */
	bool weak_barriers;
	/* Other side has made a mess, don't try any more. */
	bool broken;
	/* Host supports indirect buffers */
	bool indirect;
	/* Host publishes avail event idx */
	bool event;
	/* Head of free buffer list. */
	unsigned int free_head;
	/* Number we've added since last sync. */
	unsigned int num_added;
	/* Last used index we've seen. */
	u16 last_used_idx;

	union {
		/* Available for split ring */
		struct {
			/* Actual memory layout for this queue. */
			struct vring vring;
			/* Last written value to avail->flags */
			u16 avail_flags_shadow;
			/*
			 * Last written value to avail->idx in
			 * guest byte order.
			 */
			u16 avail_idx_shadow;
			/* Per-descriptor state. */
			struct vring_desc_state_split *desc_state;
			/* DMA address and size information */
			dma_addr_t queue_dma_addr;
			size_t queue_size_in_bytes;
		} split;

		/* Available for packed ring */
		struct {
			/* Actual memory layout for this queue. */
			struct {
				unsigned int num;
				struct vring_packed_desc *desc;
				struct vring_packed_desc_event *driver;
				struct vring_packed_desc_event *device;
			} vring;
			/* Driver ring wrap counter. */
			bool avail_wrap_counter;
			/* Device ring wrap counter. */
			bool used_wrap_counter;
			/* Avail used flags. */
			u16 avail_used_flags;
			/* Index of the next avail descriptor. */
			u16 next_avail_idx;
			/*
			 * Last written value to driver->flags in
			 * guest byte order.
			 */
			u16 event_flags_shadow;
			/* Per-descriptor state. */
			struct vring_desc_state_packed *desc_state;
			struct vring_desc_extra_packed *desc_extra;
			/* DMA address and size information */
			dma_addr_t ring_dma_addr;
			dma_addr_t driver_event_dma_addr;
			dma_addr_t device_event_dma_addr;
			size_t ring_size_in_bytes;
			size_t event_size_in_bytes;
		} packed;
	};

	/* How to notify other side. FIXME: commonalize hcalls! */
	bool (*notify)(struct virtqueue *vq);
	/* DMA, allocation, and size information */
	bool we_own_ring;
#ifdef DEBUG
	/* They're supposed to lock for us. */
	unsigned int in_use;
	/* Figure out if their kicks are too delayed. */
	bool last_add_time_valid;
	ktime_t last_add_time;
#endif
};
/* end struct vring_virtqueue */
#endif

struct virtnet_sq_stats {
	struct u64_stats_sync syncp;
	u64 packets;
	u64 bytes;
	u64 xdp_tx;
	u64 xdp_tx_drops;
	u64 kicks;
};

struct send_queue {
	struct virtqueue *vq;
	struct scatterlist sg[MAX_SKB_FRAGS + 2];
	char name[40];
	struct virtnet_sq_stats stats;
	struct napi_struct napi;
};

struct ewma_pkt_len {
	unsigned long internal;
};

struct virtnet_rq_stats {
	struct u64_stats_sync syncp;
	u64 packets;
	u64 bytes;
	u64 drops;
	u64 xdp_packets;
	u64 xdp_tx;
	u64 xdp_redirects;
	u64 xdp_drops;
	u64 kicks;
};
/* Internal representation of a receive virtqueue */
struct receive_queue {
	struct virtqueue *vq;
	struct napi_struct napi;
	struct bpf_prog *xdp_prog;
	struct virtnet_rq_stats stats;
	struct page *pages;
	struct ewma_pkt_len mrg_avg_pkt_len;
	struct page_frag alloc_frag;
	struct scatterlist sg[MAX_SKB_FRAGS + 2];
	unsigned int min_buf_len;
	char name[40];
	struct xdp_rxq_info xdp_rxq;
};

struct virtnet_info {
	struct virtio_device *vdev;
	struct virtqueue *cvq;
	struct net_device *dev;
	struct send_queue *sq;
	struct receive_queue *rq;
	unsigned int status;
	u16 max_queue_pairs;
	u16 curr_queue_pairs;
	u16 xdp_queue_pairs;
	bool big_packets;
	bool mergeable_rx_bufs;
	bool has_cvq;
	bool any_header_sg;
	u8 hdr_len;
	struct delayed_work refill;
	struct work_struct config_work;
	bool affinity_hint_set;
	struct hlist_node node;
	struct hlist_node node_dead;
	struct control_buf *ctrl;
	u8 duplex;
	u32 speed;
	unsigned long guest_offloads;
	struct failover *failover;
};
#endif
