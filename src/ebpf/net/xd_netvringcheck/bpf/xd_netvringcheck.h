#ifndef __XD_NETVRINGCHECK_H__
#define __XD_NETVRINGCHECK_H__

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

struct key_vring_filter {
	char devname[IFNAMSIZ];
	unsigned int num;
};

struct value_vring {
	char devname[IFNAMSIZ];
	unsigned int num_queues;
	unsigned int queue_idx;
	unsigned int num_uring;
	unsigned int num_free;
	unsigned int num_total;
};
#endif
