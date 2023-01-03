#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <asm/types.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <signal.h>
#include <sys/time.h>


/* for bpf*/
#include <linux/bpf.h>
#include <bpf/bpf.h>
/*  bpf end */

#include "xd_netvringcheck.h"
#include "common_u.h"
#include "xd_netvringcheck.skel.h"

#define BPF_NEXT_KEY ({key = next_key; continue;})

static int map_fd;
static unsigned int interval_time = 1;
static unsigned int filter_idx = 0xffff;
static unsigned int running = 1;
static char filter_name[IFNAMSIZ];

static const struct option long_opts[] = {
	{ "help", 0, 0, 'h' },
	{ "interval", 1, 0, 'i' },
	{ "queueidx", 1, 0, 'q' },
	{ 0 }
};

void sig_handler(int sig)
{
	switch(sig){
		case SIGTERM:
		case SIGINT:
			running = 0;
			break;
		default:
			break;
	}
}

static int vring_check(const char *trans)
{
	int ret;
	unsigned int num_avring;
	long key, next_key;
	struct value_vring value;

	printf("%12s   rx/tx %12s %32s\n", "NETDEV", "idx/total", \
			"VRING:free/uvring/avring/total");
	while(running){
		key = 0;
		next_key = 0;
		while(bpf_map_get_next_key(map_fd, &key, &next_key) == 0){
			ret = bpf_map_lookup_elem(map_fd, &next_key, &value);
			if(ret != 0){
				printf("bpf_map_lookup_elem failed\n");
				BPF_NEXT_KEY;
			}
			if(strcmp(filter_name, value.devname) != 0)
				BPF_NEXT_KEY;
			if(filter_idx != 0xffff && filter_idx != value.queue_idx)
				BPF_NEXT_KEY;
			num_avring = value.num_total - value.num_uring - value.num_free;
			printf("%12s%6s %10d/%d %16d/%4d/%4d/%4d\n", value.devname, trans, \
				/* queue idx: start from 1 */
				value.queue_idx + 1, value.num_queues, \
				value.num_free, value.num_uring, num_avring, value.num_total);

			bpf_map_delete_elem(map_fd, &next_key);
			key = next_key;
		}
		sleep(interval_time);
	} 
	
	return 0;
}

static void usage(char *cmd)
{
	printf("Usage: %s DEVNAME [rx/tx] [ OPTIONS ]\n" \
			"  [OPTIONS]\n" \
			"\t-h,--help\t\t\tthis message\n" \
			"\t-i,--interval\t\t\tThe interval time of the probe/s\n" \
			"\t-q,--queueidx\t\t\tfilter virtnet queue idx\n", \
			cmd);
}

int main(int argc, char **argv)
{
	int ch;
	int ret = 0;
	struct xd_netvringcheck_bpf *skel;

	if(argc == 1 || (argc == 2 && strcmp(argv[1], "-h") == 0)){
		usage(argv[0]);
		return 0;
	}
	if(argc < 3){
		usage(argv[0]);
		return -1;
	}
	strncpy(filter_name, argv[1], sizeof(filter_name));
	if(strlen(filter_name) < 2){
		usage(argv[0]);
		return -1;
	}
	while ((ch = getopt_long(argc-2, argv+2, "hq:i:", long_opts, NULL)) != -1) {
		switch (ch) {
		case 'i':
			interval_time = atoi(optarg);
			break;
		case 'q':
			filter_idx = atoi(optarg);
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			printf("invalid argument\n");
			return -1;
		}
	}

	memlock_rlimit();

	skel = xd_netvringcheck_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		ret = -1;
		goto cleanup;
	}   

	/* Attach tracepoint */
	ret = xd_netvringcheck_bpf__attach(skel);
	if (ret) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		ret = -1;
		goto cleanup;
	}

	if(strcmp(argv[2], "rx") == 0)
		map_fd = bpf_map__fd(skel->maps.vring_map_rx);
	else if(strcmp(argv[2], "tx") == 0)
		map_fd = bpf_map__fd(skel->maps.vring_map_tx);
	else{
		fprintf(stderr, "Invalid argument, neet rx/tx\n");
		usage(argv[0]);
		ret = -1;
		goto cleanup;
	}
	if (map_fd < 0) {
		fprintf(stderr, "Failed to get BPF map fd\n");
		ret = -1;
		goto cleanup;
	}
	
	vring_check(argv[2]);

cleanup:
	xd_netvringcheck_bpf__destroy(skel);
	return ret;
}
