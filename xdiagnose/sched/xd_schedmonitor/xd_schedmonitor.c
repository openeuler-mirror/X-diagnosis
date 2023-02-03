#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/sysmacros.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <asm/types.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>

/* for bpf*/
#include <linux/bpf.h>
#include <bpf/bpf.h>
/*  bpf end */

#include "kallsyms.h"
#include "xd_schedmonitor.h"
#include "common_u.h"
#include "xd_schedmonitor.skel.h"

static unsigned int running = 1;

static unsigned int threshold_ms = 500;
static unsigned short kstack_enable = 1;
static unsigned short waitsched_enable = 1;

/* ebpf interface from kernel space */
static struct xd_schedmonitor_bpf *skel;
static int args_mapfd;
static int kstackfd;
static void *event_pb;

static const struct option long_opts[] = {
	{ "help", 0, 0, 'h' },
	{ "threshold", 1, 0, 't' },
	{ "kstack", 1, 0, 'k' },
	{ "waitsched", 1, 0, 'w' },
	{ 0 }
};

static void print_timeinfo(void)
{
	char timestr[64]; /* time format max len */
	time_t now;
	time(&now);
	strncpy(timestr, ctime(&now), sizeof(timestr));
	timestr[strlen(timestr)-1] = 0;
	printf("%s -- ", timestr);
}

static 
void monitor_evhandler(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	int ret;
        struct event_schedmonitor *event;
	unsigned long kstack[XDIAG_KERN_STACK_DEPTH];

	event = (struct event_schedmonitor *)data;
	print_timeinfo();
	switch(event->type){
	case EVENT_SWITCH_OVERTIME:
		printf("process run overtime:%lldms, cpu=%d, pid=%d, comm=%s\n", \
			event->runtime_ns / (1000 * 1000), event->cpu, \
			event->pid, event->comm);
		break;
	case EVENT_IRQ_OVERTIME:
		printf("irq run overtime:%lldms, cpu=%d, irq=%d, action=%s\n", \
			event->runtime_ns / (1000 * 1000), event->cpu, \
			event->irq, event->irqname);
		break;
	case EVENT_WAIT_SCHED:
		printf("process waiting %lldms for sched, cpu=%d, pid=%d, comm=%s\n", \
			event->runtime_ns / (1000 * 1000), event->cpu, \
			event->pid, event->comm);
		break;
	default:
		printf("invalid event type:%d\n", event->type);
		return;
	}

	/* show stackinfo */
	memset(kstack, 0, sizeof(kstack));
	ret = bpf_map_lookup_elem(kstackfd, &event->kstackid, &kstack);
	if(ret < 0)
		return;
	print_kern_stack(kstack, XDIAG_KERN_STACK_DEPTH);
	bpf_map_delete_elem(kstackfd, &event->kstackid);

}

static int do_monitor()
{
	int ret;

	while(running){
		ret = perf_buffer__poll(event_pb, 100000);/* timeout 100ms*/
		if(ret < 0 && ret!= -EINTR){
			printf("Polling runinfo perfbuffer failed:%d\n", ret);
			return ret;
		}
	}
	return 0;
}

static int config_paras()
{
	int ret;
	unsigned int key = 0;
	struct args_user value;
	memset(&value, 0, sizeof(value));

	value.waitsched_enable = waitsched_enable;
	value.kstack_enable = kstack_enable;
	/* ms to ns */
	printf("CONFIG: threshold: %d ms\n", threshold_ms);
	value.threshold = (__u64)(threshold_ms) * 1000 * 1000;
	ret = bpf_map_update_elem(args_mapfd, &key, &value, BPF_ANY);
	if(ret < 0)
		printf("config threshold failed\n");
	return ret;
}

static int load_skel()
{
	int ret;
#ifndef LIBBPF_MAJOR_VERSION
	struct perf_buffer_opts pb_opts;
#endif
	skel = xd_schedmonitor_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return -1;
	}   

	ret = xd_schedmonitor_bpf__attach(skel);
	if (ret) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		return -1;
	}

	args_mapfd = bpf_map__fd(skel->maps.args_map);
	if (args_mapfd < 0) {
		fprintf(stderr, "Failed to get BPF map fd\n");
		return -1;
	}

	kstackfd = bpf_map__fd(skel->maps.run_kstackmap);
	if (kstackfd < 0) {
		fprintf(stderr, "Failed to get BPF map fd\n");
		return -1;
	}
	
#ifdef LIBBPF_MAJOR_VERSION
	event_pb = perf_buffer__new(bpf_map__fd(skel->maps.ev_overrun), \
			/* 64Kb for each CPU*/
			16, monitor_evhandler, NULL, NULL, NULL);
#else
	/* old libbpf version( version < 0.6) */
	memset(&pb_opts, 0, sizeof(pb_opts));
	pb_opts.sample_cb = monitor_evhandler;
	event_pb = perf_buffer__new(bpf_map__fd(skel->maps.ev_overrun), \
			/* 64Kb for each CPU*/
			16, &pb_opts);
#endif
	if (libbpf_get_error(event_pb)) {
		fprintf(stderr, "Failed to create perf buffer\n");
		return -1;
	}
	return 0;
}

static void sig_handler(int sig)
{
	running = 0;
}

static void usage(char *cmd)
{
	printf("Usage: xd_schedmonitor [ OPTIONS ]\n"
		"   -h,--help		this message\n"
		"   -k,--kstack	  	yes/no, show kernel stack\n"
		"   -w,--waitsched    	yes/no, trace wait/wakeup slow event\n"
		"   -t,--threshold    	The threshold for report/ms\n");
}

int main(int argc, char **argv)
{
	int ret = 0;
	int ch;

	if(argc < 2){
		usage(argv[0]);
		return -1;
	}

	while ((ch = getopt_long(argc, argv, "hd:t:k:w:", long_opts, NULL)) != -1) {
		switch (ch) {
		case 't':
			threshold_ms = atoi(optarg);
			break;
		case 'k':
			if(strcmp(optarg, "no") == 0)
				kstack_enable = 0;
			break;
		case 'w':
			if(strcmp(optarg, "no") == 0)
				waitsched_enable = 0;
			break;
		case 'h':
			usage(argv[0]);
			return ret;
		default:
			printf("invalid argument\n");
			return -1;
		}
	}

	memlock_rlimit();

	if (load_kallsyms()) {
		printf("failed to process /proc/kallsyms\n");
		return -1;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	ret = load_skel();
	if(ret < 0)
		goto cleanup;

	/* config common parameters */
	config_paras();
	ret = do_monitor();

cleanup:
	if(kstackfd > 0)
		close(kstackfd);
	if(args_mapfd > 0)
		close(args_mapfd);
	xd_schedmonitor_bpf__destroy(skel);
	return ret;
}

