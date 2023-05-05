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
#include <sys/time.h>
#include <time.h>
#include <signal.h>

/* for bpf*/
#include <linux/bpf.h>
#include <bpf/bpf.h>
/*  bpf end */

#include "bpf/xd_tcpresetstack.h"
#include "common_u.h"
#include "xd_tcpresetstack.skel.h"

#define MAX_SYMS 300000

struct ksym {
		long addr;
		char *name;
};

static unsigned int running = 1;
static struct ksym syms[MAX_SYMS];
static int sym_cnt;
static int stack_mapfd;
/* For Input Parameter */
/* depth of kernel stack, default 3 */
static int stack_depth = 3;

static const struct option long_opts[] = {
	{ "help", 0, 0, 'h' },
	{ "depth", 1, 0, 'd' },
	{ 0 }
};

static int ksym_cmp(const void *p1, const void *p2)
{
		return ((struct ksym *)p1)->addr - ((struct ksym *)p2)->addr;
}

static int load_kallsyms(void)
{
		FILE *f = fopen("/proc/kallsyms", "r");
		char func[256], buf[256];
		char symbol;
		void *addr;
		int i = 0;

		if (!f)
				return -ENOENT;

		while (!feof(f)) {
				if (!fgets(buf, sizeof(buf), f))
						break;
				if (sscanf(buf, "%p %c %s", &addr, &symbol, func) != 3)
						break;
				if (!addr)
						continue;
				syms[i].addr = (long) addr;
				syms[i].name = strdup(func);
				i++;
		}
		fclose(f);
		sym_cnt = i;
		qsort(syms, sym_cnt, sizeof(struct ksym), ksym_cmp);
		return 0;
}

static struct ksym *ksym_search(long key)
{
		int start = 0, end = sym_cnt;

		/* kallsyms not loaded. return NULL */
		if (sym_cnt <= 0)
				return NULL;

		while (start < end) {
				size_t mid = start + (end - start) / 2;

				if ((int)key < (int)(syms[mid].addr))
						end = mid;
				else if ((int)key > (int)(syms[mid].addr))
						start = mid + 1;
				else
						return &syms[mid];
		}
		
		if (start >= 1 && syms[start - 1].addr < key &&
			key < syms[start].addr)
				/* valid ksym */
				return &syms[start - 1];

		/* out of range. return _stext */
		return &syms[0];
}

static void usage(char *cmd)
{
	printf("Usage: xd_tcpresetstack [ OPTIONS ]\n"
			"   -h,--help		   this message\n"
			"   -d,--depth		   Kernel stack Depth\n");
}

static void print_kern_stack(unsigned long *stack)
{
	int i;
	struct ksym *sym;

	for(i = stack_depth - 1; i >= 0; i--){
		if(stack[i] == 0)
			continue;
		printf("%lx ", stack[i]);
		sym = ksym_search(stack[i]);
		printf("%s\n", sym->name);
	}
	printf("  ------ KERNEL STACK END ------ \n\n");
}

static void print_info(struct event_tcpreststack *event)
{
	char src_ip[64];
	char dst_ip[64];
	memset(src_ip, 0, sizeof(src_ip));
	memset(dst_ip, 0, sizeof(dst_ip));
	inet_ntop(event->family, event->saddr, src_ip, sizeof(src_ip));
	inet_ntop(event->family, event->daddr, dst_ip, sizeof(dst_ip));
	printf(" ============== pid: %d, comm:%s ============\n",
			event->pid, event->comm);
	printf(" -- %s:%u	%s:%u --\n", 
			src_ip, ntohs(event->sport),
			dst_ip, ntohs(event->dport));
}

static void print_timeinfo(void)
{
	time_t now;
	time(&now);
	printf("%s", ctime(&now));
}

static void event_handler(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	int ret;
	unsigned int kstack_id = 0;
	struct event_tcpreststack *event;
	unsigned long stack[XDIAG_KERN_STACK_DEPTH];

	event = (struct event_tcpreststack *)data;
	kstack_id = event->kstack_id;
	ret = bpf_map_lookup_elem(stack_mapfd, &kstack_id, &stack);
	if(ret != 0){
		printf("stack_mapfd: bpf_map_lookup_elem failed\n");
		return;
	}
	print_timeinfo();
	print_info(event);
	print_kern_stack(stack);

	return;
}

static void rst_sig_handler(int sig)
{
	running = 0;
}

int main(int argc, char **argv)
{
	int ret = 0;
	int ch;
	struct perf_buffer *pb = NULL;
#ifndef LIBBPF_MAJOR_VERSION
	struct perf_buffer_opts pb_opts = {};
#endif
	struct xd_tcpresetstack_bpf_c *skel;

	while ((ch = getopt_long(argc, argv, "hd:t:", long_opts, NULL)) != -1) {
		switch (ch) {
		case 'd':
			stack_depth = atoi(optarg);
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

	skel = xd_tcpresetstack_bpf_c__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return -1;
	}   

	/* Attach tracepoint */
	ret = xd_tcpresetstack_bpf_c__attach(skel);
	if (ret) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		ret =  -1;
		goto cleanup;
	}

	stack_mapfd = bpf_map__fd(skel->maps.stack_map);
	if (stack_mapfd < 0) {
		fprintf(stderr, "Failed to get BPF map fd\n");
		ret =  -1;
		goto cleanup;
	}

#ifdef LIBBPF_MAJOR_VERSION
	pb = perf_buffer__new(bpf_map__fd(skel->maps.stackinfo_event), \
		16, event_handler, NULL, NULL, NULL);	
#else
	pb_opts.sample_cb = event_handler;
	pb = perf_buffer__new(bpf_map__fd(skel->maps.stackinfo_event), \
			16, &pb_opts); /* 64Kb for each CPU*/
#endif
	if (libbpf_get_error(pb)) {
		fprintf(stderr, "Failed to create perf buffer\n");
		ret =  -1;
		goto cleanup_fd;
	}

	if (load_kallsyms()) {
		printf("failed to process /proc/kallsyms\n");
		ret =  -1;
		goto cleanup_fd;
	}

	signal(SIGINT, rst_sig_handler);
	signal(SIGTERM, rst_sig_handler);
	while(running){
		ret = perf_buffer__poll(pb, 100000); /* timeout 100ms*/
		if(ret < 0 && ret != -EINTR){
			fprintf(stderr, "Polling perf buffer error:%d\n", ret);
			goto cleanup_fd;
		}
	}

cleanup_fd:
	close(stack_mapfd);
cleanup:
	xd_tcpresetstack_bpf_c__destroy(skel);
	return ret;
}

