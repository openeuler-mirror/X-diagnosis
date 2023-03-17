#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/socket.h>
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

/* for bpf */
#include <linux/bpf.h>
#include <bpf/bpf.h>
/* bpf end */

#include "xd_rtnlcheck.h"
#include "common_u.h"
#include "xd_rtnlcheck.skel.h"

#define MAX_SYMS 300000

struct ksym {
	long addr;
	char *name;
};

static unsigned int running = 1;
static struct ksym syms[MAX_SYMS];
static int sym_cnt;
static char *rtnl_lock_name = "rtnl_mutex";

static int ksym_cmp(const void *p1, const void *p2)
{
	return ((struct ksym *)p1)->addr - ((struct ksym *)p2)->addr;
}

int load_kallsyms(void)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	char func[256], buf[256];
	char symbol;
	void *addr;
	int i = 0;

	if (!f)
		return -ENOENT;

	while (fgets(buf, sizeof(buf), f)) {
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

struct ksym *ksym_search(long key)
{
	int start = 0, end = sym_cnt;
	int result;

	/* kallsyms not loaded, return NULL */
	if (sym_cnt <= 0)
		return NULL;

	while(start < end) {
		size_t mid = start + (end - start) / 2;
		result = key - syms[mid].addr;
		if (result < 0)
			end = mid;
		else if (result > 0)
			start = mid + 1;
		else
			return &syms[mid];
	}

	if (start >= 1 && syms[start - 1].addr < key &&
		key < syms[start].addr)
		/* valid ksym */
		return &syms[start - 1];

	/* out of range,return _stext*/
	return &syms[0];
}

long ksym_get_addr(const char *name)
{
	int i;
	for (i = 0; i < sym_cnt; i++) {
		if (strcmp(syms[i].name, name) == 0)
			return syms[i].addr;
	}
	
	return 0;
}

static void rst_sig_handler(int sig)
{
	running = 0;
}

static void event_handler(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	time_t now;
	struct event_rtnl *event;

	event = (struct event_rtnl *)data;
	time(&now);

	if(event->pid != 0) {
		printf("%sThe task %s(pid:%d) is holding the rtnl_mutex!!!\n", ctime(&now), event->comm, event->pid);	
	}
	else {
		printf("%sNo task hold the rtnl_mutex!!!\n", ctime(&now));
	}

	running = 0;
	return;
}

int main(int argc, char **argv)
{
	int ret;
	void *event_pb = NULL;
	struct xd_rtnlcheck_bpf *skel;
#ifndef LIBBPF_MAJOR_VERSION
	struct perf_buffer_opts pb_opts = {};
#endif

	memlock_rlimit();

	skel = xd_rtnlcheck_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return -1;
	}

	/* Attach tracepoint */
	ret = xd_rtnlcheck_bpf__attach(skel);
	if (ret) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		ret = -1;
		goto cleanup;
	}

#ifdef LIBBPF_MAJOR_VERSION
	event_pb = perf_buffer__new(bpf_map__fd(skel->maps.info_event), \
			16, event_handler, NULL, NULL, NULL);
#else
	pb_opts.sample_cb = event_handler;
	event_pb = perf_buffer__new(bpf_map__fd(skel->maps.info_event), \
				16, &pb_opts);
#endif
	if (libbpf_get_error(event_pb)) {
		fprintf(stderr, "Failed to create perf buffer\n");
		ret = -1;
		goto cleanup;
	}

	if (load_kallsyms()) {
		printf("falied to process /proc/kallsyms\n");
		ret = -1;
		goto cleanup;
	}

	skel->bss->rtnl_lock_addr = ksym_get_addr(rtnl_lock_name);

	signal(SIGINT, rst_sig_handler);
	signal(SIGTERM, rst_sig_handler);
	while (running) {
		ret = perf_buffer__poll(event_pb, 1000);
		if (ret < 0 && ret != -EINTR) {
			fprintf(stderr, "Polling perf buffer error:%d\n", ret);
		}
	}

cleanup:
	xd_rtnlcheck_bpf__destroy(skel);
	return ret;
}
