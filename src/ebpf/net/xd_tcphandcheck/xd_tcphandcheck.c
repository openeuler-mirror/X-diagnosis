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

#include "bpf/xd_tcphandcheck.h"
#include "xd_tcphandcheck.skel.h"

#define MAX_UADDR_STRLEN 32

static unsigned int running = 1;
static int ret_mapfd;

static void func_sig_handler(int sig)
{
	running = 0;
}

static int bind_ret_handler(struct xd_kern_msg *kern_msg)
{
	unsigned int addr;
	unsigned short port;
	int retval;
	struct in_addr addr_in;
	char addr_s[MAX_UADDR_STRLEN] = {0};

	port = kern_msg->addr_info.srcport;
	addr = kern_msg->addr_info.srcaddr;
	retval = kern_msg->retval;

	port = htons(port);
	addr_in.s_addr = addr;
	strncpy(addr_s, inet_ntoa(addr_in), MAX_UADDR_STRLEN - 1);

	switch (retval)
	{
		case -EADDRNOTAVAIL:
			printf("%s:%d inet_bind: return -EADDRNOTAVAIL, check if ip_nonlocal_bind is disable and your address is not local\n", addr_s, port);
			break;
		case -EACCES:
			printf("%s:%d inet_bind: return -EACCES, check if your port is less than ip_unprivileged_port_start\n", addr_s, port);
			break;
		case -EINVAL:
			printf("%s:%d inet_bind: return -EINVAL, check if you bind to an existing link or this socket has already existed bound to the port\n", addr_s, port);
			break;
		case -EADDRINUSE:
			printf("%s:%d inet_bind: return -EADDRINUSE, check if this port has been used by others\n", addr_s, port);
			break;
		default:
			break;
	}

	return 0;
}

static int sys_socket_handler(struct xd_kern_msg *kern_msg)
{
	int retval = kern_msg->retval;

	switch (retval)
	{
		case -ENFILE:
		case -EMFILE:
			printf("sys_socket: failed, check if fd is reach limit\n");
		default:
			break;
	}

	return 0;
}

static int backlog_chk_handler(struct xd_kern_msg *kern_msg)
{
	unsigned int saddr, daddr;
	unsigned short sport, dport;
	struct in_addr saddr_in, daddr_in;
	char saddr_s[MAX_UADDR_STRLEN] = {0};
	char daddr_s[MAX_UADDR_STRLEN] = {0};

	sport = kern_msg->addr_info.srcport;
	saddr = kern_msg->addr_info.srcaddr;
	dport = kern_msg->addr_info.dstport;
	daddr = kern_msg->addr_info.dstaddr;

	sport = htons(sport);
	dport = htons(dport);
	saddr_in.s_addr = saddr;
	daddr_in.s_addr = daddr;
	strncpy(saddr_s, inet_ntoa(saddr_in), MAX_UADDR_STRLEN - 1);
	strncpy(daddr_s, inet_ntoa(daddr_in), MAX_UADDR_STRLEN - 1);

	printf("backlog reach max: src %s:%d dst %s:%d\n", saddr_s, sport, daddr_s, dport);

	return 0;
}

static int tw_state_process_handler(struct xd_kern_msg *kern_msg)
{
	unsigned int saddr, daddr;
	unsigned short sport, dport;
	struct in_addr saddr_in, daddr_in;
	char saddr_s[MAX_UADDR_STRLEN] = {0};
	char daddr_s[MAX_UADDR_STRLEN] = {0};

	sport = kern_msg->addr_info.srcport;
	saddr = kern_msg->addr_info.srcaddr;
	dport = kern_msg->addr_info.dstport;
	daddr = kern_msg->addr_info.dstaddr;

	sport = htons(sport);
	dport = htons(dport);
	saddr_in.s_addr = saddr;
	daddr_in.s_addr = daddr;
	strncpy(saddr_s, inet_ntoa(saddr_in), MAX_UADDR_STRLEN - 1);
	strncpy(daddr_s, inet_ntoa(daddr_in), MAX_UADDR_STRLEN - 1);

	printf("timewait process check failed: src %s:%d dst %s:%d\n", saddr_s, sport, daddr_s, dport);

	return 0;
}

static int tcp_in_window_handler(struct xd_kern_msg *kern_msg)
{
	unsigned int saddr, daddr;
	unsigned short sport, dport;
	struct in_addr saddr_in, daddr_in;
	char saddr_s[MAX_UADDR_STRLEN] = {0};
        char daddr_s[MAX_UADDR_STRLEN] = {0};

	sport = kern_msg->addr_info.srcport;
	saddr = kern_msg->addr_info.srcaddr;
	dport = kern_msg->addr_info.dstport;
	daddr = kern_msg->addr_info.dstaddr;

	sport = htons(sport);
	dport = htons(dport);
	saddr_in.s_addr = saddr;
	daddr_in.s_addr = daddr;
	strncpy(saddr_s, inet_ntoa(saddr_in), MAX_UADDR_STRLEN - 1);
	strncpy(daddr_s, inet_ntoa(daddr_in), MAX_UADDR_STRLEN - 1);

	printf("tcp in window check failed: src %s:%d dst %s:%d\n", saddr_s, sport, daddr_s, dport);

	return 0;
}

static void probe_handler(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	struct xd_kern_msg *kern_msg;
	kern_msg = (struct xd_kern_msg *)data;

	switch (kern_msg->msg_type)
	{
		case __INET_BIND:
			bind_ret_handler(kern_msg);
			break;
		case SOCKET_CREATE:
			sys_socket_handler(kern_msg);
			break;
		case TCP_V4_SYN_RECV_SOCK:
			backlog_chk_handler(kern_msg);
			break;
		case TCP_TIMEWAIT_STATE_PROCESS:
			tw_state_process_handler(kern_msg);
			break;
		case TCP_IN_WINDOW:
			tcp_in_window_handler(kern_msg);
			break;
		default:
			break;
			
	}

	return;
}

int main(int argc, char **argv)
{
	int ret = 0;
	struct perf_buffer *pb = NULL;
#ifndef LIBBPF_MAJOR_VERSION
	struct perf_buffer_opts pb_opts = {};
#endif
	struct xd_tcphandcheck_bpf_c *skel;

	skel = xd_tcphandcheck_bpf_c__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return -1;
	}   

	ret = xd_tcphandcheck_bpf_c__attach(skel);
	if (ret) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		ret =  -1;
		goto cleanup;
	}

	ret_mapfd = bpf_map__fd(skel->maps.xd_kern_events);
	if (ret_mapfd < 0) {
		fprintf(stderr, "Failed to get BPF map fd\n");
		ret =  -1;
		goto cleanup;
	}
#ifdef LIBBPF_MAJOR_VERSION
	pb = perf_buffer__new(bpf_map__fd(skel->maps.xd_kern_events), \
			16, probe_handler, NULL, NULL, NULL);
#else
	memset(&pb_opts, 0, sizeof(pb_opts));
	pb_opts.sample_cb = probe_handler;
	pb = perf_buffer__new(bpf_map__fd(skel->maps.xd_kern_events), \
			16, &pb_opts); /* 64Kb for each CPU*/
#endif
	if (libbpf_get_error(pb)) {
		fprintf(stderr, "Failed to create perf buffer\n");
		ret =  -1;
		goto cleanup_fd;
	}

	signal(SIGINT, func_sig_handler);
	signal(SIGTERM, func_sig_handler);
	while(running){
		ret = perf_buffer__poll(pb, 100000); /* timeout 100ms*/
		if(ret < 0 && ret != -EINTR){
			fprintf(stderr, "Polling perf buffer error:%d\n", ret);
			goto cleanup_fd;
		}
	}

cleanup_fd:
	close(ret_mapfd);
cleanup:
	xd_tcphandcheck_bpf_c__destroy(skel);
	return ret;
}

