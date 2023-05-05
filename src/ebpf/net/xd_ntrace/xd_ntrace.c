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

#include "common_u.h"
#include "bpf/xd_ntrace.h"
#include "xd_ntrace.skel.h"

static unsigned int running = 1;
static int filter_map;
static struct ntrace_filter_info filter = {0};

char *trace_result[IPPROTO_MAX][NET_MAX + 1] = {
	[IPPROTO_ICMP][NET_SKB_RCV] =
		"check virtual device(eg:vlan tag/bridge)",
	[IPPROTO_ICMP][NET_IP_RCV_CORE] = "check PREROUTING hook",
	[IPPROTO_ICMP][NET_IP_ROUTE_INPUT] = "check input route",
	[IPPROTO_ICMP][NET_IP_INPUT] = "check INPUT hook",
	[IPPROTO_ICMP][NET_IP_INPUT_FINISH] = "check icmp packet reassembly",
	[IPPROTO_ICMP][NET_ICMP_RCV] = "check icmp_echo_ignore_all in sysctl",
	[IPPROTO_ICMP][NET_ICMP_RCV_EXT] = "check icmp checksum",
	[IPPROTO_ICMP][NET_ICMP_REPLAY] = "check output route",
	[IPPROTO_ICMP][NET_IP_LOCAL_OUTPUT] = "check OUTPUT hook",
	[IPPROTO_ICMP][NET_IP_OUTPUT] = "check POSTROUTING hook",
	[IPPROTO_ICMP][NET_IP_FINISH_OUTPUT] = "packet too big",
	[IPPROTO_ICMP][NET_IP_FINISH_OUTPUT2] = "check neigh",
	[IPPROTO_ICMP][NET_DEV_QUEUE_XMIT] = "drop by tc",
	[IPPROTO_ICMP][NET_DEV_SCH_DIR_XMIT] = "txq is stop or frozen",
	[IPPROTO_ICMP][NET_RAW_SENDMSG] = "check output route",
	[IPPROTO_ICMP][NET_PING_RCV_SKB] = "check recv buf",
	[IPPROTO_ICMP][NET_RCV_OVERFLOW] = "ping rcv queue overflow",
	[IPPROTO_ICMP][NET_SND_OVERFLOW] = "ping snd queue overflow",
	[IPPROTO_ICMP][NET_MAX] = " ",

	[IPPROTO_ICMPV6][NET_SKB_RCV] =
		"check virtual device(eg:vlan tag/bridge)",
	[IPPROTO_ICMPV6][NET_IP_RCV_CORE] = "check PREROUTING hook",
	[IPPROTO_ICMPV6][NET_IP_ROUTE_INPUT] = "check input route",
	[IPPROTO_ICMPV6][NET_IP_INPUT] = "check INPUT hook",
	[IPPROTO_ICMPV6][NET_IP_INPUT_FINISH] = "check icmp packet reassembly",
	[IPPROTO_ICMPV6][NET_ICMP_RCV] =
		"check icmpv6_echo_ignore_all in sysctl",
	[IPPROTO_ICMPV6][NET_ICMP_RCV_EXT] = "check icmpv6 checksum",
	[IPPROTO_ICMPV6][NET_ICMP_REPLAY] = "check ouput route",
	[IPPROTO_ICMPV6][NET_IP_LOCAL_OUTPUT] = "check OUTPUT hook",
	[IPPROTO_ICMPV6][NET_IP_OUTPUT] = "check POSTROUTING hook",
	[IPPROTO_ICMPV6][NET_IP_FINISH_OUTPUT] = "packet too big",
	[IPPROTO_ICMPV6][NET_IP_FINISH_OUTPUT2] = "check neigh",
	[IPPROTO_ICMPV6][NET_DEV_QUEUE_XMIT] = "drop by tc",
	[IPPROTO_ICMPV6][NET_DEV_SCH_DIR_XMIT] = "txq is stop or frozen",
	[IPPROTO_ICMPV6][NET_RAW_SENDMSG] = "check ouput route",
	[IPPROTO_ICMPV6][NET_PING_RCV_SKB] = "check recv buf",
	[IPPROTO_ICMPV6][NET_RCV_OVERFLOW] = "ping rcv queue overrflow",
	[IPPROTO_ICMPV6][NET_SND_OVERFLOW] = "ping snd queue overrflow",
	[IPPROTO_ICMPV6][NET_MAX] = " "};

static const struct option long_opts[] = {{"help", 0, 0, 'h'},
					  {"protocol", 1, 0, 'p'},
					  {"host", 1, 0, 'H'},
					  {"hostport", 1, 0, 'P'},
					  {0}};

static void usage(char *cmd)
{
	printf("Start network stack trace [support v4/v6 and tcp/udp/icmp]\n\n");
	printf("Usage: %s [...]\n", cmd);
	printf("-p, --protocol <tcp/udp/icmp/icmp6> protocol\n");
	printf("-H, --host      <src/dest ip>\n");
	printf("-P, --hostport  <src/dest port>\n");
	printf("-h, --help      Display this help\n");
}

static int parse_ipstr(const char *ipstr, __be32 *addr)
{
	if (inet_pton(AF_INET6, ipstr, addr) == 1) {
		return AF_INET6;
	} else if (inet_pton(AF_INET, ipstr, addr) == 1) {
		addr[1] = addr[2] = addr[3] = 0;
		return AF_INET;
	}
	printf("%s is an invalid IP\n", ipstr);
	return AF_UNSPEC;
}

static int parse_ports(const char *port_str, __be16 *port)
{
	char *end;
	long portnum;

	portnum = strtol(optarg, &end, 10);
	if (portnum < 1 || portnum > 65535) {
		printf("Invalid port(s):%s\n", optarg);
		return 1;
	}
	*port = portnum;
	return 0;
}

static int parse_protostr(const char *proto_str)
{
	if (!strcmp(proto_str, "tcp"))
		return IPPROTO_TCP;
	else if (!strcmp(proto_str, "udp"))
		return IPPROTO_UDP;
	else if (!strcmp(proto_str, "icmp"))
		return IPPROTO_ICMP;
	else if (!strcmp(proto_str, "icmp6"))
		return IPPROTO_ICMPV6;
	else {
		printf("Invalid protocol: %s\n", proto_str);
		return IPPROTO_MAX;
	}
}

static void event_handler(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	struct ntrace_put_user_info *event;
	int protocol = filter.protocol;
	int stage;
	char dip[64] = {0};
	char sip[64] = {0};
	event = (struct ntrace_put_user_info *)data;
	stage = event->stage;

	if (event->icmp_type == ICMP_ACTIVE) {
		inet_ntop(filter.family, filter.hostaddr, dip, sizeof(dip));
		inet_ntop(filter.family, event->saddr, sip, sizeof(sip));
		printf("active ping: [%s->%s] cpu[%d] queue[%d] icmp_seq=%u %s\n",
		       sip, dip, event->cpuid, event->queue, event->icmp_seq,
		       trace_result[protocol][stage]);
	} else if (event->icmp_type == ICMP_PASSIVE) {
		inet_ntop(filter.family, filter.hostaddr, dip, sizeof(dip));
		printf("passive ping: [%s->%s] cpu[%d] queue[%d] icmp_seq=%u time=%lu us %s\n",
		       sip, dip, event->cpuid, event->queue, event->icmp_seq,
		       event->ts, trace_result[protocol][stage]);
	}
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
	int key = 0;
	char hostaddr[64] = {0};
	struct perf_buffer *pb = NULL;
#ifndef LIBBPF_MAJOR_VERSION
	struct perf_buffer_opts pb_opts = {};
#endif
	struct xd_ntrace_bpf_c *skel;
	const char *optstr = "H:P:p:h";
	while ((ch = getopt_long(argc, argv, optstr, long_opts, NULL)) != -1) {
		switch (ch) {
		case 'p':
			filter.protocol = parse_protostr(optarg);
			if (filter.protocol == IPPROTO_MAX)
				return 1;
			break;
		case 'H':
			filter.family = parse_ipstr(optarg, filter.hostaddr);
			if (filter.family == AF_UNSPEC)
				return 1;
			break;
		case 'P':
			if (parse_ports(optarg, &filter.hostport))
				return 1;
			break;
		case 'h':
			usage(argv[0]);
			return ret;
		default:
			printf("invalid argument\n");
			return -1;
		}
	}
	inet_ntop(filter.family, filter.hostaddr, hostaddr, sizeof(hostaddr));
	printf("trace ip:%s\n", hostaddr);

	memlock_rlimit();

	skel = xd_ntrace_bpf_c__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return -1;
	}

	/* Attach tracepoint */
	ret = xd_ntrace_bpf_c__attach(skel);
	if (ret) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		ret = -1;
		goto cleanup;
	}

	filter_map = bpf_map__fd(skel->maps.filter_map);
	if (filter_map < 0) {
		fprintf(stderr, "Failed to get BPF map fd\n");
		ret = -1;
		goto cleanup;
	}
	ret = bpf_map_update_elem(filter_map, &key, &filter, 0);
	if (ret != 0)
		fprintf(stderr, "Failed to bpf_map_update_ele fd,error:%d\n",
			errno);

#ifdef LIBBPF_MAJOR_VERSION
	pb = perf_buffer__new(bpf_map__fd(skel->maps.net_trace_event), 16,
			      event_handler, NULL, NULL, NULL);
#else
	pb_opts.sample_cb = event_handler;
	pb = perf_buffer__new(bpf_map__fd(skel->maps.net_trace_event), 16,
			      &pb_opts);
#endif

	if (libbpf_get_error(pb)) {
		fprintf(stderr, "Failed to create perf buffer\n");
		ret = -1;
		goto cleanup_fd;
	}

	signal(SIGINT, rst_sig_handler);
	signal(SIGTERM, rst_sig_handler);
	while (running) {
		ret = perf_buffer__poll(pb, 100000); /* timeout 100ms */
		if (ret < 0 && ret != -EINTR) {
			fprintf(stderr, "Polling perf buffer error:%d\n", ret);
			goto cleanup_fd;
		}
	}

cleanup_fd:
	close(filter_map);
cleanup:
	xd_ntrace_bpf_c__destroy(skel);
	return ret;
}
