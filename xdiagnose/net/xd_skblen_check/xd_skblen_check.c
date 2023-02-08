#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/time.h>
#include <signal.h>
#include <arpa/inet.h>

/*for bpf*/
#include <linux/bpf.h>
#include <bpf/bpf.h>
/* bpf end */

#include "xd_skblen_check.h"
#include "common_u.h"
#include "xd_skblen_check.skel.h"

static unsigned int running = 1;
static int map_fd;
static int interval_time = 3;

static const struct option long_opts[] = {
    { "help", 0, 0, 'h'},
    { 0 }
};

static void usage(char *cmd)
{
    printf("Usage: xd_skblen_check [ OPTIONS ]\n"
              "    -h,--help           this message\n");
}

static void rst_sig_handler(int sig)
{
   running = 0;
}

static void skblen_check(void) {
    unsigned long key = 0;
    unsigned long next_key = 0;
    struct skb_diag skb_diag;

    memset(&skb_diag, 0, sizeof(skb_diag));
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        bpf_map_lookup_elem(map_fd, &next_key, &skb_diag);
	printf("%02x:%02x:%02x:%02x:%02x:%02x    %02x:%02x:%02x:%02x:%02x:%02x    0x%-5x    %-5u     %u\n",
	               skb_diag.ethhdr.saddr[0],
		       skb_diag.ethhdr.saddr[1],
		       skb_diag.ethhdr.saddr[2],
		       skb_diag.ethhdr.saddr[3],
		       skb_diag.ethhdr.saddr[4],
		       skb_diag.ethhdr.saddr[5],
		       skb_diag.ethhdr.daddr[0],
		       skb_diag.ethhdr.daddr[1],
		       skb_diag.ethhdr.daddr[2],
		       skb_diag.ethhdr.daddr[3],
		       skb_diag.ethhdr.daddr[4],
		       skb_diag.ethhdr.daddr[5],
		       ntohs(skb_diag.ethhdr.proto),
		       skb_diag.skblen,
		       skb_diag.datalen);
        bpf_map_delete_elem(map_fd, &next_key);
	key = next_key;
    }
}
    
int main(int argc, char **argv)
{
    int ch;
    int ret = 0;
    struct xd_skblen_check_bpf *skel;

    while ((ch = getopt_long(argc, argv, "h", long_opts, NULL)) != -1) {
        switch (ch) {
	    case 'h':
	        usage(argv[0]);
		return ret;
	    default:
	        printf("invalid argument\n");
		return -1;
	}
    }

    memlock_rlimit();

    skel = xd_skblen_check_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
	return -1;
    }

    /* Attach tracpoint */
    ret = xd_skblen_check_bpf__attach(skel);
    if (ret) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
	ret = -1;
	goto cleanup;
    }

    map_fd = bpf_map__fd(skel->maps.skbdiag_map);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get BPF map fd\n");
	ret = -1;
	goto cleanup;
    }

    signal(SIGINT, rst_sig_handler);
    signal(SIGTERM, rst_sig_handler);

    printf("hw_saddr             hw_daddr             proto      len       datalen\n"); 
    while (running) {
        skblen_check();
	sleep(interval_time);
    } 

    close(map_fd);
cleanup:
    xd_skblen_check_bpf__destroy(skel);
    return ret;
}
