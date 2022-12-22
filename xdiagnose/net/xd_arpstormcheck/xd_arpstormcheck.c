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

#include "xd_arpstormcheck.h"
#include "common_u.h"
#include "xd_arpstormcheck.skel.h"

static int map_fd;
static unsigned int interval_time = 1;
/* arp storm frequency threshold, default 100 times(per second) */
static unsigned int filter_freq = 100;
static unsigned int check_count = 0xffffffff;
static unsigned int running = 1;

static const struct option long_opts[] = {
    { "help", 0, 0, 'h' },
    { "interval", 1, 0, 'i' },
    { "count", 1, 0, 'c' },
    { "freq", 1, 0, 'f' },
    { 0 }
};

static void usage(char *cmd)
{
    printf("Usage: %s [ OPTIONS ]\n"
            "   -h,--help           this message\n"
            "   -i,--interval       The interval time of the probe/s\n"
            "   -c,--count          check count, default 1\n"
            "   -f,--freq           filter freq, $$ times per second\n", cmd);
}

static void xarp_sig_handler(int sig)
{
    switch(sig){
        case SIGALRM:
            break;
        case SIGTERM:
        case SIGINT:
            running = 0;
            break;
        default:
            break;
    }
}

static void xarp_check_show(void)
{
    int ret;
    unsigned int value;
    struct key_xarp key, next_key;

    memset(&key, 0x0, sizeof(struct key_xarp));
    memset(&next_key, 0x0, sizeof(struct key_xarp));
    while(bpf_map_get_next_key(map_fd, &key, &next_key) == 0){
        value = 0;
        ret = bpf_map_lookup_elem(map_fd, &next_key, &value);
        if(ret != 0){
            printf("stack_mapfd: bpf_map_lookup_elem failed\n");
            continue;
        }

        if(value > filter_freq){
            char sip[64];
            char tip[64];
            memset(sip, 0, sizeof(sip));
            memset(tip, 0, sizeof(tip));
            inet_ntop(next_key.family, next_key.sip, sip, sizeof(sip));
            inet_ntop(next_key.family, next_key.tip, tip, sizeof(tip));
            printf("SIP:%s  TIP:%s    Freq:  %d times per SEC\n", sip, tip, value);
        }
        bpf_map_delete_elem(map_fd, &next_key);
        key = next_key;
    }

    if(check_count != 0xffffffff){
        check_count--;
        if(check_count == 0){
            running = 0;
        }
    }
    return;
}

static int xarp_check(void)
{
    struct key_xarp key, next_key;
    struct itimerval itv_new;


    itv_new.it_value.tv_sec = interval_time;
    itv_new.it_value.tv_usec = 0;
    itv_new.it_interval.tv_sec = interval_time;
    itv_new.it_interval.tv_usec = 0;
    signal(SIGALRM, xarp_sig_handler);

    /* clean icmp pkg first */
    memset(&key, 0x0, sizeof(struct key_xarp));
    memset(&next_key, 0x0, sizeof(struct key_xarp));
    while(bpf_map_get_next_key(map_fd, &key, &next_key) == 0){
        bpf_map_delete_elem(map_fd, &next_key);
        key = next_key;
    }

    setitimer(ITIMER_REAL, &itv_new, NULL);
    while(running){
        pause();
        xarp_check_show();
    } 
    
    return 0;
}

int main(int argc, char **argv)
{
    int ch;
    int ret = 0;
    struct xd_arpstormcheck_bpf *skel;

    while ((ch = getopt_long(argc, argv, "hc:f:i:", long_opts, NULL)) != -1) {
        switch (ch) {
        case 'c':
            check_count = atoi(optarg);
            break;
        case 'i':
            interval_time = atoi(optarg);
            break;
        case 'f':
            filter_freq = atoi(optarg);
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

    skel = xd_arpstormcheck_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        ret = -1;
        goto cleanup;
    }   

    /* Attach tracepoint */
    ret = xd_arpstormcheck_bpf__attach(skel);
    if (ret) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        ret = -1;
        goto cleanup;
    }

    map_fd = bpf_map__fd(skel->maps.arpcheck_map);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get BPF map fd\n");
        ret = -1;
        goto cleanup;
    }
    
    xarp_check();

cleanup:
    xd_arpstormcheck_bpf__destroy(skel);
    return ret;
}

