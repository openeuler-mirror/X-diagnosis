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

#include <linux/netlink.h>
#include <linux/inet_diag.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
/* for bpf*/
#include <linux/bpf.h>
#include <bpf/bpf.h>
/*  bpf end */

#include "xd_tcpskinfo.h"
#include "common_u.h"
#include "xd_tcpskinfo.skel.h"

#define PR_MEMBER_SIZE 64
#define PR_OUT_BUFSIZE (PR_MEMBER_SIZE * 128)
#define FILENAME_SIZE 256
#define RECV_BUFSIZE (8*1024)

struct sk_req {
    struct nlmsghdr nlh;
    struct inet_diag_req r;
};

struct sk_bit_userlocks{
    unsigned int     sk_padding : 1,
                     sk_kern_sock : 1,
                     sk_no_check_tx : 1,
                     sk_no_check_rx : 1,
                     sk_userlocks : 4,
                     sk_protocol  : 8,
                     sk_type      : 16;
} sk_bit;

static const struct option long_opts[] = {
    { "help", 0, 0, 'h' },
    { "addr", 1, 0, 'a' },
    { "port", 1, 0, 'p' },
    { 0 }
};

struct tcp_conn_stat{
    __u8 idiag_family;
    char *family_name;
};

struct tcp_conn_stat tcp_stat[] = {
    { TCP_ESTABLISHED, "ESTABLISHED" },
    { TCP_SYN_SENT, "SYN_SENT" },
    { TCP_SYN_RECV, "SYN_RECV" },
    { TCP_FIN_WAIT1, "FIN_WAIT1" },
    { TCP_FIN_WAIT2, "FIN_WAIT2" },
    { TCP_TIME_WAIT, "TIME_WAIT" },
    { TCP_CLOSE, "CLOSE" },
    { TCP_CLOSE_WAIT, "CLOSE_WAIT" },
    { TCP_LAST_ACK, "LAST_ACK" },
    { TCP_LISTEN, "LISTEN" },
    { TCP_CLOSING, "CLOSING" },
#define TCP_UNKNOWN_STATE  128
    { TCP_UNKNOWN_STATE, "UNKNOWN_STATE" }
};

struct pr_buffer {
    unsigned int len;
    char *data;
} buffer;

/* for filter */
static short is_port_filter;
static short filter_port;
static short is_addr_filter;
static int filter_addr[4];

/* bpf fd*/
static int map_fd;


static int bind_sock_netlink(int fd)
{
    struct sockaddr_nl src_addr;
    memset(&src_addr, 0, sizeof(struct sockaddr_nl));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();
    src_addr.nl_groups = 0;

    return bind(fd, (struct sockaddr *)&src_addr, 
            sizeof(struct sockaddr_nl));
}

static int outbuf(const char *fmt, ...)
{
    int ret;
    va_list args;
    char *buf;

    if (!buffer.data)
        return -1;

    buf = buffer.data + buffer.len;
    va_start(args, fmt);
    ret = vsnprintf(buf, PR_OUT_BUFSIZE - buffer.len, fmt, args);
    va_end(args);
    buffer.len += ret;
    return 0;
}

static int init_buffer(void)
{
    buffer.len = 0;
    memset(buffer.data, 0x0, PR_OUT_BUFSIZE);
    return 0;
}

static int print_buffer(void)
{
    buffer.len = 0;
    printf("%s", buffer.data);
    return 0;
}

static int pr_buffer_init(void)
{
    buffer.len = 0;
    buffer.data = malloc(PR_OUT_BUFSIZE);
    if(!buffer.data){
        printf("pr_buffer_init, malloc failed!\n");
        exit(-1);
    }
    return 0;
}

static int pr_buffer_exit(void)
{
    free(buffer.data);
    return 0;
}

static char *parse_tcp_stat(const int state)
{
    int i;
    for (i = 0; i < (sizeof(tcp_stat)/sizeof(tcp_stat[0]) - 1); i++){
        if (tcp_stat[i].idiag_family == state){
            return tcp_stat[i].family_name;
        }
    }

    return tcp_stat[i].family_name; 
}


static int print_sockmem(struct rtattr *rtas[], int attrtype)
{
    unsigned int *sockmem;

    if(!rtas[attrtype]){
        printf("attrtype: %d, data is NULL\n", attrtype);
        return -1;
    }

    sockmem = RTA_DATA(rtas[attrtype]);
    outbuf("skmem:(rmem_alloc=%u,rbuff=%u,wmem_alloc=%u,wbuff=%u,fwd_alloc=%u,", 
            sockmem[SK_MEMINFO_RMEM_ALLOC],
            sockmem[SK_MEMINFO_RCVBUF],
            sockmem[SK_MEMINFO_WMEM_ALLOC],
            sockmem[SK_MEMINFO_SNDBUF],
            sockmem[SK_MEMINFO_FWD_ALLOC]);
    outbuf("wmemq=%u,optmem=%u,backlog=%u,drops=%u)",    
            sockmem[SK_MEMINFO_WMEM_QUEUED],
            sockmem[SK_MEMINFO_OPTMEM],
            sockmem[SK_MEMINFO_BACKLOG],
            sockmem[SK_MEMINFO_DROPS]);

    return 0;
}

static int nl_tcpinfo_show(struct nlmsghdr *nlh, struct rtattr *rtas[])
{
    struct tcp_info *info;

    print_sockmem(rtas, INET_DIAG_SKMEMINFO);

    if (rtas[INET_DIAG_INFO]){
        info = RTA_DATA(rtas[INET_DIAG_INFO]);
        outbuf(" tcp_ca_state:%u", info->tcpi_ca_state);
    }

    return 0;
}

static int nl_rtattr_parse(struct rtattr *rtas[], int max, struct rtattr *rta_head, 
        int len)
{
    struct rtattr *rta = rta_head;
    while(RTA_OK(rta, len)){
        if(rta->rta_type)
            rtas[rta->rta_type] = rta;
        rta = RTA_NEXT(rta, len);
    }
    if(len){
        printf("len is error: %d, rtalen: %d\n", len, rta->rta_len);
        return -1;
    }
    return 0;
}

static int nl_rattr_show(struct nlmsghdr *nlh)
{
    struct rtattr *rtas[INET_DIAG_MAX+1];
    struct inet_diag_msg *msg = NLMSG_DATA(nlh);
    
    memset(rtas, 0, sizeof(rtas));
    nl_rtattr_parse(rtas, INET_DIAG_MAX, (struct rtattr *)(msg+1), 
            nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*msg)));

    nl_tcpinfo_show(nlh, rtas);

    return 0;
}

static int bpf_tcpinfo_show(struct inet_diag_msg *pkg)
{
    int ret;
    struct sock_key key;
    struct tcpinfo_xdiag diaginfo;

    /* Ensure that the key is the same as the kernel key. */
    memset(&key, 0x0, sizeof(struct sock_key));
    key.sport = pkg->id.idiag_sport;
    key.dport = pkg->id.idiag_dport;
    key.protocol = 0;
    key.family = pkg->idiag_family;
    if(key.family == AF_INET){
        key.saddr[0] = pkg->id.idiag_src[0];
        key.daddr[0] = pkg->id.idiag_dst[0];
    } else if (key.family == AF_INET6){
        memcpy(key.saddr, pkg->id.idiag_src, sizeof(key.saddr));
    }

    ret = bpf_map_lookup_elem(map_fd, &key, &diaginfo);
    if(ret == 0){
        outbuf(" reordering:%u", diaginfo.reordering);
        outbuf(" window_clamp:%u", diaginfo.window_clamp);
        outbuf(" rcv_nxt:%u,", diaginfo.rcv_nxt);
        outbuf(" rcv_wup:%u,", diaginfo.rcv_wup);
        outbuf(" rcv_wnd:%u,", diaginfo.rcv_wnd);
        outbuf(" rcv_ssthresh:%u,", diaginfo.rcv_ssthresh);
        outbuf(" copied_seq:%u,", diaginfo.copied_seq);
        outbuf(" snd_nxt:%u,", diaginfo.snd_nxt);
        outbuf(" snd_una:%u", diaginfo.snd_una);
        outbuf(" snd_wnd:%u", diaginfo.snd_wnd);
        outbuf(" snd_cwnd:%u", diaginfo.snd_cwnd);
        outbuf(" snd_ssthresh:%u", diaginfo.snd_ssthresh);
        outbuf(" write_seq:%u,", diaginfo.write_seq);
        /* struct sock */
        outbuf(" sk_forward_alloc:%d,", diaginfo.sk_forward_alloc);
        outbuf(" sk_rcvbuf:%d,", diaginfo.sk_rcvbuf);
        outbuf(" sk_sndbuf:%d,", diaginfo.sk_sndbuf);
        outbuf(" sk_wmem_queued:%d,", diaginfo.sk_wmem_queued);
        memcpy(&sk_bit, &diaginfo.sk_padding, sizeof(sk_bit));
        outbuf(" sk_userlocks:%d", sk_bit.sk_userlocks);
        /* struct inet_connection_sock */
        outbuf(" rcv_mss:%d", diaginfo.rcv_mss);
    }

    return 0;
}

static int nl_msg_parse(char *buf, int status)
{
    struct nlmsghdr *nlh;

    nlh = (struct nlmsghdr *)buf;
    while (NLMSG_OK(nlh, status)){
        if(nlh->nlmsg_type == NLMSG_DONE){
            break;
        }

        if(nlh->nlmsg_type == NLMSG_ERROR){
            struct nlmsgerr *err;
            err = (struct nlmsgerr *)NLMSG_DATA(nlh);
            fprintf(stderr, "%d Error %d:%s\n", __LINE__, \
                    -(err->error), strerror(-(err->error)));
            return -1;
        }
        struct inet_diag_msg *pkg = (struct inet_diag_msg *)NLMSG_DATA(nlh);
        char src_ip[64];
        char dest_ip[64];
        memset(src_ip, 0, sizeof(src_ip));
        memset(dest_ip, 0, sizeof(dest_ip));
        inet_ntop(pkg->idiag_family, pkg->id.idiag_src, src_ip, sizeof(src_ip));
        inet_ntop(pkg->idiag_family, pkg->id.idiag_dst, dest_ip, sizeof(dest_ip));

        if(is_addr_filter){
            if(memcmp(pkg->id.idiag_src, filter_addr, sizeof(filter_addr))
                && memcmp(pkg->id.idiag_dst, filter_addr, sizeof(filter_addr))){
                nlh = NLMSG_NEXT(nlh, status);
                continue;
            }
        }

        if(is_port_filter){
            if(filter_port != ntohs(pkg->id.idiag_sport) 
                && filter_port != ntohs(pkg->id.idiag_dport)){
                nlh = NLMSG_NEXT(nlh, status);
                continue;
            }
        }

        init_buffer();
        printf("------(%s  %s:%u  %s:%u  %s  ino:%u)",\
            pkg->idiag_family == AF_INET ? "AF_INET" : "AF_INET6",
            src_ip, ntohs(pkg->id.idiag_sport),
            dest_ip, ntohs(pkg->id.idiag_dport),
            parse_tcp_stat(pkg->idiag_state),
            pkg->idiag_inode);

        outbuf("  <- ");
        nl_rattr_show(nlh);
        bpf_tcpinfo_show(pkg);
        outbuf(" ->\n");
        print_buffer();

        nlh = NLMSG_NEXT(nlh, status);
    }
    return 0;
}

static int nl_tcp_sendmsg(int fd)
{
    struct sockaddr_nl src_addr;
    struct sk_req req;
    struct iovec iov;
    struct msghdr msg;

    memset(&src_addr, 0, sizeof(struct sockaddr_nl));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = 0;
    src_addr.nl_groups = 0;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = TCPDIAG_GETSOCK;
    req.nlh.nlmsg_flags = NLM_F_MATCH | NLM_F_REQUEST | NLM_F_ROOT;
    req.nlh.nlmsg_pid = 0;

    memset(&req.r, 0, sizeof(req.r));
    req.r.idiag_family = AF_INET;
    req.r.idiag_states = ((1 << (TCP_CLOSING + 1)) - 1);

    /*show socket memory*/
    req.r.idiag_ext |= (1 << (INET_DIAG_MEMINFO - 1));
    req.r.idiag_ext |= (1 << (INET_DIAG_SKMEMINFO - 1));

    /* show tcpinfo */
    req.r.idiag_ext |= (1 << (INET_DIAG_INFO - 1));
    req.r.idiag_ext |= (1 << (INET_DIAG_VEGASINFO - 1));
    req.r.idiag_ext |= (1 << (INET_DIAG_CONG-1));

    iov.iov_base = &req;
    iov.iov_len = sizeof(req);

    memset(&msg, 0, sizeof(struct msghdr));
    msg.msg_name = (void *)&src_addr;
    msg.msg_namelen = sizeof(src_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if (sendmsg(fd, &msg, 0) < 0){
        printf("netlink sendmsg failed\n");
        return -1;
    }

    return 0;
}

static int netlink_recvmsg(int fd)
{
    int ret;
    char buf[RECV_BUFSIZE];
    struct iovec iov;
    struct sockaddr_nl src_addr;
    struct msghdr msg;

    memset(&src_addr, 0, sizeof(struct sockaddr_nl));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = 0;
    src_addr.nl_groups = 0;

    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);

    while(1){
        memset(&msg, 0, sizeof(struct msghdr));
        msg.msg_name = (void *)&src_addr;
        msg.msg_namelen = sizeof(src_addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        ret = recvmsg(fd, &msg, 0);
        if(ret < 0){
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN)
                break;
            printf("netlink recvmsg failed: %s\n", strerror(errno));
            return -1;
        }

        if(ret == 0)
            break;

        nl_msg_parse(buf, ret);
        usleep(100);
    }

    return 0;
}


static int show_socket_info(void)
{
    int fd;

    if((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG)) < 0){
        printf("socket failed\n");
        return -1;
    }

    if((fcntl(fd, F_SETFL, O_NONBLOCK)) < 0){
        printf("fcntl failed\n");
        close(fd);
        return -1;
    }

    if(bind_sock_netlink(fd) < 0){
        printf("netlink bind failed\n");
        close(fd);
        return -1;
    }

    if(nl_tcp_sendmsg(fd) < 0){
        printf("nl_tcp_sendmsg failed\n");
        close(fd);
        return -1;
    }

    if(netlink_recvmsg(fd) < 0){
        printf("netlink_recvmsg failed\n");
        close(fd);
        return -1;
    }

    close(fd);

    return 0;
}

static int auto_inet_pton(char *optarg, char *ipbuf)
{
    int ret;
    if(!ipbuf || !optarg)
        return -1;
    if(strstr(optarg, ".")){
        ret = inet_pton(AF_INET, optarg, ipbuf);
    } else if (strstr(optarg, ":")){
        ret = inet_pton(AF_INET6, optarg, ipbuf);
    } else {
        return -1;
    }
    return ret;
}

static void usage(char *cmd)
{
    printf("Usage: xd_tcpskinfo [ OPTIONS ]\n"
            "   -h,--help           this message\n"
            "   -a,--addr           filter IP addr\n"
            "   -p,--port           filter port\n");
}

int main(int argc, char **argv)
{
    int ret = 0;
    int ch;
    struct xd_tcpskinfo_bpf *skel;
    int err;

    memset((void *)filter_addr, 0xff, sizeof(filter_addr));

    while((ch = getopt_long(argc, argv, "ha:p:", long_opts, NULL)) != -1){
        switch (ch) {
        case 'a':
            is_addr_filter = 1;
            memset((void *)filter_addr, 0x0, sizeof(filter_addr));
            ret = auto_inet_pton(optarg, (char *)filter_addr);
            if(ret <= 0){
                printf("error IP type!\n");
                return -1;
            }
            break;
        case 'p':
            is_port_filter = 1;
            filter_port = (unsigned short)atoi(optarg);
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

    skel = xd_tcpskinfo_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* Attach tracepoint */
    err = xd_tcpskinfo_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        ret = -1;
        goto cleanup;
    }

    map_fd = bpf_map__fd(skel->maps.tcpinfo_map);
    if (map_fd < 0){
        fprintf(stderr, "Failed to open map fd\n");
        ret = -1;
        goto cleanup;
    }

    pr_buffer_init();
    show_socket_info();
    pr_buffer_exit();

cleanup:
    xd_tcpskinfo_bpf__destroy(skel);
    return ret;
}

