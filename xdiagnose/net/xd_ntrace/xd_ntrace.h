#ifndef __XD_NTRACE_H__
#define __XD_NTRACE_H__

#define IFNAMSIZ    16
#define IP_LEN 4
struct ntrace_put_user_info {
    bool pfmemalloc;
    char indev_name[IFNAMSIZ];
    char outdev_name[IFNAMSIZ];
    __be32 saddr[IP_LEN];
    __be32 daddr[IP_LEN];
    __be16 sport;
    __be16 dport;
    int stage;
    unsigned long ts;
    unsigned short icmp_type;
    unsigned short queue;
    unsigned short icmp_seq;
    unsigned int tc_drop;
    unsigned int cpuid;
};

struct ntrace_filter_info {
    __be32 hostaddr[IP_LEN];
    __be16 hostport;
    __be16 protocol;
    __be16 family;
};

struct ntrace_tp_net_args{
    unsigned int reserve[2];
    struct sk_buff *skbaddr;
};

/* 通过下面的五元组确定是同一条流 */
struct ntrace_proto_tuple {
    __be32 saddr[4];
    __be32 daddr[4];
    __be16 sport;
    __be16 dport;
    __be16 protocol;
};

struct icmp_flow_key {
    unsigned short icmp_id;
};

struct ntrace_flow_keys {
    union {
        struct ntrace_proto_tuple tp;
        struct icmp_flow_key icmp_key;
    } key;
};

enum icmp_flow_mode {
    ICMP_ACTIVE = 1,    // 主动模式，触发ping
    ICMP_PASSIVE,       // 被动模式， 接收ping消息
    ICMP_MAX,
};

enum net_stack_stage {
    NET_SKB_RCV = 1,
    NET_IP_RCV_CORE,// disable_ipv6检查是否关闭，或者prerouting检查失败
    NET_IP_ROUTE_INPUT, // 检查路由是否查询失败
    NET_IP_INPUT, // local in的iptables钩子丢包
    NET_IP_INPUT_FINISH, // 是存在聚合失败
    NET_ICMP_RCV,// 此处可能是icmpv6_echo_ignore_all配置了.出方向无效
    NET_ICMP_RCV_EXT,// icmpv6的校验失败
    NET_ICMP_REPLAY,// 此处可能是路由失败查询了
    NET_IP_LOCAL_OUTPUT,// output的iptables失败
    NET_IP_OUTPUT, // 检查disable_ipv6配置和iptables 的posttrouting
    NET_IP_FINISH_OUTPUT,// 分片报文toobig,
    NET_IP_FINISH_OUTPUT2,// neigh查询失败
    NET_DEV_QUEUE_XMIT, // 检查是不是vlan或者bond，如果是那就直接显示在哪一层丢了，如果是带queue的
    NET_DEV_SCH_DIR_XMIT, // 检查queue_stat状态是否有异常,
    NET_DEV_START_XMIT, // end recv
    NET_RAW_SENDMSG, // start xmit，出口路由查询失败
    NET_PING_RCV_SKB, // end xmit
    NET_RCV_OVERFLOW, // 接收队列满
    NET_SND_OVERFLOW, // 发送队列满
    NET_MAX,
};
#endif
