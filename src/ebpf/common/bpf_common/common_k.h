#ifndef __COMMON_K_H__
#define __COMMON_K_H__

#include "vmlinux.h"

#ifndef NULL
#define NULL (void *)0
#endif

#define BPF_PROBE_VAL(P) \
    ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})

#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))

#define sk_dontcopy_begin       __sk_common.skc_dontcopy_begin
#define sk_dontcopy_end         __sk_common.skc_dontcopy_end
#define sk_hash                 __sk_common.skc_hash
#define sk_portpair             __sk_common.skc_portpair
#define sk_num                  __sk_common.skc_num
#define sk_dport                __sk_common.skc_dport
#define sk_addrpair             __sk_common.skc_addrpair
#define sk_daddr                __sk_common.skc_daddr
#define sk_rcv_saddr            __sk_common.skc_rcv_saddr
#define sk_family               __sk_common.skc_family
#define sk_state                __sk_common.skc_state
#define sk_reuse                __sk_common.skc_reuse
#define sk_reuseport            __sk_common.skc_reuseport
#define sk_ipv6only             __sk_common.skc_ipv6only
#define sk_net_refcnt           __sk_common.skc_net_refcnt
#define sk_bound_dev_if         __sk_common.skc_bound_dev_if
#define sk_bind_node            __sk_common.skc_bind_node
#define sk_prot                 __sk_common.skc_prot
#define sk_net                  __sk_common.skc_net
#define sk_v6_daddr             __sk_common.skc_v6_daddr
#define sk_v6_rcv_saddr __sk_common.skc_v6_rcv_saddr
#define sk_cookie               __sk_common.skc_cookie
#define sk_incoming_cpu         __sk_common.skc_incoming_cpu
#define sk_flags                __sk_common.skc_flags
#define sk_rxhash               __sk_common.skc_rxhash

#define inet_daddr		sk.__sk_common.skc_daddr
#define inet_rcv_saddr		sk.__sk_common.skc_rcv_saddr
#define inet_dport		sk.__sk_common.skc_dport
#define inet_num		sk.__sk_common.skc_num

#define s6_addr			in6_u.u6_addr8
#define s6_addr16		in6_u.u6_addr16
#define s6_addr32		in6_u.u6_addr32

/* Supported address families. */
#define AF_UNSPEC   0
#define AF_UNIX     1 /* Unix domain sockets    */
#define AF_LOCAL    1 /* POSIX name for AF_UNIX */
#define AF_INET     2 /* Internet IP Protocol   */
#define AF_AX25     3 /* Amateur Radio AX.25    */
#define AF_IPX      4 /* Novell IPX             */
#define AF_APPLETALK    5 /* AppleTalk DDP      */
#define AF_NETROM   6 /* Amateur Radio NET/ROM  */
#define AF_BRIDGE   7 /* Multiprotocol bridge   */
#define AF_ATMPVC   8 /* ATM PVCs               */
#define AF_X25      9 /* Reserved for X.25 project  */
#define AF_INET6    10 /* IP version 6          */

#endif
