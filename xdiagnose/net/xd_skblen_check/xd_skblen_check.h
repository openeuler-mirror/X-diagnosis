#ifndef __XSKBLEN_H__
#define __XSKBLEN_H__

#define MACLEN 6

struct skb_ethhdr {
    unsigned char saddr[MACLEN];
    unsigned char daddr[MACLEN];
    unsigned short proto;
};

struct skb_diag {
    struct skb_ethhdr ethhdr;
    int skblen;
    int datalen;
};

#endif
