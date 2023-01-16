#ifndef __XSKINFO_H__
#define __XSKINFO_H__

struct sock_key {
	unsigned int saddr[4];
	unsigned int daddr[4];
	unsigned short sport;
	unsigned short dport;
	unsigned short protocol;
	unsigned short family;
};

struct tcpinfo_xdiag {
	/* struct tcp_sock */
		unsigned int reordering;
	unsigned int window_clamp;
	unsigned int rcv_nxt;
	unsigned int rcv_wup;
	unsigned int rcv_wnd;
	unsigned int rcv_ssthresh;
	unsigned int copied_seq;
	unsigned int snd_nxt;
	unsigned int snd_una;
	unsigned int snd_wnd;
	unsigned int snd_cwnd;
	unsigned int snd_ssthresh;
	unsigned int write_seq;

	/* struct sock */
	int sk_forward_alloc;
	int sk_rcvbuf;
	int sk_sndbuf;
	int sk_wmem_queued;
	int sk_padding;
	
	/* struct inet_connection_sock */
	unsigned short rcv_mss;	//isck->icsk_ack.rcv_mss
};

#endif
