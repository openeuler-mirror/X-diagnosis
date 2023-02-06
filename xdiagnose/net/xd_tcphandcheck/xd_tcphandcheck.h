enum xd_pro_type {
	__INET_BIND = 0,
	SOCKET_CREATE,
	TCP_V4_SYN_RECV_SOCK,
	TCP_TIMEWAIT_STATE_PROCESS,
	TCP_IN_WINDOW,
	UNKOWN
};

struct hook_key {
	unsigned int cpu;
	enum xd_pro_type func_type;
};

struct inet_bind_args {
	unsigned short port;
	unsigned int addr;
};

struct xd_addr_info {
	unsigned long srcaddr;
	unsigned long dstaddr;
	unsigned short srcport;
	unsigned short dstport;
};

struct tw_process_ret {
	struct xd_addr_info addr_info;
	int retval;
};

struct xd_kern_msg {
	struct xd_addr_info addr_info;
	enum xd_pro_type msg_type;
	int retval;
};

#define SUCCESS 0x0

#define XD_TCPHDR_LENGTH 20
