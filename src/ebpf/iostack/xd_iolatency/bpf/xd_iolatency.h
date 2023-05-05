#ifndef __IO_LATENCY_H__
#define __IO_LATENCY_H__

#define MAX_ITEMS  		(23)
#define MAX_DEVICES_LIMIT	(128)

enum issue_flags {
	ISSUE_Q2G = 1,
	ISSUE_Q2M,
	ISSUE_G2M,
	ISSUE_G2I,
	ISSUE_I2D,
	ISSUE_D2C,
	ISSUE_MAX,
};

struct iolatency_key {
	__u32 dev;
};

struct issue_stat {
	__u64 total_ts;
	__u64 count;
};

struct iolatency_value {
	__u32 dev;
	struct issue_stat issue[ISSUE_MAX];
};

struct iolatency_issue_value {
	__u32 dev;
	__u64 min;
	__u64 max;
	__u64 count;
	__u64 total_ts;
	__u32 issue;
	__u32 item[MAX_ITEMS];
};

struct feature_key {
	__u32 enable;
};

enum feature_flags {
	FILTER_DEV = 0x1,
	FILTER_ISSUE = 0x2,
	REPORT_MS = 0x4,
};

struct feature_value {
	__u32 flag;
	__u32 filter_dev;
	__u32 filter_issue;
};

#endif /* __IO_LATENCY_H__ */
