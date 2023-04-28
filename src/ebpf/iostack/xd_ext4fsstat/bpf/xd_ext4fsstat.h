#ifndef __EXT4_FSSTAT_H__
#define __EXT4_FSSTAT_H__

#ifndef FILENAME_LEN
#define FILENAME_LEN	(56)
#endif

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN	(16)
#endif

#ifndef MAX_EXT4_FILES
#define MAX_EXT4_FILES	(8192)
#endif

enum file_opcode {
	FILE_READ,
	FILE_WRITE,
	FILE_WRITEBACK,
};

struct pid_key {
	__u32 dev;
	__u64 ino;
	__u32 pid;
	__u32 tid;
};

struct pid_iostat {
	__u32 dev;
	__u64 ino;
	__u32 pid;
	__u32 tid;
	__u64 reads;
	__u64 read_bytes;
	__u64 writes;
	__u64 write_bytes;
	__u64 writeback_bytes;
	char comm[TASK_COMM_LEN];
};

struct file_key {
	__u32 dev;
	__u64 ino;
};

struct file_iostat {
	__u64 read_bytes;
	__u64 write_bytes;
	__u64 writeback_bytes;
	char filename[FILENAME_LEN];
	char d1name[FILENAME_LEN];
	char d2name[FILENAME_LEN];
	char d3name[FILENAME_LEN];
};

enum filter_flag {
	FILTER_PID	= 0x1,
	FILTER_DEV	= 0x2,
	FILTER_OPCODE	= 0x4,	
};

struct filter_value {
	__u32 flags;
	__u32 opcode;
	__u32 dev;
	__u32 pid;
};

#endif /* __EXT4_FSSTAT_H__ */
