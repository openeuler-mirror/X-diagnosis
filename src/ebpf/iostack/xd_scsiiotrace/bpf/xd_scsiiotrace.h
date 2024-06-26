#ifndef __SCSIIO_TRACE_H__
#define __SCSIIO_TRACE_H__ 

#ifndef BPF_F_CURRENT_CPU
#define BPF_F_CURRENT_CPU	(0xffffffffULL)
#endif

#define CDB_MAX_LEN		(32)

#define SCSI_MLQUEUE_HOST_BUSY   0x1055
#define SCSI_MLQUEUE_DEVICE_BUSY 0x1056
#define SCSI_MLQUEUE_EH_BUSY     0x1057
#define SCSI_MLQUEUE_TARGET_BUSY 0x1058

#define SCSI_NEEDS_RETRY         0x2001
#define SCSI_SUCCESS             0x2002
#define SCSI_FAILED              0x2003
#define SCSI_QUEUED              0x2004
#define SCSI_SOFT_ERROR          0x2005
#define SCSI_ADD_TO_MLQUEUE      0x2006
#define SCSI_TIMEOUT_ERROR       0x2007
#define SCSI_RETURN_NOT_HANDLED  0x2008
#define SCSI_FAST_IO_FAIL        0x2009

enum ioevent {
	IO_START = 0,
	IO_DONE,
	IO_ERROR,
	IO_TIMEOUT,
};

#define FILTER_OPCODE		0x1
#define FILTER_RESULT		0x2

struct filter_rule {
	int flag;
	int opcode;
};

struct scsi_sdev {
	__u32 host;
	__u32 channel;
	__u32 id;
	__u32 lun;
};

struct event {
	struct scsi_sdev sdev;
	__u32 opcode;
	__u32 cpuid;
	__u64 ioseq;
	__u32 ioevent;
	__u32 rtn;
	__u32 result;
	__u64 timestamp;
	char cdb[CDB_MAX_LEN];
	unsigned int cdb_len;
};

#endif /* __SCSIIO_TRACE_H__ */
