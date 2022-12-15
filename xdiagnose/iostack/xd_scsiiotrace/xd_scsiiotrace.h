#ifndef __SCSIIO_TRACE_H__
#define __SCSIIO_TRACE_H__ 

#ifndef BPF_F_CURRENT_CPU
#define BPF_F_CURRENT_CPU	(0xffffffffULL)
#endif

#define CDB_MAX_LEN		(32)

struct scsi_sdev {
        unsigned int host;
        unsigned int channel;
        unsigned int id;
        unsigned long lun;
};

struct event {
	struct scsi_sdev sdev;
	unsigned int scsi_result;
	unsigned int driver_result;
	unsigned int disposition;
	char cdb[CDB_MAX_LEN];
	unsigned int cdb_len;
};

#endif /* __SCSIIO_TRACE_H__ */
