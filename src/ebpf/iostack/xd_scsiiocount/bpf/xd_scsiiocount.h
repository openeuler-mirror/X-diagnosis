#ifndef __SCSIO_COUNT_H__
#define __SCSIO_COUNT_H__

struct sdev_hctl {
	unsigned int host;
        unsigned int channel;
        unsigned int id;
        unsigned int lun;
};

struct scsi_key {
	struct sdev_hctl hctl;
	unsigned int opcode;
};

#endif  /* __SCSIO_COUNT_H__ */
