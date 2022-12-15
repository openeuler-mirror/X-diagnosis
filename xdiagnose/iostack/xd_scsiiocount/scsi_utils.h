#ifndef __SCSI_UTILS_H__
#define __SCSI_UTILS_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <argp.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>

#ifndef SDEV_PATH_LEN
#define SDEV_PATH_LEN   (1024)
#endif

#ifndef SYSFS_PATH_SDEV	
#define SYSFS_PATH_SDEV   (128)
#endif

#ifndef SDEV_NAME_LEN
#define SDEV_NAME_LEN	(16)
#endif

#define MAX_SDEV_DEVICE	(64)

struct scsi_hctl {
	int host;
	int channel;
	int id;
	uint64_t lun;
	char name[SDEV_NAME_LEN];
};

struct sdev_list {
    int max_num;
    struct scsi_hctl sdev[MAX_SDEV_DEVICE];
};

static const char * sysfs_scsi_device = "/sys/class/scsi_device";
static char sdev_name[SDEV_NAME_LEN];

static int cmp_scsi_hctl(const struct scsi_hctl *a,
         	    	 const struct scsi_hctl *b)
{
	int res;

	if (a->host == b->host) {
        	if (a->channel == b->channel) {
			if (a->id == b->id)
				res = ((a->lun == b->lun) ? 0 : 
				      ((a->lun < b->lun) ? -1 : 1));
			else
				res = (a->id < b->id) ? -1 : 1;
		} else
			res = (a->channel < b->channel) ? -1 : 1;

		return res;
        }

	return (a->host < b->host) ? -1 : 1;
}

static bool utils_get_sdev_hctl(const char *dirname,
                                struct scsi_hctl * out)
{
 	if (sscanf(dirname, "%d:%d:%d:%ld", &out->host, &out->channel,
		   &out->id, &out->lun) != 4)
		return false;

	return true;
}

static int sysfs_sdev_block_dir_scan(const struct dirent * s)
{
	if (!strncmp(s->d_name, ".", 1) ||
	    !strncmp(s->d_name, "..", 2))
		return 0;
	
	strcpy(sdev_name, s->d_name);

	return 1;
}

static int sysfs_sdev_block_scan(const char * dir_name)
{
	int num, i;
	struct dirent **dirlist;

	num = scandir(dir_name, &dirlist, sysfs_sdev_block_dir_scan, NULL);
	if (num < 0)
		return -1;

	for (i = 0; i < num; ++i)
		free(dirlist[i]);
	free(dirlist);

        return num;
}

static void get_one_sdev_name(const char * dirname,
                              const char * devname,
                              struct scsi_hctl *sdev)
{
	char buff[SDEV_PATH_LEN];

	snprintf(buff, SDEV_PATH_LEN, "%s/%s/device/block", dirname, devname);
	if (sysfs_sdev_block_scan(buff) != 1)
			return;

	snprintf(sdev->name, sizeof(sdev->name), "%s", sdev_name);
	utils_get_sdev_hctl(devname, sdev);
}

static int scsi_hctl_sort(const struct dirent ** a,
                          const struct dirent ** b)
{
	struct scsi_hctl l;
	struct scsi_hctl r;

	const char * aname = (*a)->d_name;
	const char * bname = (*b)->d_name;

        if (!utils_get_sdev_hctl(aname, &l))
                return -1;

        if (!utils_get_sdev_hctl(bname, &r))
                return 1;

        return cmp_scsi_hctl(&l, &r);
}

static int sysfs_sdev_dir_scan(const struct dirent * s)
{
	struct scsi_hctl hctl;

	if (!strchr(s->d_name, ':'))
		return 0;

	if (!utils_get_sdev_hctl(s->d_name, &hctl))
		return 0;
	else
		return 1;
}

static int scan_sdevs(struct sdev_list *list)
{
        struct dirent **dirlist;
        char buff[SYSFS_PATH_SDEV];
        int num, i;

        snprintf(buff, sizeof(buff), "%s", sysfs_scsi_device);
        num = scandir(buff, &dirlist, sysfs_sdev_dir_scan,
					  scsi_hctl_sort);
        if (num < 0)
                return -1;

        list->max_num = num;
        for (i = 0; i < num; ++i) {
                get_one_sdev_name(buff, dirlist[i]->d_name, &list->sdev[i]);
                free(dirlist[i]);
        }
        free(dirlist);

        return 0;
}

#endif  /* __SCSI_UTILS_H__ */
