// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * xd_scsiiocount: Report scsi cmnd IO count for scsi device
 *
 * Copyright (C) 2022 Huawei Inc.
 *
 * History:
 *  	5-Aug-2022 Wu Bo <wubo40@huawei.com> created.
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <argp.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "xd_scsiiocount.skel.h"
#include "scsi_proto.h"
#include "scsi_utils.h"
#include "xd_scsiiocount.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

struct disk_info {
	int filter;
	struct scsi_hctl filter_sdev;
	struct sdev_list *sdev_list;
	long disk[MAX_SDEV_DEVICE][ATA_12 + 1];
};

struct scsi_opcode_desc {
	int opcode;
	char name[32];
	char show;
	char format;
} scsi_opcode_array[] = {
	[TEST_UNIT_READY] 	= {TEST_UNIT_READY, "TEST_UNIT_READY", 1, 16},
	[REZERO_UNIT] 		= {REZERO_UNIT, "REZERO_UNIT", 0, 12},
	[REQUEST_SENSE]	 	= {REQUEST_SENSE, "REQUEST_SENSE", 0, 14},
	[FORMAT_UNIT] 		= {FORMAT_UNIT, "FORMAT_UNIT", 0},
	[READ_BLOCK_LIMITS]	= {READ_BLOCK_LIMITS, "READ_BLOCK_LIMITS", 0},
	[REASSIGN_BLOCKS]	= {REASSIGN_BLOCKS, "REASSIGN_BLOCKS", 0},
	[INITIALIZE_ELEMENT_STATUS] = {INITIALIZE_ELEMENT_STATUS, "INITIALIZE_ELEMENT_STATUS", 0},
	[READ_6]		= {READ_6, "READ_6", 1, 6},
	[WRITE_6]		= {WRITE_6, "WRITE_6", 1, 8},
	[SEEK_6]		= {SEEK_6, "SEEK_6", 1, 6},
	[READ_REVERSE]		= {READ_REVERSE, "READ_REVERSE", 0},
	[WRITE_FILEMARKS]	= {WRITE_FILEMARKS, "WRITE_FILEMARKS", 0},
	[SPACE]			= {SPACE, "SPACE", 0},
	[INQUIRY]		= {INQUIRY, "INQUIRY", 1, 8},
	[RECOVER_BUFFERED_DATA] = {RECOVER_BUFFERED_DATA, "RECOVER_BUFFERED_DATA", 0},
	[MODE_SELECT]		= {MODE_SELECT, "MODE_SELECT", 0},
	[RESERVE]		= {RESERVE, "RESERVE", 0},
	[RELEASE]		= {RELEASE, "RELEASE", 0},
	[COPY]			= {COPY, "COPY", 0},
	[ERASE]			= {ERASE, "ERASE", 0},
	[MODE_SENSE]		= {MODE_SENSE, "MODE_SENSE", 1, 11},
	[READ_CAPACITY]		= {READ_CAPACITY, "READ_CAPACITY", 0},
	[START_STOP]		= {START_STOP, "START_STOP", 0},
	[READ_10]		= {READ_10, "READ_10", 1, 8},
	[WRITE_10]		= {WRITE_10, "WRITE_10", 1, 8},
       	[SEEK_10]		= {SEEK_10, "SEEK_10", 1, 8},
	[SYNCHRONIZE_CACHE]	= {SYNCHRONIZE_CACHE, "SYNCHRONIZE_CACHE", 1, 18},
	[LOCK_UNLOCK_CACHE]	= {LOCK_UNLOCK_CACHE, "LOCK_UNLOCK_CACHE", 0},
	[READ_DEFECT_DATA]	= {READ_DEFECT_DATA, "READ_DEFECT_DATA", 0},
	[MEDIUM_SCAN]		= {MEDIUM_SCAN, "MEDIUM_SCAN", 0},
	[WRITE_BUFFER]		= {WRITE_BUFFER, "WRITE_BUFFER", 0},
	[READ_BUFFER]		= {READ_BUFFER, "READ_BUFFER", 0},
	[UPDATE_BLOCK]		= {UPDATE_BLOCK, "UPDATE_BLOCK", 0},
	[READ_LONG]		= {READ_LONG, "READ_LONG", 0},
	[WRITE_LONG]		= {WRITE_LONG, "WRITE_LONG", 0},
	[CHANGE_DEFINITION]	= {CHANGE_DEFINITION, "CHANGE_DEFINITION", 0},
	[WRITE_SAME]		= {WRITE_SAME, "WRITE_SAME", 0},
	[READ_12]		= {READ_12, "READ_12", 1, 8},
	[WRITE_12]		= {WRITE_12, "WRITE_12", 1, 8},
	[READ_16]		= {READ_16, "READ_16", 1, 8},
	[WRITE_16]		= {WRITE_16, "WRITE_16", 1, 8},
	[VERIFY_16]		= {VERIFY_16, "VERIFY_16", 0},
	[WRITE_SAME_16]		= {WRITE_SAME_16, "WRITE_SAME_16", 0},
	[ZBC_OUT]		= {ZBC_OUT, "ZBC_OUT", 0, 0},
	[ZBC_IN]		= {ZBC_IN, "ZBC_IN", 0, 0},
	[READ_32]		= {READ_32, "READ_32", 0, 0},
	[WRITE_32]		= {WRITE_32, "WRITE_32", 0},
	[WRITE_SAME_32]		= {WRITE_SAME_32, "WRITE_SAME_32", 0},
	[ATA_16]		= {ATA_16, "ATA_16", 0},
	[ATA_12]		= {ATA_12, "ATA_12", 0},
};

int array_size = ARRAY_SIZE(scsi_opcode_array);

static struct env {
	char *disk;
	time_t interval;
	int times;
	struct sdev_hctl sdev;
} env = {
	.interval = 5,
	.times = 99999999,
	.sdev.host = -1,
	.sdev.channel = -1,
	.sdev.id = -1,
	.sdev.lun = -1,
};

static volatile bool running = true;
static void sig_handler(int sig)
{
	running = false;
}

static int libbpf_print_fn(enum libbpf_print_level level,
			   const char *format, va_list args)
{
	/* Ignore debug-level libbpf logs */
	if (level > LIBBPF_INFO)
		return 0;
	return vfprintf(stderr, format, args);
}

static void memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

const char argp_program_doc[] =
	"Report IO opcode count for scsi device\n"
	"\n"
	"USAGE: xd_scsiiocount [--help] [-t times] [-d device] [-i interval]\n"
	"\n"
	"EXAMPLES:\n"
	"    xd_scsiiocount               	# report all scsi device I/O scsi cmnd count\n"
	"    xd_scsiiocount -i 10         	# print 10 second summaries\n"
	"    xd_scsiiocount -d sdb     	# Trace sdc only\n"
	"    xd_scsiiocount -t 5           # report times\n";

static const struct argp_option opts[] = {
	{ "times", 't', "times", 0, "report scsi device I/O times" },
	{ "interval", 'i', "interval", 0, "refresh interval(secs)" },
	{ "device",  'd', "device",  0, "Trace this disk only" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	size_t len;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'd':
		env.disk = arg;
		if (!env.disk)
			break;
		len = strlen(env.disk);
		if (len + 1 > SDEV_NAME_LEN) {
			fprintf(stderr, "invaild disk name: too long\n");
			argp_usage(state);
		}
		break;
	case 'i':
		env.interval = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid internal\n");
			argp_usage(state);
		}		
		break;
	case 't':
		env.times = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid times\n");
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static void free_scsi_device(struct disk_info * disk)
{
	if (disk && disk->sdev_list)
		free(disk->sdev_list);
	if (disk)
		free(disk);
}

static struct disk_info *alloc_and_scan_scsi_device(void)
{
	struct disk_info *disk = NULL;
	struct sdev_list *list = NULL;
	int err;

	disk = (struct disk_info*)calloc(1, sizeof(struct disk_info));
	if (!disk)
		return NULL;
	
	memset(disk, 0, sizeof(struct disk_info));
	list = (struct sdev_list*)calloc(1, sizeof(struct sdev_list));
	if (!list)
		goto cleanup;

	disk->sdev_list = list;
	err = scan_sdevs(list);
	if (err)
		goto cleanup;

	return disk;
cleanup:
	if (list)
		free(list);

	if (disk)
		free(disk);
	return NULL;
}

static void get_disk_hctl(struct disk_info *disk, char *name,
			  struct sdev_hctl *key)
{
	int k;
	struct sdev_list *list = disk->sdev_list;

	for (k = 0; k < list->max_num; k++) {
		if (strcmp(list->sdev[k].name, name) == 0) {
			key->host = list->sdev[k].host;
			key->channel = list->sdev[k].channel;
			key->id = list->sdev[k].id;
			key->lun = list->sdev[k].lun;

			disk->filter_sdev.host = list->sdev[k].host;
			disk->filter_sdev.channel = list->sdev[k].channel;
			disk->filter_sdev.id = list->sdev[k].id;
			disk->filter_sdev.lun = list->sdev[k].lun;
			break;
		}
	}
}

static void set_filter_disk(struct xd_scsiiocount_bpf *skel,
			    struct disk_info *disk)
{
	unsigned int enable = 1;
	int fd = bpf_map__fd(skel->maps.filter_sdev_map);

	if (env.disk && fd > 0) {
		disk->filter = 1;
		get_disk_hctl(disk, env.disk, &env.sdev);
		bpf_map_update_elem(fd, &enable, &env.sdev, BPF_ANY);
	}
}

static void display_result(struct disk_info *disk_info)
{
	int k;
	int m;
	time_t t;
	struct tm *tm;
	struct sdev_list *sdev_list;

	time(&t);
	tm = localtime(&t);
	printf("%-24s", asctime(tm));

	printf("%-10s ", "DEVICE");
	for (k = 0; k < array_size; k++) {
		if (scsi_opcode_array[k].show)
			printf("%-*s ", scsi_opcode_array[k].format,
					scsi_opcode_array[k].name);
	}

	printf("\n");
	sdev_list = disk_info->sdev_list;
	for (m = 0; m < sdev_list->max_num; m++) {
		if (disk_info->filter && 
		   cmp_scsi_hctl(&disk_info->filter_sdev,
				 &sdev_list->sdev[m]))
			continue;

		printf("%-10s ", sdev_list->sdev[m].name);
		for (k = 0; k < array_size; k++) {
			if (scsi_opcode_array[k].show)
				printf("%-*ld ", scsi_opcode_array[k].format,
						disk_info->disk[m][k]);
		}
		printf("\n");
	}

	printf("\n\n");
}

static void update_disk_opcode_count(struct scsi_key *key, int count,
			      	     struct disk_info *disk_info)
{
	int k;
	struct scsi_hctl *sdev;

	for (k = 0; k < disk_info->sdev_list->max_num; k++) {
		sdev = &(disk_info->sdev_list->sdev[k]);
		if (sdev->host == key->hctl.host
		    && sdev->channel == key->hctl.channel
		    && sdev->id == key->hctl.id
		    && sdev->lun == key->hctl.lun) {
			disk_info->disk[k][key->opcode] = count;
			break;
		}
	}
}

static void poll_process_sdev_io(struct xd_scsiiocount_bpf *skel,
				 struct disk_info *disk)
{
	struct scsi_key key, next_key;
	int value;
	int fd = bpf_map__fd(skel->maps.scsi_opcode_map);

	while(running) {
		memset(&key, 0, sizeof(key));	
		while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
			bpf_map_lookup_elem(fd, &next_key, &value);
			update_disk_opcode_count(&next_key, value, disk);
			key = next_key;
		}

		sleep(env.interval);
		display_result(disk);

		if (--env.times == 0)
                        break;
	}
}

int main(int argc, char **argv)
{
	struct xd_scsiiocount_bpf *skel;
	struct disk_info *disk;
	int err;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	memlock_rlimit();

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	
	skel = xd_scsiiocount_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	disk = alloc_and_scan_scsi_device();
	if (!disk) {
		fprintf(stderr, "Failed to scan scsi device\n");
		goto cleanup;
	}

	err = xd_scsiiocount_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto cleanup;
	}

	set_filter_disk(skel, disk);

	err = xd_scsiiocount_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Tracing scsi device I/O... Hit Ctrl-C to end.\n\n");

	/* poll */
	poll_process_sdev_io(skel, disk);

cleanup:
	xd_scsiiocount_bpf__destroy(skel);
	free_scsi_device(disk);

	return err < 0 ? -err : 0;
}
