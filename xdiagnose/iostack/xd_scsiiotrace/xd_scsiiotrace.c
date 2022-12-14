//SPDX-License-Identifier: (GPL-2.0)

/*
 * Copyright (c) 2022 Huawei Inc.
 *
 * xd_scsiiotrace: Trace scsi cmnd for scsi device 
 *
 * History:
 *      15-Sep-2022 Wu Bo <wubo40@huawei.com> created.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
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
#include "scsi_proto.h"
#include "xd_scsiiotrace.h"
#include "xd_scsiiotrace.skel.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

static volatile bool running = true;

#define CDB_BUFFER_LEN	(256)
#define SDEV_NAME_LEN	(16)

enum scsi_disposition {
	SCSI_MLQUEUE_HOST_BUSY		= 0x1055,
	SCSI_MLQUEUE_DEVICE_BUSY	= 0x1056,
	SCSI_MLQUEUE_EH_RETRY		= 0x1057,
	SCSI_MLQUEUE_TARGET_BUSY	= 0x1058,
	NEEDS_RETRY			= 0x2001,
	SUCCESS				= 0x2002,
	FAILED				= 0x2003,
	QUEUED				= 0x2004,
	SOFT_ERROR			= 0x2005,
	ADD_TO_MLQUEUE			= 0x2006,
	TIMEOUT_ERROR			= 0x2007,
	SCSI_RETURN_NOT_HANDLED		= 0x2008,
	FAST_IO_FAIL			= 0x2009,
};

/* part of code copy from the linux kernel */
static const char * cdb_byte0_names[] = {
/* 00-03 */ "Test Unit Ready", "Rezero Unit/Rewind", NULL, "Request Sense",
/* 04-07 */ "Format Unit/Medium", "Read Block Limits", NULL,
            "Reassign Blocks",
/* 08-0d */ "Read(6)", NULL, "Write(6)", "Seek(6)", NULL, NULL,
/* 0e-12 */ NULL, "Read Reverse", "Write Filemarks", "Space", "Inquiry",
/* 13-16 */ "Verify(6)", "Recover Buffered Data", "Mode Select(6)",
            "Reserve(6)",
/* 17-1a */ "Release(6)", "Copy", "Erase", "Mode Sense(6)",
/* 1b-1d */ "Start/Stop Unit", "Receive Diagnostic", "Send Diagnostic",
/* 1e-1f */ "Prevent/Allow Medium Removal", NULL,
/* 20-22 */  NULL, NULL, NULL,
/* 23-28 */ "Read Format Capacities", "Set Window",
            "Read Capacity(10)", NULL, NULL, "Read(10)",
/* 29-2d */ "Read Generation", "Write(10)", "Seek(10)", "Erase(10)",
            "Read updated block",
/* 2e-31 */ "Write Verify(10)", "Verify(10)", "Search High", "Search Equal",
/* 32-34 */ "Search Low", "Set Limits", "Prefetch/Read Position",
/* 35-37 */ "Synchronize Cache(10)", "Lock/Unlock Cache(10)",
            "Read Defect Data(10)",
/* 38-3c */ "Medium Scan", "Compare", "Copy Verify", "Write Buffer",
            "Read Buffer",
/* 3d-3f */ "Update Block", "Read Long(10)",  "Write Long(10)",
/* 40-41 */ "Change Definition", "Write Same(10)",
/* 42-48 */ "Unmap/Read sub-channel", "Read TOC/PMA/ATIP",
            "Read density support", "Play audio(10)", "Get configuration",
            "Play audio msf", "Sanitize/Play audio track/index",
/* 49-4f */ "Play track relative(10)", "Get event status notification",
            "Pause/resume", "Log Select", "Log Sense", "Stop play/scan",
            NULL,
/* 50-55 */ "Xdwrite", "Xpwrite, Read disk info", "Xdread, Read track info",
            "Reserve track", "Send OPC info", "Mode Select(10)",
/* 56-5b */ "Reserve(10)", "Release(10)", "Repair track", "Read master cue",
            "Mode Sense(10)", "Close track/session",
/* 5c-5f */ "Read buffer capacity", "Send cue sheet", "Persistent reserve in",
            "Persistent reserve out",
/* 60-67 */ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
/* 68-6f */ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
/* 70-77 */ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
/* 78-7f */ NULL, NULL, NULL, NULL, NULL, NULL, "Extended CDB",
            "Variable length",
/* 80-84 */ "Xdwrite(16)", "Rebuild(16)", "Regenerate(16)",
            "Third party copy out", "Third party copy in",
/* 85-89 */ "ATA command pass through(16)", "Access control in",
            "Access control out", "Read(16)", "Compare and Write",
/* 8a-8f */ "Write(16)", "ORWrite", "Read attributes", "Write attributes",
            "Write and verify(16)", "Verify(16)",
/* 90-94 */ "Pre-fetch(16)", "Synchronize cache(16)",
            "Lock/unlock cache(16)", "Write same(16)", NULL,
/* 95-99 */ NULL, NULL, NULL, NULL, NULL,
/* 9a-9f */ NULL, NULL, NULL, "Service action bidirectional",
            "Service action in(16)", "Service action out(16)",
/* a0-a5 */ "Report luns", "ATA command pass through(12)/Blank",
            "Security protocol in", "Maintenance in", "Maintenance out",
            "Move medium/play audio(12)",
/* a6-a9 */ "Exchange medium", "Move medium attached", "Read(12)",
            "Play track relative(12)",
/* aa-ae */ "Write(12)", NULL, "Erase(12), Get Performance",
            "Read DVD structure", "Write and verify(12)",
/* af-b1 */ "Verify(12)", "Search data high(12)", "Search data equal(12)",
/* b2-b4 */ "Search data low(12)", "Set limits(12)",
            "Read element status attached",
/* b5-b6 */ "Security protocol out", "Send volume tag, set streaming",
/* b7-b9 */ "Read defect data(12)", "Read element status", "Read CD msf",
/* ba-bc */ "Redundancy group (in), Scan",
            "Redundancy group (out), Set cd-rom speed", "Spare (in), Play cd",
/* bd-bf */ "Spare (out), Mechanism status", "Volume set (in), Read cd",
            "Volume set (out), Send DVD structure",
};

unsigned int cdb_name_array_size =  ARRAY_SIZE(cdb_byte0_names);

static const char * const hostbyte_table[]={
"DID_OK", "DID_NO_CONNECT", "DID_BUS_BUSY", "DID_TIME_OUT", "DID_BAD_TARGET",
"DID_ABORT", "DID_PARITY", "DID_ERROR", "DID_RESET", "DID_BAD_INTR",
"DID_PASSTHROUGH", "DID_SOFT_ERROR", "DID_IMM_RETRY", "DID_REQUEUE",
"DID_TRANSPORT_DISRUPTED", "DID_TRANSPORT_FAILFAST", "DID_TARGET_FAILURE",
"DID_NEXUS_FAILURE", "DID_ALLOC_FAILURE", "DID_MEDIUM_ERROR" };

static const char * const driverbyte_table[]={
"DRIVER_OK", "DRIVER_BUSY", "DRIVER_SOFT",  "DRIVER_MEDIA", "DRIVER_ERROR",
"DRIVER_INVALID", "DRIVER_TIMEOUT", "DRIVER_HARD", "DRIVER_SENSE"};

/*
 *  Use these to separate status msg and our bytes
 *
 *  These are set by:
 *
 *      status byte = set from target device
 *      msg_byte    = return status from host adapter itself.
 *      host_byte   = set by low-level driver to indicate status.
 *      driver_byte = set by mid-level.
 */
#define status_byte(result) (((result) >> 1) & 0x7f)
#define msg_byte(result)    (((result) >> 8) & 0xff)
#define host_byte(result)   (((result) >> 16) & 0xff)
#define driver_byte(result) (((result) >> 24) & 0xff)

const char *scsi_hostbyte_string(int result)
{
        const char *hb_string = NULL;
        int hb = host_byte(result);

        if (hb < ARRAY_SIZE(hostbyte_table))
                hb_string = hostbyte_table[hb];
	return hb_string;
}

const char *scsi_driverbyte_string(int result)
{
        const char *db_string = NULL;
        int db = driver_byte(result);

        if (db < ARRAY_SIZE(driverbyte_table))
                db_string = driverbyte_table[db];
        return db_string;
}

#define STR_NEEDS_RETRY		"NEEDS_RETRY"
#define STR_SUCCESS		"SUCCESS"
#define STR_FAILED		"FAILED"
#define STR_QUEUED		"QUEUED"
#define STR_SOFT_ERROR		"SOFT_ERROR"
#define STR_ADD_TO_MLQUEUE	"ADD_TO_MLQUEUE"
#define STR_TIMEOUT_ERROR	"TIMEOUT_ERROR"
#define STR_FAST_IO_FAIL	"FAST_IO_FAIL"
#define STR_SCSI_RETURN_NOT_HANDLED "SCSI_RETURN_NOT_HANDLED"
#define STR_UNKNOWN		"UNKNOWN"

static struct env {
	char *disk;
	bool filter_error;
	struct scsi_sdev sdev;
	int parse_result;
} env = {
	.filter_error = false,
	.sdev.host = -1,
	.sdev.channel = -1,
	.sdev.id = -1,
	.sdev.lun = -1,
	.parse_result = 0,
};

const char argp_program_doc[] =
"Trace scsi device scsi cmnd result.\n"
"\n"
"USAGE: xd_scsiiotrace [--help] [-d h:c:t:l] [-E]\n"
"\n"
"EXAMPLES:\n"
"    xd_scsiiotrace               	# Report all scsi cmnd result\n"
"    xd_scsiiotrace -E   		# Report error/timeout scsi cmnd result\n"
"    xd_scsiiotrace -p 0x8000002	# Parse the scsi cmnd result.\n"
"    xd_scsiiotrace -d 0:0:0:1   	# Trace the scsi device only.\n";

static const struct argp_option opts[] = {
	{ "device", 'd', "h:c:t:l",  0, "Trace this scsi device only" },
	{ "error", 'E', NULL, 0, "Trace error/timeout scsi cmnd. (default trace all scsi cmnd)" },
	{ "parse", 'p', "result",  0, "Parse the scsi cmnd result.(format hex)" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'E':
		env.filter_error = true;
		break;
	case 'p':
		if (arg)
			sscanf(arg, "%x", &env.parse_result);
		break;
	case 'd':
		env.disk = arg;
		if (!env.disk)
			break;
		if (strlen(arg) + 1 > SDEV_NAME_LEN) {
			fprintf(stderr, "invaild disk name: too long\n");
			argp_usage(state);
		}
		sscanf(env.disk, "%d:%d:%d:%ld", &env.sdev.host,
			&env.sdev.channel, &env.sdev.id, &env.sdev.lun);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static void sig_handler(int sig)
{
	running = false;
}

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level > LIBBPF_INFO)
		return 0;

	return vfprintf(stderr, format, args);
}

void memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur       = RLIM_INFINITY,
		.rlim_max       = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static int parse_scsi_cmnd_result(int result)
{
	int statusbyte = status_byte(result);
	int msgbyte = msg_byte(result);
	int hostbyte = host_byte(result);
	int driverbyte = driver_byte(result);

	printf("Parte scsi cmnd result:\n");
	printf("	hostbyte=0x%-2x %s\n", hostbyte, 
			scsi_hostbyte_string(result));
	printf("	driverbyte=0x%-2x %s\n", driverbyte,
			scsi_driverbyte_string(result));
	printf("	msgbyte=0x%-2x\n", msgbyte);
	printf("	statusbyte=0x%-2x\n", statusbyte);

	return 0;
}

static char *gitdisposition_descrp(int disposition)
{
	switch (disposition) {
	case SUCCESS:
		return STR_SUCCESS;
	case NEEDS_RETRY:
		return STR_NEEDS_RETRY;
	case FAILED:
		return STR_FAILED;
	case ADD_TO_MLQUEUE:
		return STR_ADD_TO_MLQUEUE;
	case TIMEOUT_ERROR:
		return STR_TIMEOUT_ERROR;
	case FAST_IO_FAIL:
		return STR_FAST_IO_FAIL;
	case SOFT_ERROR:
		return STR_SOFT_ERROR;
	case QUEUED:
		return STR_QUEUED;
	default:
		return STR_UNKNOWN;
	}
}

static void scsi_format_cdb_log(const struct event *e,
				char *logbuf, int buffer_len)
{
	int i;
	unsigned int off = 0;
	int opcode = e->cdb[0];
	const char *cdb_name;

	if (opcode >= VENDOR_SPECIFIC_CDB)
		return;
	
	if (opcode >= cdb_name_array_size)
		return;

	cdb_name = cdb_byte0_names[opcode];
	off += sprintf(logbuf + off, "%s", "CDB: ");
	off += sprintf(logbuf + off, "[%s] ", cdb_name);
	for (i = 0; i < e->cdb_len; i++) {
		off += sprintf(logbuf + off, "%x", e->cdb[i]);
		off += sprintf(logbuf + off, "%s", " ");

		if (off > buffer_len)
			break;
	}
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	const struct event *e = data;
	char cdb_buffer[CDB_BUFFER_LEN];

	scsi_format_cdb_log(e, cdb_buffer, CDB_BUFFER_LEN);
	printf("[%d:%d:%d:%ld] %-6s 0x%-14x 0x%-10x %-16s %-32s\n",
		e->sdev.host, e->sdev.channel, e->sdev.id, e->sdev.lun,
		" ", e->driver_result, e->scsi_result, 
		gitdisposition_descrp(e->disposition), cdb_buffer);
}

static void print_header()
{
	printf("%-16s %-16s %-12s %-16s %-32s\n",
		"DEVICE", "DRIVER_RESULT", "SCSI_RESULT", "DISPOSION", "SCSI_CMD");
}

static void set_filter_rule(struct xd_scsiiotrace_bpf *skel, struct env *env)
{
	unsigned int enable = 1;
	unsigned int feature = 1;
	int result_fd = bpf_map__fd(skel->maps.filter_result);
	int sdev_fd = bpf_map__fd(skel->maps.filter_sdev);

	if (env->filter_error && result_fd > 0) {
		bpf_map_update_elem(result_fd, &enable, &feature, BPF_ANY);
	}

	if (env->disk && sdev_fd > 0) {
		bpf_map_update_elem(sdev_fd, &enable, &env->sdev, BPF_ANY);
	}
}

int main(int argc, char **argv)
{
	struct perf_buffer *pb = NULL;
        struct perf_buffer_opts pb_opts = {};
	struct xd_scsiiotrace_bpf *skel;
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

	if (env.parse_result)
		return parse_scsi_cmnd_result(env.parse_result);

	skel = xd_scsiiotrace_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	set_filter_rule(skel, &env);

	err = xd_scsiiotrace_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	pb_opts.sample_cb = handle_event;
	pb = perf_buffer__new(bpf_map__fd(skel->maps.events),
					8/* 32KB per CPU */, &pb_opts);
	if (libbpf_get_error(pb)) {
		err = -1;
		fprintf(stderr, "Failed to create perf buffer\n");
		goto cleanup;
	}

	printf("Tracing scsi cmnd I/O result... Hit Ctrl-C to end.\n\n");

	print_header();

	/* polling */
	while (running) {
		err = perf_buffer__poll(pb, 100 /*timeout, ms*/);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "Error polling perf buffer: %d\n", err);
			goto cleanup;
		}
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	xd_scsiiotrace_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
