/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * xd-scsiiotrace licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wubo
 * Create: 2022-09-15
 * Description: Trace scsi cmnd for scsi device.
 * ****************************************************************************/
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

struct scsi_disposition_s {
	int value;
	char name[32];
};

struct scsi_disposition_s  scsi_disposition_table[] = {
	{SCSI_MLQUEUE_HOST_BUSY, "HOST_BUSY"},
	{SCSI_MLQUEUE_DEVICE_BUSY, "DEVICE_BUSY"},
	{SCSI_MLQUEUE_EH_BUSY, "EH_BUSY"},
	{SCSI_MLQUEUE_TARGET_BUSY, "TARGET_BUSY"},
	{SCSI_NEEDS_RETRY, "NEEDS_RETRY"},
	{SCSI_SUCCESS, "SUCCESS"},
	{SCSI_FAILED, "FAILED"},
	{SCSI_QUEUED, "QUEUED"},
	{SCSI_SOFT_ERROR, "SOFT_ERROR"},
	{SCSI_ADD_TO_MLQUEUE, "ADD_TO_MLQUEUE"},
	{SCSI_TIMEOUT_ERROR, "TIMEOUT_ERROR"},
	{SCSI_RETURN_NOT_HANDLED, "NOT_HANDELED"},
	{SCSI_FAST_IO_FAIL, "FAST_TO_FAIL"},
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

struct scsi_result_s {
	char name[48];
};

struct scsi_result_s hostbyte_table[] = {
	[0x0] = {"DID_OK"},
	[0x1] = {"DID_NO_CONNECT"},
	[0x2] = {"DID_BUS_BUSY"},
	[0x3] = {"DID_TIME_OUT"},
	[0x4] = {"DID_BAD_TARGET"},
	[0x5] = {"DID_ABORT"},
	[0x6] = {"DID_PARITY"},
	[0x7] = {"DID_ERROR"},
	[0x8] = {"DID_RESET"},
	[0x9] = {"DID_BAD_INTR"},
	[0xa] = {"DID_PASSTHROUGH"},
	[0xb] = {"DID_SOFT_ERROR"},
	[0xc] = {"DID_IMM_RETRY"},
	[0xd] = {"DID_REQUEUE"},
	[0xe] = {"DID_TRANSPORT_DISRUPTED"},
	[0xf] = {"DID_TRANSPORT_FAILFAST"},
	[0x10] = {"DID_TARGET_FAILURE"},
	[0x11] = {"DID_NEXUS_FAILURE"},
	[0x12] = {"DID_ALLOC_FAILURE"},
	[0x13] = {"DID_MEDIUM_ERROR"},
};

struct scsi_result_s driverbyte_table[]={
	[0x1] = {"DRIVER_OK"},
	[0x2] = {"DRIVER_BUSY"},
	[0x3] = {"DRIVER_SOFT"},
	[0x4] = {"DRIVER_MEDIA"},
	[0x5] = {"DRIVER_ERROR"},
	[0x6] = {"DRIVER_INVALID"},
	[0x7] = {"DRIVER_TIMEOUT"},
	[0x8] = {"DRIVER_HARD"},
	[0x9] = {"DRIVER_SENSE"}
};

struct scsi_result_s msgbyte_table[] = {
	[0x0] = {"COMMAND_COMPLETE"},
	[0x1] = {"EXTENDED_MESSAGE"},
	[0x2] = {"SAVE_POINTERS"},
	[0x3] = {"RESTOBE_POINTERS"},
	[0x4] = {"DISCONNECT"},
	[0x5] = {"INITIATOR_ERROR"},
	[0x6] = {"ABORT_TASK_SET"},
	[0x7] = {"MESSAGE_REJECT"},
	[0x8] = {"NOP"},
	[0x9] = {"MSG_PARITY_ERROR"},
	[0xa] = {"LINKED_CMD_COMPLETE"},
	[0xb] = {"LINKED_FLG_CMD_COMPLETE"},
	[0xc] = {"TARGET_RESET"},
	[0xd] = {"ABORT_TASK"},
	[0xe] = {"CLEAR_TASK_SET"},
	[0xf] = {"RELEASE_RECOVERY"},
	[0x10] = {"RELEASE_RECOVERY"},
	[0x16] = {"CLEAR_ACA"},
	[0x17] = {"LOGICAL_UNIT_RESET"},
	[0x20] = {"SIMPLE_QUEUE_TAG"},
	[0x21] = {"HEAD_OF_QUEUE_TAG"},
	[0x22] = {"ORDERED_QUEUE_TAG"},
	[0x23] = {"IGNORE_WIDE_RESIDE"},
	[0x24] = {"ACA"},
	[0x55] = {"QAS_REQUEST"},
};

struct scsi_result_s statusbyte_table[] = {
	[0x0] = {"SAM_STAT_GOOD"},
	[0x2] = {"SAM_STAT_CHECK_CONDITION"},
	[0x4] = {"SAM_STAT_CONDITION_MET"},
	[0x8] = {"SAM_STAT_BUSY"},
	[0x10] = {"SAM_STAT_INTERMEDIATE"},
	[0x14] = {"SAM_STAT_INTERMEDIATE_CONDITION_MET"},
	[0x18] = {"SAM_STAT_RESERVATION_CONFLICT"},
	[0x22] = {"SAM_STAT_COMMAND_TERMINATED"},
	[0x28] = {"SAM_STAT_TASK_SET_FULL"},
	[0x30] = {"SAM_STAT_ACA_ACTIVE"},
	[0x40] = {"SAM_STAT_TASK_ABORTED"},
};

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
        const char *hb_string = "undefine";
        int hb = host_byte(result);

        if (hb < ARRAY_SIZE(hostbyte_table))
                hb_string = hostbyte_table[hb].name;
	return hb_string;
}

const char *scsi_driverbyte_string(int result)
{
        const char *db_string = "undefine";
        int db = driver_byte(result);

        if (db < ARRAY_SIZE(driverbyte_table))
                db_string = driverbyte_table[db].name;
        return db_string;
}

const char *scsi_msgbyte_string(int result)
{
        const char *db_string = "undefine";
        int db = msg_byte(result);

        if (db < ARRAY_SIZE(msgbyte_table))
                db_string = strlen(msgbyte_table[db].name)
			    ? msgbyte_table[db].name
			    : "undefine";
        return db_string;
}

const char *scsi_statusbyte_string(int result)
{
        const char *db_string = "undefine";
        int db = status_byte(result);

        if (db < ARRAY_SIZE(statusbyte_table))
                db_string = strlen(statusbyte_table[db].name)
			    ? statusbyte_table[db].name
			    : "undefine";
        return db_string;
}

static char *get_return_string(int value)
{
	int i;
	int size = ARRAY_SIZE(scsi_disposition_table);

	for (i = 0; i < size; i++) {
		if (scsi_disposition_table[i].value == value)
			return scsi_disposition_table[i].name;
	}

	return "undefine";
}

static struct env {
	char *disk;
	bool filter_event;
	int event;
	bool filter_opcode;
	int opcode;
	struct scsi_sdev sdev;
	bool filter_result;
	int parse_result;
	bool is_parse_result;
} env = {
	.filter_event = false,
	.filter_result = false,
	.filter_opcode = false,
	.is_parse_result = false,
	.sdev.host = -1,
	.sdev.channel = -1,
	.sdev.id = -1,
	.sdev.lun = -1,
	.parse_result = 0,
};

const char argp_program_doc[] =
"Trace scsi device scsi cmnd result.\n"
"\n"
"USAGE: xd_scsiiotrace [--help] [-d h:c:t:l] [-o opcode]\n"
"\n"
"EXAMPLES:\n"
"    xd_scsiiotrace               	# Report all scsi cmnd result\n"
"    xd_scsiiotrace -p 0x8000002	# Parse the scsi cmnd result.\n"
"    xd_scsiiotrace -d 0:0:0:1   	# Trace the scsi device only.\n";

static const struct argp_option opts[] = {
	{ "device", 'd', "h:c:t:l",  0, "Trace this scsi device only" },
	{ "event", 'e', "EVENT",  0, "Trace event for scsi cmnd(start, error, timeout, done)" },
	{ "parse", 'p', "RESULT",  0, "Parse the scsi cmnd result.(format hex)" },
	{ "opcode", 'o', "OPCODE",  0, "Trace specical scsi cmnd" },
	{ "result", 'r', NULL,  0, "Trace the result > 0 scsi cmnd" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

struct ioevent_table_s {
	const char *name;
	enum ioevent value;
} ioevent_table[] = {
	{"start", IO_START},
	{"done", IO_DONE},
	{"error", IO_ERROR},
	{"timeout", IO_TIMEOUT},
};

static int parse_filter_event(char *arg, int *event)
{
	int i;
	int max_event = ARRAY_SIZE(ioevent_table);

	for (i = 0; i < max_event; i++) {
		if (!strcmp(ioevent_table[i].name, arg)) {
			*event = ioevent_table[i].value;
			return 0;
		}
	}

	return 1;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'e':
		if (parse_filter_event(arg, &env.event) != 0) {
			argp_usage(state);
		}
		env.filter_event = true;
		break;
	case 'r':
		env.filter_result = true;
		break;
	case 'o':
		env.opcode = strtol(arg, NULL, 16);
		env.filter_opcode = true;
		break;
	case 'p':
		if (arg) {
			sscanf(arg, "%x", &env.parse_result);
			env.is_parse_result = true;
		}
		break;
	case 'd':
		env.disk = arg;
		if (!env.disk)
			break;
		if (strlen(arg) + 1 > SDEV_NAME_LEN) {
			fprintf(stderr, "invaild disk name: too long\n");
			argp_usage(state);
		}
		sscanf(env.disk, "%d:%d:%d:%d", &env.sdev.host,
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

	printf("\n %s\n", "status: ((result>>1) & 0x7f)");
	printf(" %s\n", "msg: ((result>>8) & 0xff)");
	printf(" %s\n", "host: ((result>>16) & 0xff)");
	printf(" %s\n\n", "driver: ((result>>24) & 0xff)");
	printf(" Parte scsi cmnd result:\n");
	printf("%-6s %-12s 0x%-8x %-16s\n", " ", "driverbyte:",
			driverbyte, scsi_driverbyte_string(result));
	printf("%-6s %-12s 0x%-8x %-16s\n", " ", "hostbyte:",
			hostbyte, scsi_hostbyte_string(result));
	printf("%-6s %-12s 0x%-8x %-16s\n", " ", "msgbyte:",
			msgbyte, scsi_msgbyte_string(result));
	printf("%-6s %-12s 0x%-8x %-16s\n", " ", "statusbyte:",
			statusbyte, scsi_statusbyte_string(result));

	return 0;
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
	printf("[%d:%d:%d:%d] %-6s %-4d %-7lld %-20.8f %-8s 0x%-10x %-14s %-32s\n",
		e->sdev.host, e->sdev.channel, e->sdev.id, e->sdev.lun,
		" ", e->cpuid, e->ioseq, e->timestamp / 1000000.0,
		ioevent_table[e->ioevent].name, e->result,
		get_return_string(e->rtn), cdb_buffer);
}

static void print_header()
{
	printf("%-16s %-4s %-7s %-20s %-8s %-12s %-14s %-32s\n",
		"DEVICE", "CPU", "SEQ", "TIMESTAMP", "EVENT", "RESULT",
		"DISPOSITION", "SCSI_CMD");
}

static void handle_lost_event(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("Lost %llu events on cpu #%d\n", lost_cnt, cpu);
}

static void set_filter_rule(struct xd_scsiiotrace_bpf *skel, struct env *env)
{
	unsigned int enable = 1;
	struct filter_rule filter_value = {};
	int filter_fd = bpf_map__fd(skel->maps.filter_rule_map);
	int sdev_fd = bpf_map__fd(skel->maps.filter_sdev_map);

	filter_value.flag = 0;
	if (env->filter_opcode) {
		filter_value.flag |= FILTER_OPCODE;
		filter_value.opcode = env->opcode;
	}

	if (env->filter_result)
		filter_value.flag |= FILTER_RESULT;

	if (filter_value.flag && filter_fd > 0) {
		bpf_map_update_elem(filter_fd, &enable, &filter_value, 0);
	}

	if (env->disk && sdev_fd > 0) {
		bpf_map_update_elem(sdev_fd, &enable, &env->sdev, 0);
	}

}

static int xd_scsiiotrace_bpf_progs_attach(struct xd_scsiiotrace_bpf *skel)
{
	int err = 0;

	if (!env.filter_event)
		return xd_scsiiotrace_bpf__attach(skel);

	switch (env.event) {
	case IO_START:
		skel->links.bpf__scsi_dispatch_cmd_start =
			bpf_program__attach(skel->progs.bpf__scsi_dispatch_cmd_start);
		if (!skel->links.bpf__scsi_dispatch_cmd_start)
			err = -errno;
		break;
	case IO_DONE:
		skel->links.bpf__scsi_dispatch_cmd_done =
			bpf_program__attach(skel->progs.bpf__scsi_dispatch_cmd_done);
		if (!skel->links.bpf__scsi_dispatch_cmd_done)
			err = -errno;
		break;
	case IO_ERROR:
		skel->links.bpf__scsi_dispatch_cmd_error =
			bpf_program__attach(skel->progs.bpf__scsi_dispatch_cmd_error);
		if (!skel->links.bpf__scsi_dispatch_cmd_error)
			err = -errno;
		break;
	case IO_TIMEOUT:
		skel->links.bpf__scsi_dispatch_cmd_timeout =
			bpf_program__attach(skel->progs.bpf__scsi_dispatch_cmd_timeout);
		if (!skel->links.bpf__scsi_dispatch_cmd_timeout)
			err = -errno;
		break;
	default:
		break;
	}

	return err;
}

static struct perf_buffer *
perf_buffer_create(struct xd_scsiiotrace_bpf *skel)
{
	struct perf_buffer *pb = NULL;

#ifndef LIBBPF_MAJOR_VERSION
	struct perf_buffer_opts pb_opts = {};

	pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb = handle_lost_event;
	pb = perf_buffer__new(bpf_map__fd(skel->maps.events),
				8/* 32KB per CPU */,
				&pb_opts);
#else
	pb = perf_buffer__new(bpf_map__fd(skel->maps.events),
				8/* 32KB per CPU */,
				handle_event, handle_lost_event,
				NULL, NULL);
#endif
	return pb;
}

int main(int argc, char **argv)
{
	struct perf_buffer *pb = NULL;
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

	if (env.is_parse_result)
		return parse_scsi_cmnd_result(env.parse_result);

	skel = xd_scsiiotrace_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	set_filter_rule(skel, &env);

	err = xd_scsiiotrace_bpf_progs_attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	pb = perf_buffer_create(skel);
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
