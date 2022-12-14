// SPDX-License-Identifier: GPL-2.0
/* 
 * Copyright (c) 2022 Huawei Inc. 
 *
 * History:
 * 	15-Sep-2022 Wu Bo <wubo40@huawei.com> created.
 */
#include <common_k.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "xd_scsiiotrace.h"

#define MAX_ENTRIES   (4096)

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} filter_result SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct scsi_sdev);
} filter_sdev SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRIES);
        __type(key, struct scsi_cmnd*);
        __type(value, u32);
} cmnd_map SEC(".maps");

struct scsi_cdb {
	char cdb[32];
};

static int probe_entry(struct pt_regs *ctx, struct scsi_cmnd *cmd,
		       struct event *e)
{
	struct scsi_device *device;
	struct Scsi_Host *host;
	struct scsi_cdb *scdb;
	unsigned int enable = 1;
	struct scsi_sdev *value;

	scdb = (struct scsi_cdb *)BPF_PROBE_VAL(cmd->cmnd);
	if (!scdb)
		return 0;

	e->cdb_len = BPF_PROBE_VAL(cmd->cmd_len);
	if (e->cdb_len > CDB_MAX_LEN)
		e->cdb_len = CDB_MAX_LEN;

	bpf_probe_read_kernel(&e->cdb, e->cdb_len, (void*)&(scdb->cdb));
	device = BPF_PROBE_VAL(cmd->device);
	if (!device)
		return 0;

	bpf_probe_read_kernel(&host, sizeof(struct Scsi_Host*),
			     (void*)&device->host);
	host = BPF_PROBE_VAL(device->host);
	if (!host)
		return 0;

	e->sdev.host = BPF_PROBE_VAL(host->host_no);
	e->sdev.channel = BPF_PROBE_VAL(device->channel);
	e->sdev.id = BPF_PROBE_VAL(device->id);
	e->sdev.lun = BPF_PROBE_VAL(device->lun);

	value = bpf_map_lookup_elem(&filter_sdev, &enable);
	if (value && (value->host != e->sdev.host ||
		      value->channel != e->sdev.channel ||
		      value->id != e->sdev.id ||
		      value->lun != e->sdev.lun)) {
		return 0;
	}

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e,
			      sizeof(struct event));

	return 0;
}

SEC("kprobe/scsi_log_completion")
int scsi_log_completion(struct pt_regs *ctx)
{
	struct scsi_cmnd *cmd;

	u32 enable = 1;
	u32 *value;
	struct event e = {};

	cmd = (struct scsi_cmnd *)PT_REGS_PARM1(ctx);
	e.disposition = (int)PT_REGS_PARM2(ctx);
	e.scsi_result = BPF_PROBE_VAL(cmd->result);

	value = bpf_map_lookup_elem(&filter_result, &enable);
	if (value && e.scsi_result == 0)
		return 0;

	e.driver_result = e.scsi_result;
	value = bpf_map_lookup_elem(&cmnd_map, &cmd);
	if (value) {
		e.driver_result = *value;
		bpf_map_delete_elem(&cmnd_map, &cmd);
	}

	return probe_entry(ctx, cmd, &e);
}

SEC("kprobe/scsi_decide_disposition")
int scsi_decide_disposition(struct pt_regs *ctx)
{
	struct scsi_cmnd *cmd;
	u32 enable = 1;
	u32 *value;
	struct event e = {};

	cmd = (struct scsi_cmnd *)PT_REGS_PARM1(ctx);
	e.driver_result = BPF_PROBE_VAL(cmd->result);

	value = bpf_map_lookup_elem(&filter_result, &enable);
	if (value && e.driver_result == 0)
		return 0;

	value = bpf_map_lookup_elem(&cmnd_map, &cmd);
	if (value)
		bpf_map_delete_elem(&cmnd_map, &cmd);

	bpf_map_update_elem(&cmnd_map, &cmd, &e.driver_result, BPF_ANY);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
