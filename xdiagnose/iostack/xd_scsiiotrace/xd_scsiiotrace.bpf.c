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

#include <common_k.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "xd_scsiiotrace.h"

#define MAX_ENTRIES	(8192)
#define MAX_CPU		(256)

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CPU);
	__type(key, int);
	__type(value, u64);
} ioseq_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct filter_rule);
} filter_rule_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct scsi_sdev);
} filter_sdev_map SEC(".maps");

struct io_ctx_s {
	u64 __do_not_use__;
	unsigned int host_no;
	unsigned int channel;
	unsigned int id;
	unsigned int lun;
	unsigned int opcode;
	int cmd_len;
	unsigned int data_sglen;
	unsigned int prot_sglen;
	unsigned char prot_op;
};

struct io_ctx {
	u64 __do_not_use__;
	unsigned int host_no;
	unsigned int channel;
	unsigned int id;
	unsigned int lun;
	int result;
	unsigned int opcode;
	int cmd_len;
	unsigned int data_sglen;
	unsigned int prot_sglen;
	unsigned char prot_op;
};

#define OFFSET_CTX	(sizeof(struct io_ctx) + 4)
#define OFFSET_CTX_S	(sizeof(struct io_ctx_s))

static bool filter_dev(struct event *e)
{
	u32 enable = 1;
	struct scsi_sdev *value;

	value = bpf_map_lookup_elem(&filter_sdev_map, &enable);
	if (value && (value->host != e->sdev.host ||
	    value->channel != e->sdev.channel ||
	    value->id != e->sdev.id ||
	    value->lun != e->sdev.lun)) {
		return 1;
	}

	return 0;
}

static bool filter_check(struct event *e)
{
	u32 enable = 1;
	struct filter_rule *value;

	if (filter_dev(e))
		return 1;

	value = bpf_map_lookup_elem(&filter_rule_map, &enable);
	if (!value)
		return 0;

	if (value->flag & FILTER_IOEVENT &&
	    e->ioevent != value->ioevent)
		return 1;

	if (value->flag & FILTER_OPCODE &&
	    e->opcode != value->opcode)
		return 1;

	if (value->flag & FILTER_RESULT &&
	    !e->result)
		return 1;

	return 0;
}

static void get_cpuid_and_ioseq(struct event *e)
{
	int cpuid = bpf_get_smp_processor_id();
	u64 *val, ioseq = 1;

	val = bpf_map_lookup_elem(&ioseq_map, &cpuid);
	if (!val) {
		bpf_map_update_elem(&ioseq_map, &cpuid, &ioseq, 0);
		val = bpf_map_lookup_elem(&ioseq_map, &cpuid);
		if (!val) {
			e->cpuid = 0;
			e->ioseq = 1;
			return;
		}
	}

	e->cpuid = cpuid;
	e->ioseq = *val;

	__sync_fetch_and_add(val, 1);
}

static int probe_entry(struct io_ctx *ctx, enum ioevent ioevent)
{
	struct event e = {};

	e.sdev.host = ctx->host_no;
	e.sdev.channel = ctx->channel;
	e.sdev.id = ctx->id;
	e.sdev.lun = ctx->lun;
	e.opcode = ctx->opcode;
	e.timestamp = bpf_ktime_get_ns() / 1000;
	e.ioevent = ioevent;
	e.rtn = (ioevent == IO_ERROR) ? ctx->result : SCSI_SUCCESS;
	e.result = (ioevent != IO_ERROR) ? ctx->result : 0;

	if (filter_check(&e))
		return 0;

	get_cpuid_and_ioseq(&e);
	e.cdb_len = ctx->cmd_len;
	if (e.cdb_len > CDB_MAX_LEN)
		e.cdb_len = CDB_MAX_LEN;
	bpf_probe_read((void*)&e.cdb, e.cdb_len, (char *)ctx + OFFSET_CTX);
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e,
			      sizeof(struct event));

	return 0;
}

SEC("tracepoint/scsi/scsi_dispatch_cmd_timeout")
int bpf__scsi_dispatch_cmd_timeout(struct io_ctx *ctx)
{
	return probe_entry(ctx, IO_TIMEOUT);
}

SEC("tracepoint/scsi/scsi_dispatch_cmd_error")
int bpf__scsi_dispatch_cmd_error(struct io_ctx *ctx)
{
	return probe_entry(ctx, IO_ERROR);
}

SEC("tracepoint/scsi/scsi_dispatch_cmd_done")
int bpf__scsi_dispatch_cmd_done(struct io_ctx *ctx)
{
	return probe_entry(ctx, IO_DONE);
}

SEC("tracepoint/scsi/scsi_dispatch_cmd_start")
int bpf__scsi_dispatch_cmd_start(struct io_ctx_s *ctx)
{
	struct event e = {};

	e.sdev.host = ctx->host_no;
	e.sdev.channel = ctx->channel;
	e.sdev.id = ctx->id;
	e.sdev.lun = ctx->lun;
	e.opcode = ctx->opcode;
	e.timestamp = bpf_ktime_get_ns() / 1000;
	e.ioevent = IO_START;
	e.rtn = SCSI_SUCCESS;
	e.result = 0;

	if (filter_check(&e))
		return 0;

	get_cpuid_and_ioseq(&e);
	e.cdb_len = ctx->cmd_len;
	if (e.cdb_len > CDB_MAX_LEN)
		e.cdb_len = CDB_MAX_LEN;
	bpf_probe_read((void*)&e.cdb, e.cdb_len, (char *)ctx + OFFSET_CTX_S);
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e,
			      sizeof(struct event));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
