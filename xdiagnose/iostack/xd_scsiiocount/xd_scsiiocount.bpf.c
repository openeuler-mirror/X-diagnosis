#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "xd_scsiiocount.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct scsi_key);
	__type(value, u32);
	__uint(max_entries, 4096);
} scsi_opcode_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct sdev_hctl);
	__uint(max_entries, 1);
} filter_sdev_map SEC(".maps");

/* /sys/kernel/debug/tracing/events/scsi/scsi_dispatch_cmd_start/format */
struct scsi_cmnd_ctx {
	u64 __do_not_use__;         // First 8 bytes for bpf ctx
	struct scsi_key key;
};

SEC("tracepoint/scsi/scsi_dispatch_cmd_start")
int scsi_dispatch_cmd_start(struct scsi_cmnd_ctx *ctx)
{
	struct scsi_key key;
	int *count;
	struct sdev_hctl *filter;
	int enable = 1;
	int def_value = 1;

	filter = bpf_map_lookup_elem(&filter_sdev_map, &enable);
	if (filter && (filter->host != ctx->key.hctl.host ||
		filter->channel != ctx->key.hctl.channel ||
		filter->id != ctx->key.hctl.id ||
		filter->lun != ctx->key.hctl.lun)) {
		return 0;
	}

	key.hctl.host = ctx->key.hctl.host;
	key.hctl.channel = ctx->key.hctl.channel;
	key.hctl.id = ctx->key.hctl.id;
        key.hctl.lun = ctx->key.hctl.lun;
	key.opcode = ctx->key.opcode;

	count = bpf_map_lookup_elem(&scsi_opcode_map, &key);
	if (count) 
		__sync_fetch_and_add(count, 1);
	else
		bpf_map_update_elem(&scsi_opcode_map, &key, &def_value, BPF_ANY);

	return 0;
}

char _license[] SEC("license") = "GPL";
