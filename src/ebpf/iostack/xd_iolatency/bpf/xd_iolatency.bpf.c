/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * xd_iolatency licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: Wu Bo <wubo009@163.com>
 * Create: 2022-12-05
 * Description:Trace i/o latency
 ******************************************************************************/
#include <common_k.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "xd_iolatency.h"

#define MAX_ENTRIES	(8192)
#define MAX_TS		(0xffffffffffff)

struct io_struct {
	u32 dev;
	u64 sector;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct io_struct);
	__type(value, u64);
} io_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_DEVICES_LIMIT);
	__type(key, struct iolatency_key);
	__type(value, struct iolatency_value);
} stat_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_DEVICES_LIMIT);
	__type(key, struct iolatency_key);
	__type(value, struct iolatency_issue_value);
} issue_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, struct feature_key);
	__type(value, struct feature_value);
} feature_map SEC(".maps");

struct io_ctx {
	u64 __do_not_use__;         // First 8 bytes for bpf ctx
	u32 dev;
	u64 sector;
	u32 nr_sector;
};

static void create_io_key(struct io_ctx *ctx, struct io_struct *key)
{
	key->dev = ctx->dev;
	key->sector = ctx->sector;
}

static unsigned int log2(unsigned int v)
{
	unsigned int r, shift;

	r = (v > 0xFFFF) << 4; v >>= r;
	shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
	shift = (v > 0xF) << 2; v >>= shift; r |= shift;
	shift = (v > 0x3) << 1; v >>= shift; r |= shift;
	r |= (v >> 1);

	return r;
}

static unsigned int log2l(unsigned long v)
{
	unsigned int hi = v >> 32;
	if (hi)
		return log2(hi) + 32;
	else
		return log2(v);
}

static int update_iolatency_issue(struct io_ctx *ctx, u64 delta,
				  enum issue_flags issue, bool ms)
{
	struct iolatency_key key = {.dev = ctx->dev};
	struct iolatency_issue_value *valuep, def_value = {};
	u64 index;
       
	valuep = bpf_map_lookup_elem(&issue_map, &key);
	if (!valuep) {
		__builtin_memset(&def_value, 0, sizeof(def_value));
		bpf_map_update_elem(&issue_map, &key, &def_value, 0);
		valuep = bpf_map_lookup_elem(&issue_map, &key);
		if (!valuep)
			return 0;
		valuep->dev = ctx->dev;
		valuep->count = 0;
		valuep->total_ts = 0;
		valuep->min = MAX_TS;
		valuep->max = 0;
		valuep->issue = issue;
	}

	if (valuep->total_ts > MAX_TS) {
		bpf_map_delete_elem(&issue_map, &key);
		return 0;
	}

	if (ms)
		delta /= 1000000U;
	else
		delta /= 1000U;

	if (delta > valuep->max)
		valuep->max = delta;
	if (delta < valuep->min)
		valuep->min = delta;

	valuep->total_ts += delta;
	__sync_fetch_and_add(&valuep->count, 1);
	index = log2l(delta);
	if (index >= MAX_ITEMS)
		index = MAX_ITEMS - 1;
	__sync_fetch_and_add(&valuep->item[index], 1);
	return 0;
}

static int update_iolatency(struct io_ctx *ctx,
			    u64 delta, enum issue_flags issue)
{
	struct iolatency_key key = {.dev = ctx->dev};
	struct iolatency_value *valuep, def_value = {};

	valuep = bpf_map_lookup_elem(&stat_map, &key);
	if (!valuep) {
		__builtin_memset(&def_value, 0, sizeof(def_value));
		bpf_map_update_elem(&stat_map, &key, &def_value, 0);
		valuep = bpf_map_lookup_elem(&stat_map, &key);
		if (!valuep)
			return 0;
		valuep->dev = ctx->dev;
	}

	valuep->issue[issue].total_ts += delta;
	__sync_fetch_and_add(&valuep->issue[issue].count, 1);

	return 0;
}

static bool filter_issue(struct feature_value *valuep, 
	        	 enum issue_flags issue)
{
	if (valuep->filter_issue == issue)
		return true;

	return false;
}

static bool filter_dev(struct io_ctx *ctx, struct feature_value *valuep)
{
	if (valuep->flag & FILTER_DEV &&
		valuep->filter_dev != ctx->dev)
		return true;

	return false;
}

static int probe_entry(struct io_ctx *ctx, enum issue_flags issue)
{
	struct io_struct key = {};
	u64 curr_ts = bpf_ktime_get_ns();
	u64 *old_ts, delta;
	struct feature_key fkey = {.enable = 1};
	struct feature_value *valuep = NULL;
	bool ms = false;
	
	valuep = bpf_map_lookup_elem(&feature_map, &fkey);
	if (valuep && filter_dev(ctx, valuep))
		return 0;
	
	create_io_key(ctx, &key);
	old_ts = bpf_map_lookup_elem(&io_map, &key);
	if (!old_ts) {
		bpf_map_update_elem(&io_map, &key, &curr_ts, 0);
 		return 0;
	}

	delta = curr_ts - *old_ts;
	*old_ts = curr_ts;
	if (valuep && valuep->flag & REPORT_MS)
		ms = true;

	if (issue == ISSUE_Q2M || issue == ISSUE_G2M ||
	    issue == ISSUE_D2C)
		bpf_map_delete_elem(&io_map, &key);

	if (valuep && valuep->flag & FILTER_ISSUE) {
		if (filter_issue(valuep, issue))
			return update_iolatency_issue(ctx, delta, issue, ms);
	} else {
		return update_iolatency(ctx, delta, issue);
	}

	return 0;
}

SEC("tracepoint/block/block_bio_queue")
int bpf__block_bio_queue(struct io_ctx *ctx)
{
	struct io_struct key = {};
	struct feature_key fkey = {.enable = 1};
	struct feature_value *valuep = NULL;
	u64 ts = bpf_ktime_get_ns();

	valuep = bpf_map_lookup_elem(&feature_map, &fkey);
	if (valuep && filter_dev(ctx, valuep))
		return 0;

	create_io_key(ctx, &key);
	bpf_map_update_elem(&io_map, &key, &ts, 0);

	return 0;
}

SEC("tracepoint/block/block_getrq")
int bpf__block_getrq(struct io_ctx *ctx)
{
	return probe_entry(ctx, ISSUE_Q2G);
}

SEC("tracepoint/block/block_bio_frontmerge")
int bpf__block_bio_frontmerge(struct io_ctx *ctx) 
{	
	return probe_entry(ctx, ISSUE_Q2M);
}

SEC("tracepoint/block/block_bio_backmerge")
int bpf__block_bio_backmerge(struct io_ctx *ctx)
{
	return probe_entry(ctx, ISSUE_Q2M);
}

SEC("tracepoint/block/block_rq_merge")
int bpf__block_rq_merge(struct io_ctx *ctx)
{
	return probe_entry(ctx, ISSUE_G2M);
}

SEC("tracepoint/block/block_rq_insert")
int bpf__block_rq_insert(struct io_ctx *ctx)
{
	return probe_entry(ctx, ISSUE_G2I);
}

SEC("tracepoint/block/block_rq_issue")
int bpf__block_rq_issue(struct io_ctx *ctx)
{
	return probe_entry(ctx, ISSUE_I2D);
}

SEC("tracepoint/block/block_rq_complete")
int bpf__block_rq_complete(struct io_ctx *ctx)
{
	return probe_entry(ctx, ISSUE_D2C);
}

char LICENSE[] SEC("license") = "GPL";
