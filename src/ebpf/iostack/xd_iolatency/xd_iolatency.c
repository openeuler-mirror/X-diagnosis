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
#include <common_u.h>
#include "xd_iolatency.skel.h"
#include "bpf/xd_iolatency.h"

#define MAX_NAME_LEN 	(32)
#define MAX_STARS	(40)
#define PATH_LEN	(512)

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof(*(x)))

struct partition {
	char name[MAX_NAME_LEN];
	unsigned dev;
	unsigned int major;
	unsigned int first_minor;
};

struct partitions {
	unsigned int max;
	unsigned int count;
	struct partition *part_list;
};

static volatile bool running = true;
static struct iolatency_issue_value issue_stat[MAX_DEVICES_LIMIT];
static struct iolatency_value io_stat[MAX_DEVICES_LIMIT];

struct iolatency_ctx {
	struct partitions *disk_parts;
	struct xd_iolatency_bpf_c *obj;
};

struct iolatency_attach_wapper {
	char *tp_base;
	char *tp_name;
	struct bpf_program *prog;
	struct bpf_link **link;
	bool attach;
};

static struct env {
	int time;
	int times;
	bool ms;
	bool filter_issue;
	char *issue;
	int issue_value;
	bool filter_dev;
	bool clean_data;
	char *disk;
	void (*print)(struct iolatency_ctx *ctx);
} env = {
	.clean_data = false,
	.filter_issue = false,
	.filter_dev = false,
	.ms = false,
	.time = 5,
	.times = 999999999,
};

const char argp_program_doc[] =
	"Trace I/O latency for block device.\n"
	"\n"
	"USAGE: xd_iolatency [--help] [-t time] [-d device] [-i ISSUE] [-T times] [-m] [-c]\n"
	"\n"
	"EXAMPLES:\n"
	"    xd_iolatency               # trace device I/O latency\n"
	"    xd_iolatency -d sdb     	# trace sdc only\n"
	"    xd_iolatency -i D2C     	# trace D2C issue only\n"
	"    xd_iolatency -t 10         # trace 10 second (default 5s)\n";

static const struct argp_option opts[] = {
	{ "time", 't', "TIME", 0, "Trace I/O stat time (default 5s)" },
	{ "times", 'T', "TIMES", 0, "Trace I/O stat times" },
	{ "device",  'd', "DEVICE",  0, "Trace this disk only" },
	{ "issue",  'i', "ISSUE",  0, "Trace the issue only (Q2G,Q2M,G2M,G2I,I2D,D2C)" },
	{ "milliseconds", 'm', NULL, 0, "Millisecond histogram" },
	{ "clean", 'c', NULL, 0, "Clean the history data" },
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
		if (len + 1 > MAX_NAME_LEN) {
			fprintf(stderr, "invaild disk name: too long\n");
			argp_usage(state);
		}
		env.filter_dev = true;
		break;
	case 'm':
		env.ms = true;
		break;
	case 'c':
		env.clean_data = true;
		break;
	case 'i':
		env.issue = arg;
		if (!strcmp(env.issue, "Q2G") || !strcmp(env.issue, "Q2M")
		    || !strcmp(env.issue, "G2I") ||
		    !strcmp(env.issue, "G2M") || 
		    !strcmp(env.issue, "I2D") || 
		    !strcmp(env.issue, "D2C")) {
			env.filter_issue = true;
			break;
		}
		fprintf(stderr, "invalid issue\n");
		argp_usage(state);
		break;
	case 't':
		env.time = strtol(arg, NULL, 10);
		if (errno || env.time < 1) {
			fprintf(stderr, "invalid time\n");
			argp_usage(state);
		}
		break;	
	case 'T':
		env.times = strtol(arg, NULL, 10);
		if (errno || env.times < 1) {
			fprintf(stderr, "invalid times\n");
			argp_usage(state);
		}
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

static int libbpf_print_fn(enum libbpf_print_level level,
			   const char *format, va_list args)
{
	/* Ignore debug-level libbpf logs */
	if (level > LIBBPF_INFO)
		return 0;
	return vfprintf(stderr, format, args);
}

static bool tracepoint_exist(const char *base, const char *event)
{
	char path[PATH_LEN];
	char *traceing_dir = "/sys/kernel/debug/tracing/events";

	snprintf(path, sizeof(path), "%s/%s/%s/format", traceing_dir,
		 base, event);

	if (!access(path, F_OK))
		return true;

	return false;
}

static int get_disk_dev(struct partitions *parts, char *name)
{
	int i;
	struct partition *part;

	for (i = 0; i < parts->count; i++) {
		part = &parts->part_list[i];
		if (!strcmp(part->name, name))
			return part->dev;
	}

	return 0;

}

static char * get_partition_name(struct partitions *parts,
				 unsigned int find_dev)
{
	int i;
	struct partition *part;

	for (i = 0; i < parts->count; i++) {
		part = &parts->part_list[i];
		if (part->dev == find_dev)
			return part->name;
	}

	return "N/A";
}

static void disk_partitions_cleanup(struct partitions *parts)
{
	if (!parts)
		return;
	if (parts->part_list)
		free(parts->part_list);
	free(parts);
}

static int disk_partitions_add(struct partitions *parts, char *part_name,
			       unsigned int major, unsigned int first_minor)
{
	struct partition *part;
	void *ptr;
	
	if (parts->count == parts->max) {
		ptr = realloc(parts->part_list, (parts->max + 10) *
			      sizeof(*parts->part_list));
		if (!ptr)
			return 1;
		parts->max += 10;
		parts->part_list = ptr;
	}
	
	part = &parts->part_list[parts->count];
	part->dev = (major << 20) + first_minor;
	part->major = major;
	part->first_minor = first_minor;
	snprintf(part->name, sizeof(part->name), "%s", part_name);
	parts->count++;

	return 0;
}

static struct partitions * disk_partitions_read(void)
{
	struct partitions *parts;
	unsigned int major, first_minor, unuse;
	char line[128];
	char part_name[MAX_NAME_LEN];
	FILE *fp;

	fp = fopen("/proc/partitions", "r");
	if (!fp)
		return NULL;
	parts = (struct partitions *)malloc(sizeof(struct partitions));
	if (!parts)
		goto cleanup;

	parts->part_list = malloc(sizeof(struct partition) * 10);
	if (!parts->part_list)
		goto cleanup;

	parts->max = 10;
	parts->count = 0;
	while (fgets(line, sizeof(line), fp) != NULL) {
		if (sscanf(line, " %d %d %d %[^\n ] ", &major, &first_minor,
		    &unuse, part_name) != 4)
			continue;
		if (disk_partitions_add(parts, part_name, major, first_minor))
			goto cleanup;
	}	
	fclose(fp);
	return parts;
cleanup:
	fclose(fp);
	disk_partitions_cleanup(parts);
	return NULL;
}

static void clean_stat(int fd)
{
	int err;
	struct iolatency_key key, *prev_key = NULL;

	while (running) {
		err = bpf_map_get_next_key(fd, prev_key, &key);
		if (err)
			break;
		err = bpf_map_delete_elem(fd, &key);
		if (err)
			break;
		prev_key = &key;
	}
}

static void clean_issue_stat(int fd)
{
	clean_stat(fd);
}

static void get_stars(char *str, long val, long val_max, int width)
{
	int i, num_stars;

	num_stars = width * val / val_max - 1;
	for (i = 0; i < num_stars && i < width - 1; i++)
		str[i] = '#';
	if (val > val_max)
		str[i - 1] = '+';
	str[i] = '\0';
}

static void print_log2_hist(unsigned int *vals, int vals_size,
			    const char *val_type)
{
	int stars_max = MAX_STARS;
	char starstr[MAX_STARS];
	unsigned long long low, high;
	int idx_max = -1;
	unsigned int val, val_max = 0;
	int stars, width, i;
	int total_v = 0;

	for (i = 0; i < vals_size; i++) {
		val = vals[i];
		if (val > 0)
			idx_max = i;
		if (val > val_max)
			val_max = val;
		total_v += val;
	}

	if (idx_max < 0)
		return;
	
	width = idx_max <= 32 ? 10 : 20;
	printf(" %-2s >=(%s) .. <(%-s)", " ", val_type, val_type);
	printf("%*s %-11s %-6s |%-*s|\n", width - 5, " ",
		"count", "ratio", MAX_STARS, "distribution"); 

	stars = idx_max <= 32 ? stars_max : (stars_max >> 1);
	for (i = 0; i <= idx_max; i++) {
		val = vals[i];
		low = (1ULL << (i + 1)) >> 1;
		high = (1ULL << (i + 1)) - 1;
		if (low == high)
			low -= 1;
		printf("%*lld .. %-*lld : %-8d  %-5.2f%% ", 
			width, low, width, high, val, val * 100.0 / total_v);
		get_stars(starstr, val, val_max, stars);
		printf("|%-*s|\n", MAX_STARS, starstr);
	}
	printf("\n\n");
}

static void print_issue_stat(struct iolatency_ctx *ctx)
{
	struct iolatency_key key = {}, next_key;
	int count = 0;
	struct tm *tm;
	time_t t;
	struct partitions *disk_parts = ctx->disk_parts;
	struct xd_iolatency_bpf_c *obj = ctx->obj;
	int fd = bpf_map__fd(obj->maps.issue_map);
	int i, err;
	char *type = env.ms ? "ms" : "us";

	while (bpf_map_get_next_key(fd, &key, &next_key) != -1) {
		err = bpf_map_lookup_elem(fd, &next_key, &issue_stat[count]);
		if (err < 0)
			return;
		count++;
		key = next_key;
	}

	time(&t);
	tm = localtime(&t);
	for (i = 0; i < count; i++) {
		printf("%-2s %-24s", " ", asctime(tm));
		printf("%-2s %s -> issue:%s  max:%lld  min:%lld  avg:%.4f  "
			"count:%lld\n", " ",
			get_partition_name(disk_parts, issue_stat[i].dev),
			env.issue, issue_stat[i].max, issue_stat[i].min,
			issue_stat[i].total_ts * 1.0 / issue_stat[i].count,
			issue_stat[i].count);
		print_log2_hist(issue_stat[i].item, MAX_ITEMS, type);
	}

	if (env.clean_data)
		clean_issue_stat(fd);
}

static inline double get_issue_value(struct iolatency_value *valuep,
				     enum issue_flags flag)
{
	__u64 count = valuep->issue[flag].count;
	double ms;

	ms = env.ms ? 1000000.0 : 1000.0;
	if (count)
		return valuep->issue[flag].total_ts / ms / count;

	return 0;
}

static void print_stat_header(void)
{
	time_t t;
	struct tm *tm;

	time(&t);
	tm = localtime(&t);
	printf("\n\n%-24s", asctime(tm));
	if (env.ms)
		printf("%-12s %-14s %-14s %-14s %-14s %-14s %-14s\n",
			"DEVICE", "Q2G(ms)", "Q2M(ms)", "G2M(ms)",
			"G2I(ms)", "I2D(ms)", "D2C(ms)");
	else
		printf("%-12s %-14s %-14s %-14s %-14s %-14s %-14s\n",
			"DEVICE", "Q2G(us)", "Q2M(us)", "G2M(us)",
			"G2I(us)", "I2D(us)", "D2C(us)");
}

static void print_stat(struct iolatency_ctx *ctx)
{
	struct iolatency_key key = {}, next_key;
	struct iolatency_value *valuep;
	int count = 0;
	struct partitions *disk_parts = ctx->disk_parts;
	struct xd_iolatency_bpf_c *obj = ctx->obj;
	int fd = bpf_map__fd(obj->maps.stat_map);
	int i, err;

	while (bpf_map_get_next_key(fd, &key, &next_key) != -1) {
		err = bpf_map_lookup_elem(fd, &next_key, &io_stat[count]);
		if (err < 0)
			return;
		count++;
		key = next_key;
	}

	print_stat_header();
	for (i = 0; i < count; i++) {
		valuep = &io_stat[i];
		printf("%-12s %-14.4f %-14.4f %-14.4f %-14.4f %-14.4f %-14.4f\n",
			get_partition_name(disk_parts, valuep->dev),
			get_issue_value(valuep, ISSUE_Q2G),
			get_issue_value(valuep, ISSUE_Q2M),
		        get_issue_value(valuep, ISSUE_G2M),
		        get_issue_value(valuep, ISSUE_G2I),
		        get_issue_value(valuep, ISSUE_I2D),
		        get_issue_value(valuep, ISSUE_D2C));
	}

	if (env.clean_data)
		clean_stat(fd);
}

static void poll_iolatency(struct iolatency_ctx *ctx)
{
	long times = env.times;

	while (running) {
		sleep(env.time);
		env.print(ctx);

		if (--times == 0)
			break;
	}
}

static void set_feature(struct iolatency_ctx *ctx)
{
	struct feature_key key = {.enable = 1};
	struct feature_value value = {.flag = 0};
	struct xd_iolatency_bpf_c *obj = ctx->obj;
	int fd = bpf_map__fd(obj->maps.feature_map);
	unsigned int dev;

	if (env.ms)
		value.flag |= REPORT_MS;

	if (env.filter_issue) {
		if (!strcmp(env.issue, "Q2G"))
			value.filter_issue = ISSUE_Q2G;
		if (!strcmp(env.issue, "Q2M"))
			value.filter_issue = ISSUE_Q2M;
		if (!strcmp(env.issue, "G2M"))
			value.filter_issue = ISSUE_G2M;
		if (!strcmp(env.issue, "G2I"))
			value.filter_issue = ISSUE_G2I;
		if (!strcmp(env.issue, "I2D"))
			value.filter_issue = ISSUE_I2D;
		if (!strcmp(env.issue, "D2C"))
			value.filter_issue = ISSUE_D2C;
		env.issue_value = value.filter_issue;
		value.flag |= FILTER_ISSUE;
	}

	if (env.filter_dev) {
		dev = get_disk_dev(ctx->disk_parts, env.disk);
		if (dev) {
			value.flag |= FILTER_DEV;
			value.filter_dev = dev;
		}
	}
	
	if (value.flag)
		bpf_map_update_elem(fd, &key, &value, 0);
}

static void iolatency_init(void)
{
	if (env.filter_issue)
		env.print = print_issue_stat;
	else
		env.print = print_stat;
}

static int xd_iolatency_section_attach(struct xd_iolatency_bpf_c *obj)
{
	int err = 0;
	int size, i;
	struct iolatency_attach_wapper *ptr;
	struct iolatency_attach_wapper attach_progs[] = {
		{"block", "block_bio_queue", obj->progs.bpf__block_bio_queue,
			&obj->links.bpf__block_bio_queue, true},
		{"block", "block_getrq", obj->progs.bpf__block_getrq,
			&obj->links.bpf__block_getrq, true},
		{"block", "block_bio_frontmerge", obj->progs.bpf__block_bio_frontmerge,
			&obj->links.bpf__block_bio_frontmerge, true},
		{"block", "block_bio_backmerge", obj->progs.bpf__block_bio_backmerge,
			&obj->links.bpf__block_bio_backmerge, true},
		{"block", "block_rq_merge", obj->progs.bpf__block_rq_merge,
			&obj->links.bpf__block_rq_merge, true},
		{"block", "block_rq_insert", obj->progs.bpf__block_rq_insert,
			&obj->links.bpf__block_rq_insert, true},
		{"block", "block_rq_issue", obj->progs.bpf__block_rq_issue,
			&obj->links.bpf__block_rq_issue, true},
		{"block", "block_rq_complete", obj->progs.bpf__block_rq_complete,
			&obj->links.bpf__block_rq_complete, true},
	};

	size = ARRAY_SIZE(attach_progs);

	for (i = 0; i < size; i++) {
		ptr = &attach_progs[i];
		if (tracepoint_exist(ptr->tp_base, ptr->tp_name) &&
		    ptr->attach) {
			*ptr->link = bpf_program__attach(ptr->prog);
			if (!(*ptr->link)) {
				err = -errno;
				fprintf(stderr, "failed to attach %s %s\n",
					ptr->tp_name, strerror(-err));
				break;
			}
		}
	}

	return err;
}

int main(int argc, char **argv)
{
	int err;
	struct xd_iolatency_bpf_c *obj;
	struct partitions *disk_parts = NULL;
	struct iolatency_ctx ctx;

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
	
	iolatency_init();

	obj = xd_iolatency_bpf_c__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	err = xd_iolatency_bpf_c__load(obj);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto cleanup;
	}

	disk_parts = disk_partitions_read();
	if (!disk_parts) {
		fprintf(stderr, "Failed to read device partitions\n");
		goto cleanup;
	}

	ctx.obj = obj;
	ctx.disk_parts = disk_parts;
	set_feature(&ctx);

	err = xd_iolatency_section_attach(obj);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Tracing I/O latency... Hit Ctrl-C to end.\n\n");

	/* poll */
	poll_iolatency(&ctx);
cleanup:
	disk_partitions_cleanup(disk_parts);
	xd_iolatency_bpf_c__destroy(obj);
	return err < 0 ? -err : 0;
}
