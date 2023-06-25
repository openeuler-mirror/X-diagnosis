/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * xd-ext4fsstat licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wubo
 * Create: 2022-11-05
 * Description: Trace ext4 filesystem read/write.
 * ****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <argp.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <mntent.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <common_u.h>
#include "bpf/xd_ext4fsstat.h"
#include "xd_ext4fsstat.skel.h"

#define MAX_FILE_LIMIT		MAX_EXT4_FILES
#define BUFFER_LEN		(128)
#define TRACE_FILENAME_LEN	(512)

static struct env {
	time_t interval;
	__u32 times;
	__u32 sort;
	__u32 opcode;
	__u32 rw;
	__u32 pid;
	__u32 top;
	char *mntname;
	bool filter_mnt;
	bool filter_opcode;
	bool filter_pid;
	bool clean;
	bool clear;
	bool showtop;
	bool viewpid;
} env = {
	.viewpid = false,
	.filter_opcode = false,
	.filter_pid = false,
	.filter_mnt = false,
	.clean = false,
	.clear = false,
	.interval = 5,
	.times = 99999999,
	.sort = FILE_READ,
};

static volatile bool running = true;
static struct file_iostat filestat[MAX_FILE_LIMIT];

struct pid_iostat_wapper {
	int filestat_index;
	struct pid_iostat pidstat;
};
static struct pid_iostat_wapper pid[MAX_FILE_LIMIT];
static char filename_buffer[TRACE_FILENAME_LEN];
static char mnt_dir[TRACE_FILENAME_LEN];

static void sig_hander(int sig)
{
	running = false;
}

static int libbpf_print_fn(enum libbpf_print_level level,
			  const char *format, va_list args)
{
	if (level > LIBBPF_INFO)
		return 0;
	return vfprintf(stderr, format, args);
}

const char argp_program_doc[] = 
	"Trace file read/write stat for ext4 filesystem.\n"
	"\n"
	"USAGE: ext4fstat [--help] [-t times] [-i interval] [-s SORT] [-o opcode]\n"
	"\n"
	"EXAMPLES:\n"
	"    ext4fsstat			#Trace file read/write stat for ext4 filesystem\n"
	"    ext4fsstat -i 10		#printf 10 second summaries\n"
	"    ext4fsstat -m /mnt/test	#Trace the special mount point for ext4 filesystem.\n"
	"    ext4fsstat	-s r		#Sort the read bytes\n"
	"    ext4fsstat -o r		#Trace read only, default read and wriete\n"
	"    ext4fsstat -t 5		#Trace 5 times\n"
	"    ext4fsstat -v p 		#show the pid view\n";

static const struct argp_option opts[] = {
	{"times", 't', "TIMES", 0, "Trace times"},
	{"top", 'T', "TOP", 0, "show the topN (1~8192)"},
	{"interval", 'i', "INTERVAL", 0, "Refreash interval(secs), default 5s."},
	{"mnt", 'm', "MNTPOINT", 0, "the special mount point"},
	{"sort", 's', "SORT", 0, "Sort r/w/wb, default read"},
	{"opcode", 'o', "OPCODE", 0, "Trace file r/w, defalut both."},
	{"clean", 'c', NULL, 0, "Clean the trace data"},
	{"clear", 'C', NULL, 0, "Clear the screen"},
	{"pid", 'p', "PID", 0, "Trace the pid only"},
	{"view", 'v', "VIEW", 0, "p:pids view, f: files view, defaut file view"},
	{NULL, 'h', NULL, OPTION_HIDDEN, "Show the help."},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'i':
		env.interval = strtol(arg, NULL, 10);
		if (errno || env.interval < 1) {
			fprintf(stderr, "invalid internal");
			argp_usage(state);
		}
		break;
	case 'm':
		env.filter_mnt = true;
		env.mntname = arg;
		break;
	case 'v':
		if (!strcmp(arg, "p"))
			env.viewpid = true;
		else if (!strcmp(arg, "f"))
			env.viewpid = false;
		else
			argp_usage(state);
		break;
	case 'c':
		env.clean = true;
		break;
	case 'C':
		env.clear = true;
		break;
	case 'T':
		env.top = strtol(arg, NULL, 10);
		if (errno || env.top  < 0 || env.top > MAX_EXT4_FILES) {
			fprintf(stderr, "invalid topN\n");
			argp_usage(state);
			break;
		}
		env.showtop = true;
		break;
	case 't':
		env.times = strtol(arg, NULL, 10);
		if (errno || env.times < 1) {
			fprintf(stderr, "invalid topN\n");
			argp_usage(state);
		}
		break;
	case 'p':
		env.pid = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid pid\n");
			argp_usage(state);
		}
		env.filter_pid = true;
		env.viewpid = true;
		break;
	case 'o':
		if (!strcmp(arg, "r")) {
			env.filter_opcode = true;
			env.opcode = FILE_READ;
		} else if (!strcmp(arg, "w")) { 
			env.filter_opcode = true;
			env.opcode = FILE_WRITE;
		} else {
			argp_usage(state);
		}
		break;	
	case 's':
		if (!strcmp(arg, "r"))
			env.sort = FILE_READ;
		else if (!strcmp(arg, "w"))
			env.sort = FILE_WRITE;
		else if (!strcmp(arg, "wb"))
			env.sort = FILE_WRITEBACK;
		else
			argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static int sort_pidstat_handler(const void *a, const void *b)
{
	struct pid_iostat_wapper *p1 = (struct pid_iostat_wapper*)a;
	struct pid_iostat_wapper *p2 = (struct pid_iostat_wapper*)b;

	if (env.sort == FILE_READ)
		return p2->pidstat.read_bytes - p1->pidstat.read_bytes;
	else if (env.sort == FILE_WRITE)
		return p2->pidstat.write_bytes - p1->pidstat.write_bytes;
	else
		return p2->pidstat.writeback_bytes - p1->pidstat.writeback_bytes;
}

static int sort_filestat_handler(const void *a, const void *b)
{
	struct file_iostat *f1 = (struct file_iostat*)a;
	struct file_iostat *f2 = (struct file_iostat*)b;

	if (env.sort == FILE_READ)
		return f2->read_bytes - f1->read_bytes;
	else if (env.sort == FILE_WRITE)
		return f2->write_bytes - f1->write_bytes;
	else
		return f2->writeback_bytes - f1->writeback_bytes;
}

static void ext4fsstat_data_clean(struct xd_ext4fsstat_bpf_c *skel)
{
	int err;
	struct file_key key, *prev_key = NULL;
	struct pid_key pkey, *pprev_key = NULL;
	int fd;

	fd = bpf_map__fd(skel->maps.filestat_map);
	while (running) {
		err = bpf_map_get_next_key(fd, prev_key, &key);
		if (err)
			break;
		err = bpf_map_delete_elem(fd, &key);
		if (err)
			break;
		prev_key = &key;
	}

	if (!env.viewpid)
		return;
	fd = bpf_map__fd(skel->maps.pidstat_map);
	while (running) {	
		err = bpf_map_get_next_key(fd, pprev_key, &pkey);
		if (err)
			break;
		err = bpf_map_delete_elem(fd, &pkey);
		if (err)
			break;
		pprev_key = &pkey;	
	}
}

char *get_file_path(struct file_iostat *io, char *buffer, int len)
{
	if (strstr(io->d1name, "/")) {
		snprintf(buffer, len, "%s%s%s", mnt_dir,
			 strlen(mnt_dir) ? "/" : "", io->filename);
	} else if (strstr(io->d2name, "/")) {
		snprintf(buffer, len, "%s/%s/%s", mnt_dir,
			 io->d1name, io->filename);
	} else if (strstr(io->d3name, "/")) {
		snprintf(buffer, len, "%s/%s/%s/%s", mnt_dir,
			 io->d2name, io->d1name, io->filename);
	} else {
		snprintf(buffer, len, "%s/{...}/%s/%s/%s/%s", mnt_dir,
			 io->d3name, io->d2name, io->d1name, io->filename);
			
	}

	return buffer;	
}

static int get_pidstat(int fd)
{
	int rows = 0;
	int err;
	struct pid_key key, *prev_key = NULL;

	while (running) {	
		err = bpf_map_get_next_key(fd, prev_key, &key);
		if (err)
			break;
		err = bpf_map_lookup_elem(fd, &key, &pid[rows++].pidstat);
		if (err)
			break;
		prev_key = &key;
	}
	return rows;
}

static void get_filestat(int fd, int *rows)
{
	int i = 0;
	int err = 0;
	struct file_key key = {}, *prev_key = NULL;

	if (env.viewpid && *rows == 0)
		return;

	while (running) {
		if (env.viewpid) {
			key.dev = pid[i].pidstat.dev;
			key.ino = pid[i].pidstat.ino;
			pid[i].filestat_index = -1;
			if (i >= *rows)
				err = 1;
		} else
			err = bpf_map_get_next_key(fd, prev_key, &key);
		if (err)
			break;
		err = bpf_map_lookup_elem(fd, &key, &filestat[i]);
		if (err < 0)
			break;
		pid[i].filestat_index = i;
		pid[i].pidstat.writeback_bytes = filestat[i].writeback_bytes;
		prev_key = &key;
		i++;
	}

	*rows = i;
}

static void print_header(void)
{
	struct tm *tm;
	time_t t;

	time(&t);
	tm = localtime(&t);

	printf("\n\n%-24s", asctime(tm));
	if (!env.viewpid) {
		printf("%s%-16s %-16s %-16s %s\n",
		       " ", "READ(Kb)", "WRITE(Kb)",
			"WRITEBACK(Kb)", "FILENAME");
	} else {
		printf("%s%-12s %-18s %-8s %-12s %-8s %-12s %-16s %s\n",
		       " ", "TID", "COMM", "READs", "READ(Kb)",
		       "WRITEs", "WRITE(Kb)", "WRITEBACK(Kb)", "FILENAME");
	}	
}

static void print_file_stat(int rows)
{
	int i = 0;

	qsort(filestat, rows, sizeof(struct file_iostat),
	      sort_filestat_handler);

	rows = env.showtop && rows > env.top ? env.top : rows;
	for (i = 0; i < rows; i++) {
		printf(" %-16f %-16f %-16f %s\n",
		      filestat[i].read_bytes / 1024.0,
		      filestat[i].write_bytes / 1024.0,
		      filestat[i].writeback_bytes / 1024.0,
		      get_file_path(&filestat[i], filename_buffer,
		      TRACE_FILENAME_LEN));
	}
}

static void print_pid_stat(int rows)
{
	int i;

	qsort(pid, rows, sizeof(struct pid_iostat_wapper),
	      sort_pidstat_handler);

	rows = env.showtop && rows > env.top ? env.top : rows;
	for (i = 0; i < rows; i++) {
		printf(" %-12d %-18s %-8lld %-12f %-8lld"
		       " %-12f %-16f %s\n",
		        pid[i].pidstat.tid,
			pid[i].pidstat.comm,
			pid[i].pidstat.reads,
			pid[i].pidstat.read_bytes / 1024.0,
			pid[i].pidstat.writes,
			pid[i].pidstat.write_bytes / 1024.0,
			pid[i].pidstat.writeback_bytes / 1024.0,
			pid[i].filestat_index != -1 
		      	? get_file_path(&filestat[pid[i].filestat_index],
					filename_buffer, TRACE_FILENAME_LEN)
			: "N/A");
	}
}

static void print_ext4fstat(struct xd_ext4fsstat_bpf_c *skel)
{
	int rows = 0;
	int pid_fd = bpf_map__fd(skel->maps.pidstat_map);
	int file_fd = bpf_map__fd(skel->maps.filestat_map);

	if (env.viewpid)
		rows = get_pidstat(pid_fd);
	get_filestat(file_fd, &rows);

	if (env.clear)
		system("clear");

	print_header();
	if (!running || rows == 0)
		return;
	if (env.viewpid)
		print_pid_stat(rows);
	else
		print_file_stat(rows);

	if (env.clean)
		ext4fsstat_data_clean(skel);
}

static int get_block_devt(char *name)
{
	char *filename = "/proc/partitions";
	char line[BUFFER_LEN];
	char ptname[BUFFER_LEN];
	FILE *fp;
	int major, minor, size;

	fp = fopen(filename, "r");
	if (!fp)
		return 0;
	while(fgets(line, sizeof(line), fp)) {
		if (sscanf(line, " %d %d %d %[^\n ] ", &major, &minor,
		    &size, ptname) != 4)
			continue;
		if (strcmp(ptname, name) == 0)
			return (major << 20) + minor;
	}
	
	return 0;
}

static int get_mntpoint_dev(char *mntname, unsigned int *dev)
{
	char *filename = "/proc/mounts";
	char *ftype = "ext4";
	FILE *file;
	struct mntent *mntent;
	char devicename[BUFFER_LEN];
	char buffer[BUFFER_LEN];
	char *ptr;
	unsigned int devt = 0;

	file = setmntent(filename, "r");
	if (!file)
		return 1;
	while ((mntent = getmntent(file)) != NULL) {
		if(strstr(mntent->mnt_type, ftype)) {
			if (strcmp(mntent->mnt_dir, mntname))
				continue;
			strcpy(devicename, mntent->mnt_fsname);
			if (readlink(devicename, buffer, BUFFER_LEN) != -1) {
				ptr = strrchr(buffer, '/');
			} else {
				ptr = strrchr(devicename, '/');
				errno = 0;
			}
			ptr++;
			devt = get_block_devt(ptr);
			break;	
		}
	}

	endmntent(file);
	if (!devt)
		return 1;
	*dev = devt;
	return 0;
}

static void set_filter(struct xd_ext4fsstat_bpf_c *skel)
{
	int err;
	__u32 dev;
	__u32 filter_enable = 1;
	static struct filter_value value;
	int fd;

	value.flags = 0;
	if (env.filter_mnt && env.mntname) {
		err = get_mntpoint_dev(env.mntname, &dev);
		if (!err) {
			snprintf(mnt_dir, sizeof(mnt_dir), "%s", env.mntname);
			value.flags |= FILTER_DEV;
			value.dev = dev;
		}
	}

	if (env.filter_opcode) {
		value.flags |= FILTER_OPCODE;
		env.sort = env.opcode;
		value.opcode = env.opcode;
	}

	if (env.filter_pid) {
		value.flags |= FILTER_PID;
		value.pid = env.pid;
	}

	if (value.flags) {
		fd =  bpf_map__fd(skel->maps.filter_map);
		bpf_map_update_elem(fd, &filter_enable, &value, 0);
	}
}

static int ext4fsstat_attach_read(struct xd_ext4fsstat_bpf_c *skel)
{
	int err = 0;

	skel->links.bpf__ext4_file_read_iter = 
		bpf_program__attach(skel->progs.bpf__ext4_file_read_iter);
	if (!skel->links.bpf__ext4_file_read_iter) {
		err = -errno;
		fprintf(stderr, "failed to attach ext4 file read %s\n",
			strerror(-err));
	}

	return err;
}

static int ext4fsstat_attach_write(struct xd_ext4fsstat_bpf_c *skel)
{
	int err = 0;
	struct kversion version;

	skel->links.bpf__ext4_file_write_iter = 
		bpf_program__attach(skel->progs.bpf__ext4_file_write_iter);
	if (!skel->links.bpf__ext4_file_write_iter) {
		err = -errno;
		fprintf(stderr, "failed to attach ext4 file write %s\n",
			strerror(-err));
	}

	if (utils_get_kversion(&version)) {
		err = -errno;
		fprintf(stderr, "failed to get kern version.");
		return err;
	}

	if (version.major == 5 && version.minor >= 10) {	
		skel->links.bpf__ext4_writepages_result = 
			bpf_program__attach(skel->progs.bpf__ext4_writepages_result);
		if (!skel->links.bpf__ext4_writepages_result) {
			err = -errno;
			fprintf(stderr, "failed to attach ext4 writepages"
				" result %s\n", strerror(-err));
			return err;
		}
	} else {
		skel->links.bpf__ext4_io_submit = 
			bpf_program__attach(skel->progs.bpf__ext4_io_submit);
		if (!skel->links.bpf__ext4_io_submit) {
			err = -errno;
			fprintf(stderr, "failed to attach ext4 file write %s\n",
				strerror(-err));
			return err;
		}
	}

	return err;
}

static int xd_ext4fstat_progs_attach(struct xd_ext4fsstat_bpf_c *skel)
{
	int err = 0;

	if (env.filter_opcode) {
		err = (env.opcode == FILE_READ)
		      ? ext4fsstat_attach_read(skel)
		      : ext4fsstat_attach_write(skel);
	} else {
		err = ext4fsstat_attach_read(skel);
		err = ext4fsstat_attach_write(skel);	
	}

	return err;
}

static void poll_process_ext4fstat(struct xd_ext4fsstat_bpf_c *skel)
{
	long times = env.times;

	while (running) {
		sleep(env.interval);
		print_ext4fstat(skel);

		if (--times == 0)
			break;
	}
}

int main(int argc, char **argv)
{
	struct xd_ext4fsstat_bpf_c *skel;
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

	signal(SIGINT, sig_hander);
	signal(SIGTERM, sig_hander);

	skel = xd_ext4fsstat_bpf_c__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	err = xd_ext4fsstat_bpf_c__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeltion\n");
		goto cleanup;
	}

	set_filter(skel);
	err = xd_ext4fstat_progs_attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attch BPF skeleton\n");
		goto cleanup;
	}

	printf("Tracing filesystem read/write stat ... Hit Ctrl-C to end.\n\n");;

	/* poll */
	poll_process_ext4fstat(skel);

cleanup:
	xd_ext4fsstat_bpf_c__destroy(skel);
	return err < 0 ? -err : 0;
}	
