/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * xd_ext4fsstat licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wubo
 * Create: 2022-11-05
 * Description:Trace ext4 filesystem read/write.
 ******************************************************************************/
#include <common_k.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "xd_ext4fsstat.h"

#define MAX_ENTRIES MAX_EXT4_FILES

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct pid_key);
	__type(value, struct pid_iostat);
} pidstat_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct file_key);
	__type(value, struct file_iostat);
} filestat_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct filter_value);
} filter_map SEC(".maps");

typedef struct ext4_io_end {
	char __pad[24];
	struct inode *inode;
	struct bio *bio;
} ext4_io_end_t;

struct ext4_io_submit {
	__u64 __pad;
	struct bio *io_bio;
	ext4_io_end_t *io_end;
};

struct ext4_writepages_result_format {
	__u64 __do_not_use__; /* First 8 bytes for bpf ctx */
	dev_t dev;
	ino_t ino;
	int ret;
	int pages_written;
};

static int filter_dev_check(dev_t dev)
{
	__u32 filter_enable = 1;
	struct filter_value *valuep;

	valuep = bpf_map_lookup_elem(&filter_map, &filter_enable);
	if (!valuep)
		return 0;

	if (valuep->flags & FILTER_DEV
	    && valuep->dev != dev)
		return 1;
	
	return 0;
}

static int filter_check(enum file_opcode op)
{
	__u32 filter_enable = 1;
	struct filter_value *valuep;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	valuep = bpf_map_lookup_elem(&filter_map, &filter_enable);
	if (!valuep)
		return 0;

	if ((valuep->flags & FILTER_PID)
	    && (valuep->pid != pid || valuep->pid != tid))
		return 1;

	if ((valuep->flags & FILTER_OPCODE)
	    && (valuep->opcode != op))
		return 1;
	return 0;
}

static int create_key(struct inode *inode, struct file_key *fkey,
		      struct pid_key *pkey)
{
	struct super_block *sb;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	sb = (struct super_block *)BPF_PROBE_VAL(inode->i_sb);
	if (!sb)
		return 1;

	fkey->ino = BPF_PROBE_VAL(inode->i_ino);
	fkey->dev = BPF_PROBE_VAL(sb->s_dev);

	pkey->ino = fkey->ino;
	pkey->dev = fkey->dev;
	pkey->pid = pid;
	pkey->tid = tid;

	return 0;
}

static void get_file_name(struct file *file, struct file_iostat *io)
{
	struct qstr dname;
	struct dentry *d,*d1,*d2,*d3;

	d = BPF_PROBE_VAL(file->f_path.dentry);
	bpf_probe_read_kernel(&dname, sizeof(dname), (void*)&d->d_name);
	bpf_probe_read_kernel(&io->filename, sizeof(io->filename), 
			      (void*)dname.name);

	/* d1name */
	d1 = BPF_PROBE_VAL(d->d_parent);
	if (!d1)
		return;
	bpf_probe_read_kernel(&dname, sizeof(dname), (void*)&d1->d_name);
	bpf_probe_read_kernel(&io->d1name, sizeof(io->d1name), 
			     (void*)dname.name);

	/* d2name */
	d2 = BPF_PROBE_VAL(d1->d_parent);
	if (!d2)
		return;
	bpf_probe_read_kernel(&dname, sizeof(dname), (void*)&d2->d_name);
	bpf_probe_read_kernel(&io->d2name, sizeof(io->d2name), 
			     (void*)dname.name);

	/* d3name */
	d3 = BPF_PROBE_VAL(d2->d_parent);
	if (!d3)
		return;
	bpf_probe_read_kernel(&dname, sizeof(dname), (void*)&d3->d_name);
	bpf_probe_read_kernel(&io->d3name, sizeof(io->d3name), 
			     (void*)dname.name);

}

static int update_fileiostat(struct file* file, struct file_key *key,
			     size_t count, enum file_opcode op)
{
	struct file_iostat *io;
	struct file_iostat def_value = {};

	io = bpf_map_lookup_elem(&filestat_map, key);
	if (!io) {
		if (op == FILE_WRITEBACK)
			return 1;
		bpf_map_update_elem(&filestat_map, key, &def_value, 0);
		io = bpf_map_lookup_elem(&filestat_map, key);
		if (!io)
			return 1;
		if (file)
			get_file_name(file, io);
	}

	if (op == FILE_READ) {
		io->read_bytes += count;
	} else if (op == FILE_WRITE) {
		io->write_bytes += count;
	} else {	
		io->writeback_bytes += count;
	}

	return 0;
}

static void update_pidiostat(struct pid_key *key, size_t count,
			     enum file_opcode op)
{
	struct pid_iostat *io;
	struct pid_iostat def_value = {};

	io = bpf_map_lookup_elem(&pidstat_map, key);
	if (!io) {
		bpf_map_update_elem(&pidstat_map, key, &def_value, 0);
		io = bpf_map_lookup_elem(&pidstat_map, key);
		if (!io)
			return;
		io->pid = key->pid;
		io->tid = key->tid;
		io->dev = key->dev;
		io->ino = key->ino;
		bpf_get_current_comm(&io->comm, sizeof(io->comm));
	}

	if (op == FILE_READ) {
		io->reads += 1;
		io->read_bytes += count;
	} else {
		io->writes +=1;
		io->write_bytes += count;
	}
}

static int probe_entry(struct file *file, struct inode *inode,
		       size_t count, enum file_opcode op)
{
	struct file_key fkey = {};
	struct pid_key pkey = {};

	if (create_key(inode, &fkey, &pkey))
		return 0;

	if (filter_dev_check(pkey.dev))
		return 0;

	if (update_fileiostat(file, &fkey, count, op))
		return 0;

	if (op != FILE_WRITEBACK)
		update_pidiostat(&pkey, count, op);

	return 0;
}

SEC("kprobe/ext4_file_read_iter")
int bpf__ext4_file_read_iter(struct pt_regs *ctx)
{
	struct kiocb *iocb;
	struct iov_iter *to;
	struct file *file;
	struct inode *inode;
	size_t count = 0;

	iocb = (struct kiocb *)PT_REGS_PARM1(ctx);
	to = (struct iov_iter *)PT_REGS_PARM2(ctx);

	count = BPF_PROBE_VAL(to->count);
	file = BPF_PROBE_VAL(iocb->ki_filp);

	if (filter_check(FILE_READ))
		return 0;

	inode = (struct inode *)BPF_PROBE_VAL(file->f_inode);
	if (!inode)
		return 0;

	return probe_entry(file, inode, count, FILE_READ);
}

SEC("kprobe/ext4_file_write_iter")
int bpf__ext4_file_write_iter(struct pt_regs *ctx)
{
	struct kiocb *iocb;
	struct iov_iter *from;
	struct file *file;
	struct inode *inode;
	size_t count = 0;

	iocb = (struct kiocb *)PT_REGS_PARM1(ctx);
	from = (struct iov_iter *)PT_REGS_PARM2(ctx);

	count = BPF_PROBE_VAL(from->count);
	file = BPF_PROBE_VAL(iocb->ki_filp);

	if (filter_check(FILE_WRITE))
		return 0;

	inode = (struct inode *)BPF_PROBE_VAL(file->f_inode);
	if (!inode || !count)
		return 0;

	return probe_entry(file, inode, count, FILE_WRITE);
}

SEC("kprobe/ext4_io_submit")
int bpf__ext4_io_submit(struct pt_regs *ctx)
{
	struct ext4_io_submit *io;
	struct bio *bio;
	struct inode *inode;
	size_t count = 0;
	struct ext4_io_end *io_end;

	io = (struct ext4_io_submit *)PT_REGS_PARM1(ctx);
	bio = BPF_PROBE_VAL(io->io_bio);
	if (!bio)
		return 0;

	io_end = BPF_PROBE_VAL(io->io_end);
	if (!io_end)
		return 0;

	inode = BPF_PROBE_VAL(io_end->inode);
	count = BPF_PROBE_VAL(bio->bi_iter.bi_size);

	if (!count || !inode)
		return 0;

	return probe_entry(NULL, inode, count, FILE_WRITEBACK);
}

SEC("tracepoint/ext4/ext4_writepages_result")
int bpf__ext4_writepages_result(void *ctx)
{
	struct pid_key pkey = {};
	struct file_key fkey = {};
	size_t count;

	struct ext4_writepages_result_format *c = 
		(struct ext4_writepages_result_format*)ctx;

	if (!c->pages_written)
		return 0;
	fkey.ino = c->ino;
	fkey.dev = c->dev;

	if (filter_dev_check(fkey.dev))
		return 0;
	count = c->pages_written * 4096;
	update_fileiostat(NULL, &fkey, count, FILE_WRITEBACK);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
