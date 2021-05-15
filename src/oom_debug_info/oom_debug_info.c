// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. ALL rights reversed.
 */

#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/hugetlb.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/nmi.h>
#include <linux/oom.h>
#include <linux/printk.h>
#include <linux/rwsem.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/seq_file.h>
#include <linux/swap.h>
#ifdef CONFIG_CMA
#include <linux/cma.h>
#endif
#include <../fs/mount.h>
#include <../mm/slab.h>

#include "oom_debug_info.h"

#define TMP_FS_ID 1
#define FILE_PATH_BUF_SIZE 1024
#define MAX_PRINT_STR_SIZE 1024
#define SHOW_FILE_NUM_IN_DIR 1024
#define RECURSE_DEPTH_LIMIT 50
#define FILE_NUM_MDELAY_FOR_LOG 1000
#define MAX_PRINT_FILE_INFO_BYTES (2 * 1024 * 1024UL)
#define MAX_BUF_LEN 256

int sysctl_oom_enhance_enable = 1;
int sysctl_oom_print_file_info = 1;
int sysctl_oom_show_file_num_in_dir = 10;

static atomic_t console_silent_atomic = ATOMIC_INIT(0);
static atomic_t dentry_tree_running = ATOMIC_INIT(0);
static char file_path_buf[FILE_PATH_BUF_SIZE];
static char str_print[MAX_PRINT_STR_SIZE];
static unsigned long min_heap[SHOW_FILE_NUM_IN_DIR];
static unsigned int fs_id;
static char *mount_path[] = {
	"",
	"/tmp",
};

static unsigned long show_file_num;
static unsigned long print_file_info_bytes;

static const char *task_state_Array[] = {
	"R (running)",		/*      0 */
	"S (sleeping)",		/*      1 */
	"D (disk sleep)",	/*      2 */
	"T (stopped)",		/*      4 */
	"T (tracing stop)",	/*      8 */
	"Z (zombie)",		/* 16 */
	"X (dead)"		/* 32 */
};

/* get_task_state() */
#ifndef TASK_REPORT
#define TASK_REPORT (TASK_RUNNING | TASK_INTERRUPTIBLE |     \
		     TASK_UNINTERRUPTIBLE | __TASK_STOPPED | \
		     __TASK_TRACED)
#endif

static struct ctl_table_header *debug_table_header;

static struct ctl_table debug_kernel_table[] = {
	{
	 .procname = "oom_enhance_enable",
	 .data = &sysctl_oom_enhance_enable,
	 .maxlen = sizeof(int),
	 .mode = 0640,
	 .proc_handler = proc_dointvec_minmax,
	 },
	{
	 .procname = "oom_print_file_info",
	 .data = &sysctl_oom_print_file_info,
	 .maxlen = sizeof(int),
	 .mode = 0640,
	 .proc_handler = proc_dointvec_minmax,
	 },
	{
	 .procname = "oom_show_file_num_in_dir",
	 .data = &sysctl_oom_show_file_num_in_dir,
	 .maxlen = sizeof(int),
	 .mode = 0640,
	 .proc_handler = proc_dointvec_minmax,
	 },
	{}
};

static struct ctl_table debug_root_table[] = {
	{
	 .procname = "kernel",
	 .mode = 0555,
	 .child = debug_kernel_table,
	 },
	{}
};

// TODO: compat to kernel-5.10

static struct rw_semaphore *k_namespace_sem = NULL;
static rwlock_t *k_tasklist_lock = NULL;

typedef void (*show_mem_fn)(unsigned int, nodemask_t *);
show_mem_fn k_show_mem = NULL;

typedef void (*iterate_supers_fn)(void (*)(struct super_block *, void *), void *);
iterate_supers_fn k_iterate_supers = NULL;

typedef void (*hugetlb_report_meminfo_fn)(struct seq_file *);
hugetlb_report_meminfo_fn k_hugetlb_report_meminfo = NULL;

static int last_console_printk = 0;
static int *k_console_printk = NULL;

static inline void _console_silent(void)
{
	last_console_printk = *k_console_printk;
	*k_console_printk = CONSOLE_LOGLEVEL_SILENT;
}

static inline void _console_resume(void)
{
	*k_console_printk = last_console_printk;
}

static int init_kernel_sym(void)
{
	k_namespace_sem = (struct rw_semaphore *) kallsyms_lookup_name("namespace_sem");

	k_tasklist_lock = (rwlock_t *) kallsyms_lookup_name("tasklist_lock");
	if (!k_tasklist_lock) {
		printk(KERN_WARNING "tasklist_lock is not found\n");
		return -1;
	}

	k_console_printk = (int*) kallsyms_lookup_name("console_printk");
	if (!k_console_printk) {
		printk(KERN_WARNING "console_printk is not found\n");
		return -1;
	}

	k_show_mem = (show_mem_fn) kallsyms_lookup_name("show_mem");
	if (!k_show_mem) {
		printk(KERN_WARNING "show_mem is not found\n");
		return -1;
	}

	k_iterate_supers = (iterate_supers_fn) kallsyms_lookup_name("iterate_supers");
	if (!k_iterate_supers) {
		printk(KERN_WARNING "iterate_supers is not found\n");
		return -1;
	}

	k_hugetlb_report_meminfo = (hugetlb_report_meminfo_fn) kallsyms_lookup_name("hugetlb_report_meminfo");
	if (!k_hugetlb_report_meminfo) {
		printk(KERN_WARNING "hugetlb_report_meminfo is not found\n");
		return -1;
	}

	return 0;
}

static struct dentry *get_mountpoint_from_mnt_root(struct dentry *dentry)
{
	struct mnt_namespace *ns = current->nsproxy->mnt_ns;
	struct mount *mnt;
	struct dentry *mount_point = NULL;

	if (IS_ERR_OR_NULL(dentry) || strncmp(dentry->d_iname, "/", sizeof("/")))
		goto out;

	if (!k_namespace_sem) {
		printk(KERN_WARNING "k_namespace_sem is NULL\n");
		return NULL;
	}

	if (!down_read_trylock(k_namespace_sem)) {
		printk(KERN_WARNING "get namespace_sem fail when get mountpoint from mnt_root!\n");
		return NULL;
	}

	list_for_each_entry(mnt, &ns->list, mnt_list) {
		if (mnt->mnt.mnt_root == dentry) {
			mount_point = mnt->mnt_mountpoint;
			break;
		}
	}
	up_read(k_namespace_sem);
out:
	return mount_point;
}

static int show_proc_slab_info(void)
{
// TODO: read file /proc/slabinfo
	return 0;
}

static int show_proc_mem_info(void)
{
// TODO:  read file /proc/meminfo
	return 0;
}

/*
 * get string of task status according to stat of task_struct.
 */
static inline const char *oom_get_task_state(struct task_struct *tsk)
{
	unsigned int state = (tsk->state & TASK_REPORT) | tsk->exit_state;
	const char **p = &task_state_Array[0];

	while (state) {
		p++;
		state >>= 1;
	}
	return *p;
}

/*
 * refer to ps -aux, show task info for debug.
 */
static int show_ps_aux_info(void)
{
	struct task_struct *p;

	printk(KERN_WARNING "%5s %5s %20s %8s %8s %16s\n", "PID", "PPID", "VSZ", "RSS", "STAT", "COMMAND");
	read_lock(k_tasklist_lock);
	for_each_process(p) {
		printk(KERN_WARNING "%5d %5d %7luK %7luK %16s %s\n", p->pid,
		       p->parent->pid,
		       (p->mm != NULL ? p->mm->total_vm : 0) * 4,
		       (p->mm != NULL ? get_mm_rss(p->mm) : 0) * 4, oom_get_task_state(p), p->comm);
	}
	read_unlock(k_tasklist_lock);
	return 0;
}

static char *get_file_path(struct dentry *dentry)
{
	/* for placing '\0' at end */
	int byte_left = FILE_PATH_BUF_SIZE - 2;
	int name_len;

	memset(file_path_buf, 0, FILE_PATH_BUF_SIZE);

	while (dentry && (strncmp(dentry->d_name.name, "/", 1) != 0)) {
		name_len = strlen(dentry->d_name.name);
		if (byte_left <= name_len) {
			printk(KERN_WARNING "file name too long ...");
			break;
		}

		byte_left -= name_len;
		memcpy(file_path_buf + byte_left, dentry->d_name.name, name_len);
		byte_left--;
		file_path_buf[byte_left] = '/';
		dentry = dentry->d_parent;
	}

	return file_path_buf + byte_left;
}

static bool is_empty_dir(struct dentry *dir)
{
	struct dentry *dentry = NULL;

	if (!d_is_dir(dir))
		return false;

	if (list_empty(&dir->d_subdirs))
		return true;

	spin_lock(&dir->d_lock);
	list_for_each_entry(dentry, &dir->d_subdirs, d_child) {
		if (dentry == NULL || dentry->d_inode == NULL)
			continue;
		if (d_is_file(dentry) && dentry->d_inode->i_size > 0) {
			spin_unlock(&dir->d_lock);
			return false;
		}
		if (d_is_dir(dentry) && !is_empty_dir(dentry)) {
			spin_unlock(&dir->d_lock);
			return false;
		}
	}
	spin_unlock(&dir->d_lock);
	return true;
}

static void my_swap(unsigned long *a, int i, int j)
{
	unsigned long temp = a[i];

	a[i] = a[j];
	a[j] = temp;
}

static void heap_adjust(unsigned long *a, int n, int i)
{
	int j = 2 * i + 1;

	while (j < n) {
		if (j + 1 < n && a[j] > a[j + 1])
			j++;
		if (a[i] > a[j])
			my_swap(a, i, j);
		else
			break;
		i = j;
		j = 2 * i + 1;
	}
}

static void heap_build(unsigned long *a, int n)
{
	int i;

	for (i = n / 2 - 1; i >= 0; i--)
		heap_adjust(a, n, i);
}

static unsigned long get_topn_size_in_dir(struct dentry *dir, unsigned int *file_num)
{
	struct dentry *dentry = NULL;
	unsigned long topn_size = 0;

	*file_num = 0;
	memset(min_heap, 0, sizeof(min_heap));

	spin_lock(&dir->d_lock);
	list_for_each_entry(dentry, &dir->d_subdirs, d_child) {
		if (dentry == NULL || dentry->d_inode == NULL)
			continue;
		if (d_is_file(dentry)) {
			(*file_num)++;
			if (*file_num < sysctl_oom_show_file_num_in_dir) {
				min_heap[*file_num - 1] = dentry->d_inode->i_size;
			} else if (*file_num == sysctl_oom_show_file_num_in_dir) {
				min_heap[*file_num - 1] = dentry->d_inode->i_size;
				heap_build(min_heap, sysctl_oom_show_file_num_in_dir);
			} else if (*file_num > sysctl_oom_show_file_num_in_dir) {
				if (dentry->d_inode->i_size > min_heap[0]) {
					min_heap[0] = dentry->d_inode->i_size;
					heap_adjust(min_heap, sysctl_oom_show_file_num_in_dir, 0);
				}
			}
		}
	}
	spin_unlock(&dir->d_lock);

	if (*file_num > sysctl_oom_show_file_num_in_dir)
		topn_size = min_heap[0];
	return topn_size;
}

static unsigned long do_show_dentry_tree(struct dentry *tree, unsigned int depth)
{
	struct dentry *dentry = NULL;
	unsigned long topn_size;
	unsigned long dir_size = 0;
	unsigned long subdir_size;
	unsigned int file_num;
	int num_chars;

	if (print_file_info_bytes > MAX_PRINT_FILE_INFO_BYTES) {
		printk(KERN_WARNING "file info exceed %lu bytes!\n", MAX_PRINT_FILE_INFO_BYTES);
		return 0;
	}

	if (depth >= RECURSE_DEPTH_LIMIT) {
		printk(KERN_WARNING "dir depth exceed %d!\n", RECURSE_DEPTH_LIMIT);
		return 0;
	}

	/* get topN file size in dir */
	topn_size = get_topn_size_in_dir(tree, &file_num);

	spin_lock(&tree->d_lock);
	/* ramfs and tmpfs will "pin the dentry in core",
	 * so we can iterate all files in root initramfs(tmpfs) by dentry.
	 */
	list_for_each_entry(dentry, &tree->d_subdirs, d_child) {
		if (dentry == NULL || dentry->d_inode == NULL)
			continue;
		if (dentry->d_inode->i_size == 0)
			continue;
		if (d_is_symlink(dentry))
			continue;
		if (d_is_file(dentry)) {
			if (dentry->d_inode->i_size >= topn_size) {
				num_chars = snprintf(str_print,
						     MAX_PRINT_STR_SIZE, "%s:%llu\n",
						     dentry->d_name.name, dentry->d_inode->i_size);
				if (num_chars > 0)
					print_file_info_bytes += num_chars;
				printk(KERN_CONT "%s", str_print);
				show_file_num++;
			}
			if (show_file_num % FILE_NUM_MDELAY_FOR_LOG == 0) {
				num_chars = snprintf(str_print, MAX_PRINT_STR_SIZE,
						     "already printed %lu files, will mdelay 10 ms for log system.\n",
						     show_file_num);
				if (num_chars > 0)
					print_file_info_bytes += num_chars;
				printk(KERN_CONT "%s", str_print);
				touch_nmi_watchdog();
				mdelay(10);
			}
			dir_size += dentry->d_inode->i_size;
		}
	}
	/* second iterate list for showing subdirs after showing files */
	list_for_each_entry(dentry, &tree->d_subdirs, d_child) {
		if (dentry == NULL || dentry->d_inode == NULL)
			continue;
		/* 1.we use d_mountpoint to skip mountpoint, but
		 * auditd mounted /usr/lib/modules to itself process space,
		 * it will lead to skip this dir in memory rootfs by mistake.
		 * 2.you can fix it by all inodes have same super block in same
		 * file system, pity that all inodes have same super block in
		 * root initramfs(tmpfs) when unpack, lead to it cann`t work by
		 * dentry iterate, although you can get distinguished
		 * inode->i_sb->s_dev by name lookup, refer to vfs_lstat to get
		 * stat.dev, but it shouldn`t sched or alloc when oom.
		 * 3.you also can fix it by refer to is_local_mountpoint,
		 * notice down_read may sleep and up_read call wake_up_process
		 * when hold d_lock, use down_read_trylock and call
		 * local_irq_save and preempt_disable preempt_enable_no_resched
		 * to ensure safe.
		 * 4.we handle it in simple way, treat as mountpoint is empty
		 * dir in initramfs.
		 */
		if (is_empty_dir(dentry))
			continue;
		if (d_is_dir(dentry)) {
			num_chars = snprintf(str_print, MAX_PRINT_STR_SIZE,
					     "%s%s\n", mount_path[fs_id], get_file_path(dentry));
			if (num_chars > 0)
				print_file_info_bytes += num_chars;
			printk(KERN_CONT "%s", str_print);
			subdir_size = do_show_dentry_tree(dentry, depth + 1);
			if (subdir_size > 0) {
				num_chars = snprintf(str_print,
						     MAX_PRINT_STR_SIZE, "dir %s%s:%lu\n",
						     mount_path[fs_id], get_file_path(dentry), subdir_size);
				if (num_chars > 0)
					print_file_info_bytes += num_chars;
				printk(KERN_CONT "%s", str_print);
				dir_size += subdir_size;
			}
		}
	}
	spin_unlock(&tree->d_lock);

	if (topn_size > 0) {
		num_chars = snprintf(str_print, MAX_PRINT_STR_SIZE, "...files num:%d\n", file_num);
		if (num_chars > 0)
			print_file_info_bytes += num_chars;
		printk(KERN_CONT "%s", str_print);
	}

	return dir_size;
}

static void show_dentry_tree(struct dentry *tree)
{
	unsigned long dir_size;

	if (IS_ERR_OR_NULL(tree))
		return;
	printk(KERN_WARNING "%s%s\n", mount_path[fs_id], tree->d_iname);
	dir_size = do_show_dentry_tree(tree, 0);
	printk(KERN_WARNING "%lu bytes in %s%s\n", dir_size, mount_path[fs_id], tree->d_iname);
}

static void show_file_info_by_name(struct super_block *sb, void *name)
{
	struct dentry *mount_point = NULL;

	if (strncmp(sb->s_type->name, name, strlen(name)))
		return;

	if (!strncmp(name, "rootfs", strlen(name))) {
		fs_id = 0;
		show_dentry_tree(sb->s_root);
	} else if (!strncmp(name, "tmpfs", strlen(name))) {
		/* get mount_point of mnt_root, I have no better way than refer
		 * to is_local_mountpoint, notice down_read may sleep and
		 * up_read call wake_up_process, use down_read_trylock and
		 * call preempt_disable preempt_enable_no_resched.
		 */
		mount_point = get_mountpoint_from_mnt_root(sb->s_root);
		if (!strncmp(get_file_path(mount_point), "/tmp", sizeof("/tmp"))
		    && !strncmp(mount_point->d_sb->s_type->name, "rootfs", sizeof("rootfs"))) {
			printk(KERN_WARNING "###################\n");
			printk(KERN_WARNING "show files in /tmp:\n");
			fs_id = TMP_FS_ID;
			show_dentry_tree(sb->s_root);
		}
	}
}

void show_rootfs_info(void)
{
	printk(KERN_WARNING "rootfs file info:\n");
	k_iterate_supers(show_file_info_by_name, "rootfs");
}

void show_tmpfs_info(void)
{
	k_iterate_supers(show_file_info_by_name, "tmpfs");
}

void show_memfs_info(void)
{
	if (!sysctl_oom_print_file_info)
		return;

	if (atomic_cmpxchg(&dentry_tree_running, 0, 1))
		return;
	print_file_info_bytes = 0;
	show_file_num = 0;
	show_rootfs_info();
	show_tmpfs_info();
	atomic_set(&dentry_tree_running, 0);
}

void oom_show_debug_info(void)
{
	typedef int (*ivpfn) (void);
	ivpfn show_pfn_memory_info = NULL;

	if (atomic_cmpxchg(&console_silent_atomic, 0, 1) == 1) {
		mdelay(500);
		return;
	}

	dump_stack();

	/* print the use info of all memory */
	show_pfn_memory_info = (ivpfn) kallsyms_lookup_name("MEM_PrintAllMemory");
	if (show_pfn_memory_info != NULL) {
		printk(KERN_EMERG "\nmem trace:\n");
		show_pfn_memory_info();
	} else {
		printk(KERN_EMERG "error, MEM_PrintAllMemory is NULL!\n");
	}

	/* print slab info */
	printk(KERN_EMERG "\nslab info:\n");
	show_proc_slab_info();

	/* print mem info */
	printk(KERN_EMERG "\nmem info:\n");
	show_proc_mem_info();

	/* silent console for console print too slow */
	_console_silent();
	/* print the info of current process */
	printk(KERN_EMERG "ps -aux:\n");
	show_ps_aux_info();
	_console_resume();

	/* print mem */
	k_show_mem(0, NULL);

	/* silent console for console print too slow */
	_console_silent();
	show_memfs_info();
	_console_resume();

	atomic_set(&console_silent_atomic, 0);
}

static int debug_oom_notify(struct notifier_block *self, unsigned long notused, void *nfreed)
{
	if (sysctl_oom_enhance_enable)
		oom_show_debug_info();
	return 0;
}

static struct notifier_block debug_oom_nb = {
	.notifier_call = debug_oom_notify
};

static int __init oom_debug_info_init(void)
{
	int ret;

	printk("oom_debug_info init\n");

	ret = init_kernel_sym();
	if (ret) {
		return ret;
	}

	ret = register_oom_notifier(&debug_oom_nb);
	if (ret) {
		printk("register_oom_notifier fail\n");
		return ret;
	}

	debug_table_header = register_sysctl_table(debug_root_table);
	if (!debug_table_header) {
		printk("register_sysctl_table fail\n");
		ret = -ENOMEM;
		goto sysctl_fail;
	}

	return 0;

sysctl_fail:
	unregister_oom_notifier(&debug_oom_nb);
	return ret;
}

static void __exit oom_debug_info_exit(void)
{
	printk("oom_debug_info exit\n");
	unregister_oom_notifier(&debug_oom_nb);
	unregister_sysctl_table(debug_table_header);
}

module_init(oom_debug_info_init)
module_exit(oom_debug_info_exit)

MODULE_LICENSE("GPL");
