/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 */
#ifndef _OOM_SHOW_INFO_H
#define _OOM_SHOW_INFO_H
#ifdef CONFIG_EULEROS_DEBUG_OOM
#include <linux/nodemask.h>
#include <linux/seq_file.h>

extern int sysctl_oom_enhance_enable;
extern int sysctl_oom_print_file_info;
extern int sysctl_oom_show_file_num_in_dir;

extern unsigned long kallsyms_lookup_name(const char *name);
extern void oom_show_debug_info(nodemask_t *nodemask);
extern struct dentry *get_mountpoint_from_mnt_root(struct dentry *dentry);
#endif
#endif
