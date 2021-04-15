#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# cpuload   Display top N tasks use more than U percent cpu resource when
#           the cpu doesn't enter idle state for more than T ms.
#
# USAGE: cpuload [-h] [-t time] [-n number] [-p percent_limit] [-m max_entry]
#
# This uses in-kernel eBPF maps to cache task details (PID and comm) by
# sched_switch, as well as a running time for calculating cpu usage.
#
# Licensed under the Apache License, Version 2.0 (the "License")
# Copyright (C) 2021 Huawei Technologies Co., Ltd.

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import argparse
from datetime import datetime

# arguments
examples = """examples:
    ./cpuload                # display tasks when cpu overload
    ./cpuload -t 100         # calculate cpu usage every 100 ms
    ./cpuload -n 5           # display top 5 tasks details
    ./cpuload -p 30          # display tasks when cpu usage exceeds 30%
    ./cpuload -m 10000       # set the maximum number of entry to 10,000
"""
parser = argparse.ArgumentParser(
    description="display tasks when cpu overload",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--time", default=1000,
    help="interval for calculating the CPU usage, in milliseconds(0 - 60000), default 1000")
parser.add_argument("-n", "--number", default=3,
    help="display top n tasks with high cpu usage, default 3")
parser.add_argument("-p", "--percent_limit", default=90,
    help="display when the usage of a cpu exceeds percent_limit(0 - 100), default 90")
parser.add_argument("-m", "--max_entry", default=10000,
    help="size of the cyclic buffer for recording the scheduling track(1000 - 1000000), default 10000")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
time_ms = int(args.time)
time_ns = time_ms * 1000000
number = int(args.number)
percent_limit = int(args.percent_limit)
max_entry = int(args.max_entry)
debug = 0

if time_ms > 60000 or time_ms < 0:
    print("time invalid")
    exit(1)

if percent_limit > 100 or percent_limit < 0:
    print("percent_limit invalid")
    exit(1)

if max_entry > 1000000 or max_entry < 1000:
    print("max_entry invalid")
    exit(1)

# define BPF program
bpf_text = """
#include <linux/sched.h>

#define MAX_TIME """ + str(time_ns) + """
#define THRESHOLD """ + str(percent_limit) + """
#define MAX_ENTRY """ + str(max_entry) + """

struct cpu_data_t {
    u32 index;
    u32 number;
    u64 prev_time;
    u64 busy_time;
    u64 total_time;
};

struct task_data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u64 delta;
};

struct data_t {
    u32 index;
    u32 number;
    u64 total_time;
};

BPF_PERCPU_ARRAY(cpu_data, struct cpu_data_t, 1);

BPF_PERCPU_ARRAY(task_data, struct task_data_t, MAX_ENTRY);

BPF_PERF_OUTPUT(events);
TRACEPOINT_PROBE(sched, sched_switch) {
    u32 index = 0;
    u64 now = bpf_ktime_get_ns(), delta;
    struct data_t data = {};
    struct cpu_data_t *cpu = cpu_data.lookup(&index);
    struct task_data_t *task;

    if (cpu == NULL)
        return 0;

    if (cpu->prev_time == 0) {
        cpu->prev_time = now;
        return 0;
    }

    index = (cpu->index + cpu->number) % MAX_ENTRY;
    task = task_data.lookup(&index);
    if (task == NULL)
        return 0;

    delta = now - cpu->prev_time;
    if (args->prev_pid != 0) {
        cpu->busy_time += delta;
        task->pid = args->prev_pid;
        __builtin_memcpy(&task->comm, &args->prev_comm, sizeof(task->comm));
        task->delta = now - cpu->prev_time;
        cpu->number++;
    }

    cpu->prev_time = now;
    cpu->total_time += delta;

    if (cpu->total_time > MAX_TIME || cpu->number == MAX_ENTRY) {
        if (cpu->busy_time * 100 > cpu->total_time * THRESHOLD) {
            data.index = cpu->index;
            data.number = cpu->number;
            data.total_time = cpu->total_time;
            events.perf_submit(args, &data, sizeof(data));
            cpu->index = (index + 1) % MAX_ENTRY;
        }
        cpu->number = 0;
        cpu->busy_time = 0;
        cpu->total_time = 0;
        cpu->prev_time = now;
    }

    return 0;
}
"""

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)

print("Tracing task switch. Output when cpu is overload. Ctrl-C to end.")

print("%-19s %-14s %-7s %-4s %-8s %-5s" %
        ("DATE", "COMM", "PID", "CPU", "TIME(ms)", "%CPU"))

# process event
def print_event(cpu, data, size):
    date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    data = b["events"].event(data)
    dic = {}
    tasks = b["task_data"]
    if data.total_time < time_ns:
        print("max_entry is too small, please set more than %d" %
            (max_entry * time_ns / data.total_time))
    for i in range(data.index, data.number + data.index):
        task = tasks[i % max_entry][cpu]
        entry = dic.get(task.pid)
        if entry is not None:
            entry.delta += task.delta
        else:
            dic[task.pid] = task

    count = 0
    for item in sorted(dic.items(), key=lambda x: x[1].delta, reverse=True):
        if count >= number:
            break
        task = item[1]
        u = task.delta * 100 / data.total_time
        print("%s %-14.14s %-7s %-4s %-8.3f %05.2f%%" % (
            date,
            task.comm.decode("utf-8", "replace"),
            task.pid,
            cpu,
            float(task.delta) / 1000000,
            u))
        count += 1
    dic.clear()
    print("---------------------------------------------------------------")

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
