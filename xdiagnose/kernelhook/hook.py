#!/usr/bin/env python
# coding: utf-8

import sys
import os
import re
import signal
import subprocess
from socket import inet_ntop, htons, inet_pton, AF_INET6, ntohl, AF_INET
from struct import unpack, pack
from xdiagnose.cmdfile.eftrace import parse_multi_cmds


# enum {
#   NFPROTO_UNSPEC =  0,
#   NFPROTO_INET   =  1,
#   NFPROTO_IPV4   =  2,
#   NFPROTO_ARP    =  3,
#   NFPROTO_NETDEV =  5,
#   NFPROTO_BRIDGE =  7,
#   NFPROTO_IPV6   = 10,
#   NFPROTO_DECNET = 12,
#   NFPROTO_NUMPROTO,
# };
# enum nf_inet_hooks {
#   NF_INET_PRE_ROUTING,
#   NF_INET_LOCAL_IN,
#   NF_INET_FORWARD,
#   NF_INET_LOCAL_OUT,
#   NF_INET_POST_ROUTING,
#   NF_INET_NUMHOOKS
# };

# v3: 3.10内核
# v4: 3.10以上内核版本

VERSION_3 = 0   # 3.10内核
VERSION_4 = 1   # 4.x内核
VERSION_5 = 2   # 5.10内核

NF_HOOKS = 18
nf_hook_func_cmd = ['',
                    'hook%d_func%d=(struct nf_hook_entries)((struct netns_nf *)((struct net *)(%%r0->dev->nd_net)->nf+%d).hooks_ipv4+%d)->hooks ',
                    'hook%d_func%d=(struct nf_hook_entries)((struct netns_nf *)((struct net *)(%%r0->dev->nd_net)->nf+%d).hooks_ipv4+%d)->hooks ']

nf_hook_num_cmd = ['hookhead%d=@%s ',
                   'num%d=(struct netns_nf *)((struct net *)(%%r0->dev->nd_net)->nf+%d).hooks_ipv4->num_hook_entries ',
                   'num%d=(struct netns_nf *)((struct net *)(%%r0->dev->nd_net)->nf+%d).hooks_ipv4->num_hook_entries ']

# 5.10使用的函数
ftrace_func_5_10 = ['ip_rcv_core',
                    'ip_local_deliver',
                    'nf_hook_slow']

# 3.10 4.x使用的函数
ftrace_func = ['ip_rcv',
               'netif_receive_skb_internal',
               'ip_local_deliver',
               '__netif_receive_skb_core',
               'nf_hook_slow']

ftrace_dev = ['devname=+0x0(+0x20(%%di)):string ',
              'devname=%%r0->dev->name ',
              'devname=%%r0->dev->name ']

ftrace_ip = ['srcip=+0xc(+0xe8(%%di)):u32 dstip=+0x10(+0xe8(%%di)):u32 ',
             'srcip=(struct iphdr*)(%%r0->data)->saddr dstip=(struct iphdr*)(%%r0->data)->daddr  ',
             'srcip=(struct iphdr*)(%%r0->data)->saddr dstip=(struct iphdr*)(%%r0->data)->daddr  ']

GET_HOOK_CMD = ["echo 'p:FUNC FUNC DEV IP %s ' >> /sys/kernel/debug/tracing/kprobe_events",
                'p:FUNC FUNC DEV IP %s ',
                'p:FUNC FUNC DEV IP %s ']


FTRACE_CMD_FILTER_DEV = '(devname==\"%s\")'
FTRACE_CMD_FILTER_IP = '(srcip==%s || dstip==%s)'
FTRACE_CMD_FILTER_CMD = "echo '%s' > /sys/kernel/debug/tracing/events/kprobes/filter"

hook_index_to_list = {}
devname = ''
host = ''

hook_name = ["NFPROTO_IPV4     NF_INET_PRE_ROUTING   ",
             "NFPROTO_IPV4     NF_INET_LOCAL_IN      ",
             "NFPROTO_IPV4     NF_INET_FORWARD       ",
             "NFPROTO_IPV4     NF_INET_LOCAL_OUT     ",
             "NFPROTO_IPV4     NF_INET_POST_ROUTING  ",
             "NFPROTO_IPV6     NF_INET_PRE_ROUTING   ",
             "NFPROTO_IPV6     NF_INET_LOCAL_IN      ",
             "NFPROTO_IPV6     NF_INET_FORWARD       ",
             "NFPROTO_IPV6     NF_INET_LOCAL_OUT     ",
             "NFPROTO_IPV6     NF_INET_POST_ROUTING  ",
             "NFPROTO_ARP      NF_ARP_IN             ",
             "NFPROTO_ARP      NF_ARP_OUT            ",
             "NFPROTO_ARP      NF_ARP_FORWARD        ",
             "NFPROTO_BRIDGE   NF_INET_PRE_ROUTING   ",
             "NFPROTO_BRIDGE   NF_INET_LOCAL_IN      ",
             "NFPROTO_BRIDGE   NF_INET_FORWARD       ",
             "NFPROTO_BRIDGE   NF_INET_LOCAL_OUT     ",
             "NFPROTO_BRIDGE   NF_INET_POST_ROUTING  "
             ]

class HookModule(object):
    def __init__(self, args):
        self.args = args

    def run(self):
        main()

    def clear(self):
        pass

    def stop(self):
        pass


def is_arp_exist():
    ret = subprocess.run('grep arptable_filter /proc/kallsyms', shell=True,
                           stdout=subprocess.PIPE)
    if ret.returncode == 0:
        return True
    else:
        return False

def get_trace(num):
    trace_dict = {}
    with open('/sys/kernel/debug/tracing/trace_pipe', 'r') as fd:
        while True:
            line = fd.readline()
            if re.search(r'\ (\w+)\:', line):
                funcname = re.search(r'\ (\w+)\:', line).group(1)
                if funcname and funcname not in trace_dict:
                    trace_dict[funcname] = line

            if len(trace_dict) >= num:
                return trace_dict


def set_trace(cmdline, version):
    try:
        # 拼装kprobe命令
        lines = get_trace_cmd(cmdline, version)

        # os.system('echo 0 > /sys/kernel/debug/tracing/events/kprobes/enable')
        os.system('echo nop > /sys/kernel/debug/tracing/current_tracer')
        os.system('echo >  /sys/kernel/debug/tracing/kprobe_events')
        os.system('echo >  /sys/kernel/debug/tracing/trace')
        # print(lines)
        for line in lines:
            os.system(line)
        if devname or host:
            if devname:
                filter = FTRACE_CMD_FILTER_DEV % devname
                if host:
                    filter += ' && ' + FTRACE_CMD_FILTER_IP % (host, host)
            else:
                filter = FTRACE_CMD_FILTER_IP % (host, host)
            # print(FTRACE_CMD_FILTER_CMD % filter)
            os.system(FTRACE_CMD_FILTER_CMD % filter)

        os.system('echo 1 > /sys/kernel/debug/tracing/events/kprobes/enable')
        os.system('echo 1 > /sys/kernel/debug/tracing/tracing_on')

        # 获取trace日志
        trace_dict = get_trace(len(lines))

        os.system('echo 0 > /sys/kernel/debug/tracing/events/kprobes/enable')
        os.system('echo nop > /sys/kernel/debug/tracing/current_tracer')
        os.system('echo >  /sys/kernel/debug/tracing/kprobe_events')
        os.system('echo >  /sys/kernel/debug/tracing/trace')

        trace = ''
        for v in trace_dict.values():
            trace += v
        return trace

    except Exception as e:
        print('set_trace has an error.', e)


def get_kallsyms(sym):
    ret = subprocess.Popen('cat /proc/kallsyms | grep "%s"' % sym, shell=True,
                           stdout=subprocess.PIPE)
    data = ret.stdout.readlines()
    ret.stdout.close()
    return data


# 信号处理程序
def sigint_handler(signum, frame):
    os.system('echo 0 > /sys/kernel/debug/tracing/events/kprobes/enable')
    os.system('echo >  /sys/kernel/debug/tracing/kprobe_events')
    exit()


def get_trace_cmd(cmdline, version):
    try:
        #global ftrace_func
        lines = []
        trace_cmd = []
        lens = len(cmdline)
        cmd_len = len(ftrace_func)
        start = i = 0
        trace_func = ftrace_func_5_10 if version == VERSION_5 else ftrace_func
        # GET_HOOK_CMD = "echo 'p:FUNC FUNC DEV IP %s ' >> /sys/kernel/debug/tracing/kprobe_events"
        while start < lens and i < cmd_len:
            kprobe_cmd = GET_HOOK_CMD[version].replace('FUNC', trace_func[i])
            kprobe_cmd = kprobe_cmd.replace('DEV', ftrace_dev[version] if devname else ' ')
            kprobe_cmd = kprobe_cmd.replace('IP', ftrace_ip[version] if host else ' ')
            if start + 60 >= lens or i == cmd_len - 1:
                lines.append(kprobe_cmd % ("".join(cmdline[start:])))
            else:
                lines.append(kprobe_cmd % ("".join(cmdline[start:start + 60])))
            
            if version == VERSION_4 or version == VERSION_5:
                tmp = parse_multi_cmds(lines[i])
                trace_cmd.append(tmp[0])
            start += 60
            i += 1

        return trace_cmd if version != VERSION_3 else lines
    except Exception as e:
        print('get_trace_cmd has an error.', e)


def get_trace_v3_big(nf_hook_nums):
    try:
        # 获取各hook函数的cmd
        cmdline = []
        for k, v in enumerate(nf_hook_nums):
            if v != -1:
                continue
            # nf_hook_num_cmd_r7 = 'hookhead%d=@0x%x '
            cmdline.append(nf_hook_num_cmd[VERSION_3] % (k, hook_index_to_list[i][0]))

            funccmd = 'hook%d_func%d=+0x10(%s):u64 '
            nextcmd = 'hook%d_func%d_next=+0x0(%s):u64 '
            addr = '@' + hook_index_to_list[k][0]
            for j in range(32):
                func_cmd = funccmd % (k, j, addr)
                next_cmd = nextcmd % (k, j, addr)
                cmdline.append(func_cmd)
                cmdline.append(next_cmd)
                addr = '+0(%s)' % addr

        # 返回trace
        trace = set_trace(cmdline, GET_HOOK_CMD[VERSION_3])

        return trace
    except Exception as e:
        print('get_trace_v3_big has an error.', e)


def get_trace_v3(nf_hooks_addr):
    try:
        # 计算各hook链的list地址
        index = 0
        for pf in [2, 10, 3, 7]:
            for hook in range(5):
                if pf == 3 and hook >= 3:
                    continue
                list_head = nf_hooks_addr + pf * 128 + hook * 16
                list_head_hex = '0x%x' % list_head
                hook_index_to_list[index] = [list_head_hex]
                index += 1

        # 获取各hook函数的cmd
        cmdline = []
        # print(hook_index_to_list)
        for k, v in hook_index_to_list.items():
            # nf_hook_num_cmd_r7 = 'hookhead%d=@0x%x '
            cmdline.append(nf_hook_num_cmd[VERSION_3] % (k, v[0]))

            funccmd = 'hook%d_func%d=+0x10(%s):u64 '
            nextcmd = 'hook%d_func%d_next=+0x0(%s):u64 '
            addr = '@' + v[0]
            for i in range(8):
                func_cmd = funccmd % (k, i, addr)
                next_cmd = nextcmd % (k, i, addr)
                cmdline.append(func_cmd)
                cmdline.append(next_cmd)
                addr = '+0(%s)' % addr

        # 返回trace
        # print("-----start-----")
        # print(hook_index_to_list)
        trace = set_trace(cmdline, VERSION_3)

        return trace
    except Exception as e:
        print('get_trace_v3 has an error.', e)


def get_func_addr_v3(nf_hook_nums, trace):
    try:
        hook_next = re.findall('hook(\d+)_func(\d+)_next=([a-fx0-9]+)', trace)
        # print(hook_next)
        # 各hook链的钩子数目
        if hook_next:
            for naddr in hook_next:
                # print(naddr)
                index = int(naddr[0])
                if nf_hook_nums[index] == -1 and naddr[2][-16:] == hook_index_to_list[index][0][-16:]:
                    nf_hook_nums[index] = int(naddr[1]) + 1

        print('nf_hook_nums: ')
        print(nf_hook_nums)

        # 解析各钩子函数
        hook_func = re.findall('hook(\d+)_func(\d+)=([a-fx0-9]+)', trace)
        # print(hook_func)
        hook_func_list = []
        if hook_func:
            for func in hook_func:
                hook_index = int(func[0])
                hook_func_index = int(func[1])
                if hook_func_index < nf_hook_nums[hook_index]:
                    sysctl_file = get_kallsyms(func[2][-16:])
                    if sysctl_file:
                        sysctl_file_decode = sysctl_file[-1][:-1].decode()
                        hook_func_list.append([hook_index, hook_func_index, sysctl_file_decode[19:]])
                    else:
                        hook_func_list.append([hook_index, hook_func_index, func[2][-16:]])

        return hook_func_list
    except Exception as e:
        print('get_func_addr_v3 has an error.', e)


def get_hooks_v3():
    try:
        # 获取nf_hooks的符号地址
        sysctl_file = get_kallsyms(" nf_hooks")
        nf_hooks_addr = int(sysctl_file[0][:16], 16)
        print("nf_hooks     %s " % sysctl_file[0][:16])

        # 拼装命令，获取trace
        # print(nf_hooks_addr)
        trace = get_trace_v3(nf_hooks_addr)

        # print("-----get trace-----")
        # print(trace)
        hook_num = re.findall('hookhead(\d+)=([a-fx0-9]+)', trace)

        # 剔除空链表
        nf_hook_nums = [-1] * 18
        if hook_num:
            for i in hook_num:
                if i[1][-16:] == hook_index_to_list[int(i[0])][0][-16:]:
                    nf_hook_nums[int(i[0])] = 0

        hook_func_list = get_func_addr_v3(nf_hook_nums, trace)

        if -1 in nf_hook_nums:
            trace = get_trace_v3_big(nf_hook_nums)
            hook_func_list += get_func_addr_v3(nf_hook_nums, trace)
        return hook_func_list
    except Exception as e:
        print('get_hooks_v3 has an error.', e)


def get_trace_v4_nums(version):
    try:
        cmdline = []
        res = []
        nf_hook_nums = [0] * 18

        print("-----start get nums-----")
        for i in range(NF_HOOKS):
            cmdline.append(nf_hook_num_cmd[version] % (i, +  8 * i))

        trace = set_trace(cmdline, version)

        # 获取各hook链的钩子数目
        hook_num = re.findall('num(\d+)=([a-fx0-9]+)', trace)
        if hook_num:
            for i in hook_num:
                nf_hook_nums[int(i[0])] = int(i[1], 16)
        if(not is_arp_exist()):
            nf_hook_nums[10] = 0
            nf_hook_nums[11] = 0
            nf_hook_nums[12] = 0
        
        print("nf_hook_nums: ")
        print(nf_hook_nums)

        return nf_hook_nums
    except Exception as e:
        print('get_trace_v4_nums has an error.', e)


def get_trace_v4(version):
    try:
        cmdline = []
        nf_hook_nums = get_trace_v4_nums(version)

        print("-----start get func-----")
        for i, v in enumerate(nf_hook_nums):
            if not v:
                continue
            for j in range(v):
                cmdline.append(nf_hook_func_cmd[version] % (i, j, i * 8, 16 * j))
    
        trace = set_trace(cmdline, version)

        return trace
    except Exception as e:
        print('get_trace_v4 has an error.', e)


def get_hooks_v4(version):
    try:
        # 拼装命令，获取trace
        trace = get_trace_v4(version)

        # 解析各钩子函数
        hook_func = re.findall('hook(\d+)_func(\d+)=([a-fx0-9]+)', trace)
        # print(hook_func)
        hook_func_list = []
        if hook_func:
            for func in hook_func:
                hook_index = int(func[0])
                hook_func_index = int(func[1])
                sysctl_file = get_kallsyms(func[2][-16:])
                if sysctl_file:
                    sysctl_file_decode = sysctl_file[-1][:-1].decode()
                    hook_func_list.append([hook_index, hook_func_index, sysctl_file_decode[19:]])
                else:
                    hook_func_list.append([hook_index, hook_func_index, func[2][-16:]])
        return hook_func_list
    except Exception as e:
        print('get_hooks_v4 has an error.', e)


def main():
    try:
        global devname, host
        if len(sys.argv) >= 3 and sys.argv[1] == 'dev':
            devname = sys.argv[2]
            if len(sys.argv) == 5 and sys.argv[3] == 'host':
                data = inet_pton(AF_INET, sys.argv[4])
                ipv4_n = unpack('I', data)
                host = hex(ipv4_n[0])
        elif len(sys.argv) == 3 and sys.argv[1] == 'host':
            data = inet_pton(AF_INET, sys.argv[2])
            ipv4_n = unpack('I', data)
            host = hex(ipv4_n[0])

        if devname:
            print('dev : %s' % devname)
        if host:
            print('host: %s' % host)

        # 获取euler版本
        ret = subprocess.Popen("uname -a", shell=True, stdout=subprocess.PIPE)
        versions = ret.stdout.readline().decode()
        ret.stdout.close()

        if '3.10.0-327' in versions or '3.10.0-514' in versions or '3.10.0-862' in versions:
            version = VERSION_3
        elif '4.19.36' in versions or '4.19.90' in versions or '4.18.0' in versions:
            version = VERSION_4
        elif '5.10.0' in versions:
            version = VERSION_5
        else:
            print(versions)
            print('Please check os version.')
            print('Support 2.5 2.7 2.8 2.9 and 2.10')
            return

        # 关注异常信号
        signal.signal(signal.SIGINT, sigint_handler)
        signal.signal(signal.SIGHUP, sigint_handler)
        signal.signal(signal.SIGTERM, sigint_handler)

        hook_func_list = []
        if version == VERSION_3:
            hook_func_list = get_hooks_v3()
        # 读取各个钩子点的数目
        elif version == VERSION_4 or version == VERSION_5:
            hook_func_list = get_hooks_v4(version)

        hook_func_list.sort()
        # print(hook_func_list)
        # print("-----get sym-----")
        hooknum = 0
        for func_list in hook_func_list:
            # print(func_list)
            if hooknum != func_list[0]:
                print(' ')
                hooknum = func_list[0]
            print("%s%s" % (hook_name[func_list[0]], func_list[2]))
        print(' ')

    except Exception as e:
        print('has an error.', e)
    finally:
        os.system('echo nop > /sys/kernel/debug/tracing/current_tracer')
        os.system('echo >  /sys/kernel/debug/tracing/kprobe_events')
        os.system('echo >  /sys/kernel/debug/tracing/trace')


if __name__ == '__main__':
    main()
