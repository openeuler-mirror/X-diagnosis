#!/usr/bin/python3
# coding: utf-8
import os
import re
import socket
import struct
import subprocess

from xdiagnose.cmdfile.eftrace import parse_multi_cmds

KPROBE_EVENT = "/sys/kernel/debug/tracing/kprobe_events"
KPROBE_ENABLE = "/sys/kernel/debug/tracing/events/kprobes/enable"
KPROBE_TRACE = "/sys/kernel/debug/tracing/trace"

percpu_hash = {'inet_bind':[],
               'tcp_v4_syn_recv_sock':[],
               'tcp_conn_request':[],
               'socket_create':[],
               'tcp_time_process':[],
               'tcp_in_window':[]}
current_arch = None

SYN_FLAG = 64


def write_file(command="", filepath=None, add=False):
    if not filepath:
        return False

    if not add:
        cmd_str = "echo " + "\'" + command + "\'" + " > " + filepath
    else:
        cmd_str = "echo " + "\'" + command + "\'" + " >> " + filepath

    res = subprocess.call(cmd_str, shell=True)
    if res != 0:
        return False

    return True


def get_sysctl_info(params=None):
    if not params:
        return False, None

    command = "sysctl -a | grep " + params

    try:
        res = subprocess.check_output(command, shell=True)
    except subprocess.CalledProcessError:
        return False, None

    re_str = params + " = " + "(.*)" + ""
    re_obj = re.search(re_str, str(res[:-1]))
    if re_obj:
        output = re_obj.group(1)
        return True, output[:-1]

    return False, None


def endian_convert_port(port):
    port_hex = str(port)[2:].zfill(4)

    port_res = int(port_hex[2:] + port_hex[:2], 16)
    return port_res


def endian_convert_addr(addr):
    addr_hex = str(addr)[2:].zfill(8)

    addr_conv = addr_hex[6:] + addr_hex[4:6] + addr_hex[2:4] + addr_hex[:2]
    ip_addr = socket.inet_ntoa(struct.pack('I', socket.htonl(int(addr_conv, 16))))

    return ip_addr

def make_cmd():
    cmds = parse_multi_cmds('''p:inet_bind_p __inet_bind port=(struct sockaddr_in *)%r1->sin_port addr=(struct sockaddr_in *)%r1->sin_addr 
    r:inet_bind_r __inet_bind ret=$retval 
    p:sock_create_p __sys_socket family=%r0 r:sock_create_r __sys_socket ret=$retval 
    p:tcp_v4_syn_recv_sock_p tcp_v4_syn_recv_sock ack_backlog=%r0->sk_ack_backlog max_ack_backlog=%r0->sk_max_ack_backlog 
        sport=(struct tcphdr *)(%r1->data)->source saddr=(struct iphdr *)(%r1->data-20)->saddr dport=(struct tcphdr *)(%r1->data)->dest 
        daddr=(struct iphdr *)(%r1->data-20)->daddr 
    r:tcp_v4_syn_recv_sock_r tcp_v4_syn_recv_sock ret=$retval p:tcp_conn_request_p 
    tcp_conn_request ack_backlog=%r2->sk_ack_backlog max_ack_backlog=%r2->sk_max_ack_backlog sport=(struct tcphdr *)(%r3->data)->source 
        saddr=(struct iphdr *)(%r3->data-20)->saddr dport=(struct tcphdr *)(%r3->data)->dest daddr=(struct iphdr *)(%r3->data-20)->daddr 
    r:tcp_conn_request_r tcp_conn_request ret=$retval 
    p:tcp_tw_process_p tcp_timewait_state_process sport=(struct tcphdr *)(%r1->data)->source saddr=(struct iphdr *)(%r1->data-20)->saddr 
        dport=(struct tcphdr *)(%r1->data)->dest daddr=(struct iphdr *)(%r1->data-20)->daddr 
    r:tcp_tw_process_r tcp_timewait_state_process ret=$retval''') 
    for cmdline in cmds:
            subprocess.call(cmdline, shell=True)

def add_all_trace():
    # clean up exist tracer line
    if os.path.exists(KPROBE_ENABLE):
        write_file("0", KPROBE_ENABLE)

    write_file("", KPROBE_EVENT)
    write_file("", KPROBE_TRACE)
    make_cmd()
    write_file("1", KPROBE_ENABLE)


def get_cpus_count():
    command = "lscpu | grep ^CPU\(s\)"

    try:
        res = subprocess.check_output(command, shell=True)
    except subprocess.CalledProcessError:
        print("get_cpus_count failed")
        return -1

    cpus = re.match(r'CPU\(s\):\s*(.*)', str(res[:-1])[2:-1])
    cpus = int(cpus.group(1))

    return cpus


def init_percpu_hash():
    cpus = get_cpus_count()

    for key in percpu_hash.keys():
        percpu_hash[key] = [[] for _ in range(cpus)]


def chk_ip_nonlocal_bind():
    res, output = get_sysctl_info("net.ipv4.ip_nonlocal_bind")
    if not res:
        print("chk_ip_nonlocal_bind: get nonlocal v4 bind info failed")
        return False

    if int(str(output)) == 1:
        return True
    else:
        return False


def chk_inet_bind_ret(pre_line, line):
    port_obj = re.search(r'port=(.*)\s+addr', pre_line)
    addr_obj = re.search(r'addr=(.*)\s', pre_line)

    port_raw = port_obj.group(1)
    addr_raw = addr_obj.group(1)

    src_port = endian_convert_port(port_raw)
    src_addr = endian_convert_addr(addr_raw)

    params_list = line.strip().split()
    inet_ret = params_list[8]
    re_obj = re.match(r'ret=(.*)', inet_ret)
    retval = re_obj.group(1)

    src_info = str(src_addr) + ":" + str(src_port)

    if retval == '0x0':
        pass
    elif retval == '0xffffff9e':
        print("{} inet_bind: return -EADDRINUSE".format(src_info))
    elif retval == '0xffffff9d':
        print("{} inet_bind: return -EADDRNOTAVAIL".format(src_info))
        if not chk_ip_nonlocal_bind():
            print("ip_nonlocal_bind is not enable; maybe you should check your address")
    elif retval == '0xfffffff3':
        print("{} inet_bind: return -EACCES".format(src_info))
    elif retval == '0xffffffea':
        print("{} inet_bind: return -EINVAL".format(src_info))
    else:
        print("{} inet_bind: return {}".format(src_info, retval))


def chk_ack_backlog(pre_line, line):
    params_list = pre_line.strip().split()
    sk_ack_backlog = re.search(r'ack_backlog=([a-fx0-9]+)', params_list[6])
    sk_ack_backlog = sk_ack_backlog.group(1)
    sk_max_ack_backlog = re.search(r'max_ack_backlog=([a-fx0-9]+)', params_list[7])
    sk_max_ack_backlog = sk_max_ack_backlog.group(1)

    sport_obj = re.search(r'sport=([a-fx0-9]+)', pre_line)
    saddr_obj = re.search(r'saddr=([a-fx0-9]+)', pre_line)

    dport_obj = re.search(r'dport=([a-fx0-9]+)', pre_line)
    daddr_obj = re.search(r'daddr=([a-fx0-9]+)', pre_line)

    sport_raw = sport_obj.group(1)
    saddr_raw = saddr_obj.group(1)
    dport_raw = dport_obj.group(1)
    daddr_raw = daddr_obj.group(1)

    src_port = endian_convert_port(sport_raw)
    src_addr = endian_convert_addr(saddr_raw)

    dst_port = endian_convert_port(dport_raw)
    dst_addr = endian_convert_addr(daddr_raw)

    params_list = line.strip().split()
    inet_ret = params_list[8]
    re_obj = re.match(r'ret=(.*)', inet_ret)
    retval = re_obj.group(1)

    if sk_ack_backlog > sk_max_ack_backlog:
        print("[TCP] {}:{} to {}:{}  queue full!! sk_ack_backlog is {},"
            "larger than sk_max_ack_backlog {}".format(src_addr, src_port, dst_addr, dst_port,sk_ack_backlog, sk_max_ack_backlog))


def chk_fp_full(pre_line, line):
    params_list = line.strip().split()
    inet_ret = params_list[8]
    re_obj = re.match(r'ret=(.*)', inet_ret)
    retval = re_obj.group(1)

    if retval == '0xffffffe9':
        print("socket create failed: return -ENFILE this means that OS cannot alloc socket anymore")
    elif retval == '0xffffffe8':
        print("socket create failed: return -EMFILE this means that OS cannot alloc fd anymore")


def chk_tcp_tw_process(pre_line, line):
    sport_obj = re.search(r'sport=([a-fx0-9]+)', pre_line)
    saddr_obj = re.search(r'saddr=([a-fx0-9]+)', pre_line)
    dport_obj = re.search(r'dport=([a-fx0-9]+)', pre_line)
    daddr_obj = re.search(r'daddr=([a-fx0-9]+)', pre_line)

    sport_raw = sport_obj.group(1)
    saddr_raw = saddr_obj.group(1)
    dport_raw = dport_obj.group(1)
    daddr_raw = daddr_obj.group(1)

    src_port = endian_convert_port(sport_raw)
    src_addr = endian_convert_addr(saddr_raw)

    dst_port = endian_convert_port(dport_raw)
    dst_addr = endian_convert_addr(daddr_raw)

    params_list = line.strip().split()
    inet_ret = params_list[8]
    re_obj = re.match(r'ret=(.*)', inet_ret)
    retval = re_obj.group(1)

    src_info = str(src_addr) + ":" + str(src_port)
    dst_info = str(dst_addr) + ":" + str(dst_port)

    if retval == '0x0':
        pass
    elif retval == '0x1':
        print("tcp_timewait_state_process: TCP_TW_RST source is {} destination is {}".format(src_info, dst_info))
    elif retval == '0x2':
        print("tcp_timewait_state_process: TCP_TW_ACK source is {} destination is {}".format(src_info, dst_info))
    elif retval == '0x3':
        # print("tcp_timewait_state_process: TCP_TW_SYN source is {}".format(src_info))
        pass
    else:
        print("tcp_tw_result: {}".format(retval))


def get_src_info(pre_line):
    sport_obj = re.search(r'sport=(.*)\s+saddr', pre_line)
    saddr_obj = re.search(r'saddr=(.*)\s+dport', pre_line)

    port_raw = sport_obj.group(1)
    addr_raw = saddr_obj.group(1)

    src_port = endian_convert_port(port_raw)
    src_addr = endian_convert_addr(addr_raw)

    return src_port, src_addr


def get_dst_info(pre_line):
    dport_obj = re.search(r'dport=(.*)\s+daddr', pre_line)
    daddr_obj = re.search(r'daddr=(.*)', pre_line)

    port_raw = dport_obj.group(1)
    addr_raw = daddr_obj.group(1)

    dst_port = endian_convert_port(port_raw)
    dst_addr = endian_convert_addr(addr_raw)

    return dst_port, dst_addr


def chk_tcp_flag(raw_flag):
    int_flag = int(str(raw_flag))
    hex_flag = hex(int_flag)

    if int_flag & SYN_FLAG == SYN_FLAG:
        return "SYN"
    else:
        return "ERR"


def chk_tcp_in_window(pre_line, line):
    sport_obj = re.search(r'sport=(.*)\s+saddr', pre_line)
    saddr_obj = re.search(r'saddr=(.*)\s+dport', pre_line)
    dport_obj = re.search(r'dport=(.*)\s+daddr', pre_line)
    daddr_obj = re.search(r'daddr=(.*)\s+flag', pre_line)
    tcp_flag = re.search(r'flag=(.*)', pre_line)

    sport_raw = sport_obj.group(1)
    saddr_raw = saddr_obj.group(1)
    dport_raw = dport_obj.group(1)
    daddr_raw = daddr_obj.group(1)
    flag_raw = tcp_flag.group(1)

    tcp_flag = chk_tcp_flag(flag_raw)

    src_port = endian_convert_port(sport_raw)
    src_addr = endian_convert_addr(saddr_raw)
    dst_port = endian_convert_port(dport_raw)
    dst_addr = endian_convert_addr(daddr_raw)

    params_list = line.strip().split()
    inet_ret = params_list[9]
    re_obj = re.match(r'ret=(.*)', inet_ret)
    retval = re_obj.group(1)

    src_info = str(src_addr) + ":" + str(src_port)
    dst_info = str(dst_addr) + ":" + str(dst_port)

    if retval == '0x1':
        pass
    elif tcp_flag == SYN_FLAG:
        print("tcp in window, source is {} destination is {}".format(src_info, dst_info))


def analy_line(line):
    if line[0] == '#':
        return
    info = re.search(r'\[(\d+)\]\s.*?\s(\w+):', line)
    if not info:
        return
    cpu = int(info.group(1))
    target = info.group(2)
    for k, v in TcpHandCheckModule.tcp_func.items():
        if v[0] == target:
            percpu_hash[k][cpu].append(line)
            return
        elif v[1] == target and len(percpu_hash[k][cpu]) > 0:
            pre_line = percpu_hash[k][cpu].pop()
            v[2](pre_line, line)

def main_loop():
    fp = open(KPROBE_TRACE, 'r')
    while True:
        lines = fp.readlines(1000)
        if lines:
            for line in lines:
                analy_line(line)

    fp.close()


def keyint_handler():
    print("tracer stop by keyboard interrupt")
    write_file("0", KPROBE_ENABLE)
    write_file("", KPROBE_EVENT)
    write_file("", KPROBE_TRACE)
    print("bye!")


class TcpHandCheckModule(object):
    tcp_func = {'inet_bind': ['inet_bind_p', 'inet_bind_r', chk_inet_bind_ret],
                'tcp_v4_syn_recv_sock': ['tcp_v4_syn_recv_sock_p', 'tcp_v4_syn_recv_sock_r', chk_ack_backlog],
                'tcp_conn_request': ['tcp_conn_request_p', 'tcp_conn_request_r', chk_ack_backlog],
                'socket_create': ['socket_create_p', 'socket_create_r', chk_fp_full],
                'tcp_time_process': ['tcp_time_process_p', 'tcp_time_process_r', chk_tcp_tw_process],
                'tcp_in_window': ['tcp_in_window_p', 'tcp_in_window_r', chk_tcp_in_window]}
    def __init__(self, args):
        self.args = args

    def run(self):
        main()

    def clear(self):
        pass

    def stop(self):
        pass


def main():
    try:
        init_percpu_hash()
        add_all_trace()

        main_loop()
    except KeyboardInterrupt:
        keyint_handler()


if __name__ == "__main__":
    main()

