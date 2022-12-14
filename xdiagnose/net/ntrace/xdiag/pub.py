# coding: utf-8
import re
import os
import io
import signal
import threading
from subprocess import getstatusoutput as get_output
from struct import pack
from socket import (inet_ntoa, inet_ntop, ntohs, ntohl, AF_INET, AF_INET6)

from xdiagnose.utils.logger import logger
from xdiagnose.utils.logger import raw_logger
from xdiagnose.utils.config import config
from xdiagnose.cmdfile.eftrace import xd_make_cmd


KPROBE_FILTER = "echo '%s'>/sys/kernel/debug/tracing/events/kprobes/%s/filter\n\n"

re_base = {
    'cpu':       r'\[(\d+)\]',
    'timestamp': r'\s(\d+\.\d+)\:',
    'function':  r'\ (\w+)\:',
    'devname':   r'devname="(\w+)\"',
    'skb':       r'skb=(?:0x)?([a-f0-9]+)',
    'hook':      r' hook=(?:0x)?([a-f0-9]+)',
    'ip_proto':  r'ip_proto=(?:0x)?([a-f0-9]+)',
    'txq_state': r'txq_state=(?:0x)?([a-f0-9]+)',
    'qdisc_len': r'qdisc_len=(?:0x)?([a-f0-9]+)',
    'src_mac':   r'dl_src=(?:0x)?([a-f0-9]+)\ ',
    'dst_mac':   r'dl_dst=(?:0x)?([a-f0-9]+)\ ',
    'ret':       r'ret=(?:0x)?([a-f0-9]+)$',
}

re_ipv4 = {
    'srcip':    r' srcip=(?:0x)?([a-f0-9]+)',
    'dstip':    r' dstip=(?:0x)?([a-f0-9]+)',
    'ip_len':   r' ip_len=(?:0x)?([a-f0-9]+)',
    'ip_id':    r' ip_id=(?:0x)?([a-f0-9]+)',
    'ip_frag':  r' ip_frag=(?:0x)?([a-f0-9]+)',
    'ip_check': r' ip_check=(?:0x)?([a-f0-9]+)',
}

re_ipv6 = {
    'srcip':  r' srcip=(?:0x)?([a-f0-9]+)',
    'dstip':  r' dstip=(?:0x)?([a-f0-9]+)',
    'srcip2': r' srcip2=(?:0x)?([a-f0-9]+)',
    'dstip2': r' dstip2=(?:0x)?([a-f0-9]+)',
    'srcip3': r' srcip3=(?:0x)?([a-f0-9]+)',
    'dstip3': r' dstip3=(?:0x)?([a-f0-9]+)',
    'srcip4': r' srcip4=(?:0x)?([a-f0-9]+)',
    'dstip4': r' dstip4=(?:0x)?([a-f0-9]+)',
}

byte_orders = [
    ('ip_id', 0), ('ip_len', 0), ('ip_frag', 0), ('ip_check', 0),
    ('tcp_seq', 1), ('tcp_ack', 1), ('srcport', 0), ('dstport', 0),
    ('tcp_win', 0), ('tcp_check', 0), ('udplen', 0),
    ('icmp_id', 0), ('icmp_seq', 0)
]

proto_name = {1: 'icmp', 6: 'tcp', 17: 'udp', 58: 'icmp6'}


class DiagParam(object):

    def __init__(self):
        self.running = True

        self.proto = 0
        self.family = None
        self.sysctl = {}
        self.version = ''
        self.cpu_mask_old = ''
        self.kprobe_filter = None

        self.all_func = {}
        self.ret_func = {}
        self.cpu_last_func = {}
        self.regex = {}
        self.kcache = {}

        self.args = None

        self.base_key = ['cpu', 'timestamp', 'function']
        self.proto_key = []

    def __del__(self):
        if self.cpu_mask_old:
            os.system('echo %s > /sys/kernel/debug/tracing/tracing_cpumask'
                      % self.cpu_mask_old)

    def proto_init(self):
        raise NotImplementedError()

    def proto_trace(self, line, pkt_dict):
        raise NotImplementedError()

    def proto_ret(self, line, pkt_dict):
        raise NotImplementedError()

    def update_regex(self, new_regex=None):
        if new_regex:
            regex = new_regex.copy()
        else:
            regex = re_base.copy()
            if int(self.family) == int(AF_INET):
                regex.update(re_ipv4)
            else:
                regex.update(re_ipv6)

        for k, v in regex.items():
            self.regex[k] = re.compile(v)

    def handle_retwarn(self, line, pkt_dict):
        if not pkt_dict['function'].endswith('_r'):
            return 0

        re_data = self.regex['ret'].search(line)
        if re_data:
            pkt_dict['ret'] = re_data.group(1)
        else:
            return 0

        cpu = int(pkt_dict['cpu'])
        if cpu not in self.cpu_last_func:
            return 1

        if self.proto_ret and self.proto_ret(line, pkt_dict):
            return 1
        return 1

    def decode_keys(self, pkt_dict):
        if int(self.family) == int(AF_INET):
            srcip = pkt_dict['srcip']
            dstip = pkt_dict['dstip']
            if (srcip, 2) not in self.kcache:
                self.kcache[(srcip, 2)] = inet_ntoa(pack("=I", int(srcip, 16)))

            if (dstip, 2) not in self.kcache:
                self.kcache[(dstip, 2)] = inet_ntoa(pack("=I", int(dstip, 16)))

            pkt_dict['srcip'] = self.kcache[(srcip, 2)]
            pkt_dict['dstip'] = self.kcache[(dstip, 2)]

        elif int(self.family) == int(AF_INET6):
            sip, sip2, sip3, sip4 = pkt_dict['srcip'], pkt_dict['srcip1'],\
                                    pkt_dict['srcip2'], pkt_dict['srcip3']
            dip, dip2, dip3, dip4 = pkt_dict['dstip'], pkt_dict['dstip1'],\
                                    pkt_dict['dstip2'], pkt_dict['dstip3']

            ip6_src_key = (sip, sip2, sip3, sip4)
            ip6_dst_key = (dip, dip2, dip3, dip4)

            if ip6_src_key not in self.kcache:
                self.kcache[ip6_src_key] =\
                    ipv6_to_string(int(sip, 16), int(sip2, 16),
                                   int(sip3, 16), int(sip4, 16))

            if ip6_dst_key not in self.kcache:
                self.kcache[ip6_dst_key] =\
                    ipv6_to_string(int(dip, 16), int(dip2, 16),
                                   int(dip3, 16), int(dip4, 16))

            pkt_dict['srcip'] = self.kcache[ip6_src_key]
            pkt_dict['dstip'] = self.kcache[ip6_dst_key]

        for v in byte_orders:
            if v[0] in pkt_dict:
                temp = pkt_dict[v[0]]
                pkt_dict[v[0]] = int(temp, 16)

                if (temp, v[1]) not in self.kcache:
                    if v[1]:
                        pkt_dict[v[0]] = str(ntohl(pkt_dict[v[0]]))
                    else:
                        pkt_dict[v[0]] = str(ntohs(pkt_dict[v[0]]))
                    self.kcache[(temp, v[1])] = pkt_dict[v[0]]
                pkt_dict[v[0]] = self.kcache[(temp, v[1])]
        return pkt_dict

    def analysis_init(self, line):
        pkt_dict = {}
        for k in self.base_key:
            re_data = self.regex[k].search(line)
            if re_data:
                pkt_dict[k] = re_data.group(1)

        return pkt_dict

    def analysis_traceline(self, line, extra_key=None):
        if not extra_key:
            extra_key = []

        keys = self.proto_key[:]
        keys += extra_key

        pkt_dict = {}
        for k in keys:
            s = self.regex[k].search(line)
            if s:
                pkt_dict[k] = s.group(1)
        return self.decode_keys(pkt_dict)

    def handle_one_trace_line(self, line):
        pkt_dict  = self.analysis_init(line)
        if not pkt_dict or 'function' not in pkt_dict:
            return line

        if not self.args.read_file and \
            pkt_dict['function'] not in self.all_func:
            return line

        if self.handle_retwarn(line, pkt_dict):
            return line

        pkt_dict['cpu'] = int(pkt_dict['cpu'])
        pkt_dict['timestamp'] = float(pkt_dict['timestamp'])

        self.proto_trace(line, pkt_dict)
        return line

    def read_trace(self):
        if self.args.timeout:
            timer_stop = threading.Timer(self.args.timeout,
                                            func_timeout, (self, ))
            timer_stop.start()

        self.proto_init()
        logger.info('Start trace')

        pipe = open('/sys/kernel/debug/tracing/trace_pipe', 'r')

        while self.running:
            line = pipe.readline()
            line = self.handle_one_trace_line(line)
            raw_logger.info(line)
        pipe.close()

    def read_trace_file(self):
        with open(self.args.read_file, 'r') as file_obj:
            self.proto_init()
            while True:
                lines = file_obj.readlines(1000)
                if not lines:
                    break
                for line in lines:
                    self.handle_one_trace_line(line)


def func_timeout(npara):
    npara.running = False
    logger.info('Timeout after %ss' % npara.args.timeout)
    os.kill(os.getpid(), signal.SIGTERM)


def read_one_cmd_filter(npara, fd, line):
    """
    filter: dst 1.1.1.1 or src 2.2.2.2 and port 30000
    parsed: ((dstip==1.1.1.1||srcip==2.2.2.2)&&(sport==30000||dport==30000))
    """
    func = re.search(r'p:(\w+)\s', line)
    if not func:
        func = re.search(r'r:(\w+)\s', line)
        if func:
            npara.ret_func[func.group(1)] = 1
        return

    options = ['srcip', 'dstip', 'srcport', 'dstport']
    excludes = ['ip_proto']

    for op in options:
        if op not in line:
            excludes.append(op)

    filters = [elem for elem in npara.kprobe_filter
                if not any(ex in elem for ex in excludes) or elem in ['||', '&&']]

    l = 0
    for elem in filters:
        if elem in ['||', '&&']:
            l += 1
        else:
            break
    filters = filters[l:]

    r = len(filters)
    for elem in filters[::-1]:
        if elem in ['||', '&&']:
            r -= 1
        else:
            break
    filters = filters[:r]

    op = 0
    for i in range(len(filters) - 1, -1, -1):
        if filters[i] in ['||', '&&']:
            op += 1
        else:
            op = 0
        if op > 1:
            del filters[i]

    op_counts = filters.count('||') + filters.count('&&')
    if op_counts:
        filters.insert(0, '(' * (op_counts + 1))

    for i in range(len(filters)):
        if filters[i] in ['||', '&&']:
            filters[i] = ')' + filters[i]

    if op_counts:
        filters.append(')')

    part1 = ''.join(filters)
    filters2 = ['(' + part1 + ')'] if part1 else []

    if 'ip_proto' in line and len(npara.kprobe_filter) > 0 and \
        'ip_proto' in npara.kprobe_filter[0]:
        filters2.insert(0, npara.kprobe_filter[0])

    if 'icmp_seq' in line:
        filters2.append('icmp_seq!=0')

    # syn or fin or rst flag set
    # if 'tcp_flags' in line and not npara.args.mode & 8:
    #     filters2.append('(tcp_flags!=0x10&&tcp_flags!=0x18)')

    if 'devname' in line and npara.args.interface:
        filters2.append('(devname=="%s")' % npara.args.interface)

    if filters2:
        func_filter = '&&'.join(filters2)
        if fd:
            fd.write(KPROBE_FILTER % (func_filter, func.group(1)))
        else:
            os.system(KPROBE_FILTER % (func_filter, func.group(1)))


def read_one_cmd(npara, fd, cmd_file):
    avail_func = set()
    with open('/sys/kernel/debug/tracing/available_filter_functions') as f:
        for line in f.readlines():
            line = line.split()
            avail_func.add(line[0].strip())

    with io.open(cmd_file, 'r', encoding='utf-8') as file_obj:
        if not fd and npara.args.cpu_mask and npara.cpu_mask_old:
            os.system('echo %s > '
                      '/sys/kernel/debug/tracing/tracing_cpumask'
                      % npara.args.cpu_mask)
        elif fd and npara.args.cpu_mask:
            fd.write('echo %s > '
                     '/sys/kernel/debug/tracing/tracing_cpumask\n'
                     % npara.args.cpu_mask)

        for line in file_obj.readlines():
            line = line.lstrip()
            if line.startswith('echo'):
                s = re.search(r':(\w+)\s', line)
                if s:
                    func = s.group(1)
                    raw_func = func[:-2] if func.endswith('_r') else func
                    if raw_func not in avail_func:
                        logger.error('Function is not available: %s' % raw_func)
                        continue
                    npara.all_func[func] = 1
                elif line.rstrip().endswith('filter'):
                    f_parts = line.split('/')
                    if len(f_parts) >= 2 and f_parts[-2] not in npara.all_func:
                        continue
                if fd:
                    fd.write(line)
                else:
                    os.system(line)
                read_one_cmd_filter(npara, fd, line)


def read_kprobe_cmd(npara):
    cmd_file = os.path.join(config.get('diaglog', 'FtraceFile'), npara.cmd_file)
    if not os.path.exists(cmd_file):
        xd_make_cmd(npara.cmd_source, cmd_file)
    read_one_cmd(npara, None, cmd_file)
    os.system('echo 1 > /sys/kernel/debug/tracing/events/kprobes/enable')
    os.system('echo 1 > /sys/kernel/debug/tracing/tracing_on')


def write_kprobe_cmd(npara):
    cmd_file = os.path.join(config.get('diaglog', 'FtraceFile'), npara.cmd_file)
    if not os.path.exists(cmd_file):
        xd_make_cmd(npara.cmd_source, cmd_file)
    with io.open(npara.args.write_file, 'w+', encoding='utf-8') as fd:
        fd.write('echo 0 > /sys/kernel/debug/tracing/events/kprobes/enable\n')
        fd.write('echo >  /sys/kernel/debug/tracing/kprobe_events\n')
        fd.write('echo nop > /sys/kernel/debug/tracing/current_tracer\n')
        fd.write('echo >  /sys/kernel/debug/tracing/trace\n')
        read_one_cmd(npara, fd, cmd_file)
        fd.write('echo 1 >  /sys/kernel/debug/tracing/tracing_on\n')
        fd.write('echo 1 >  /sys/kernel/debug/tracing/events/kprobes/enable\n')


def get_arp_num():
    line = get_sys_data("arp -nv | grep Entries")
    s_num = re.search('Entries: (\d+)', line)
    return s_num.group(1) if s_num else 0


def check_dev_ip(source_ip):
    if not source_ip:
        return

    lines = get_sys_data("ip -br add")

    source_ip_list = source_ip.split('.')
    mask_max = 0
    dev_up_ip = []
    for line in lines.split('\n'):
        b = re.split(r" +", line)
        if b[1] == 'DOWN':
            continue

        for i in range(2, len(b)):
            if '.' in b[i]:
                bb = re.split(r"[./]", b[i])
                mask = mask_temp = int(bb[-1])
                j = 0
                while mask_temp >= 8 and source_ip_list[j] == bb[j]:
                        mask_temp -= 8
                        j += 1
                if mask_temp < 8 and mask > mask_max:
                    if b[i].startswith(source_ip):
                        logger.info('Local closest address is %s in dev %s(%s)'
                                    % (b[i], b[0], b[1]))
                        return
                    elif not mask_temp or \
                        int(source_ip_list[j]) >> (8-mask_temp) == \
                        int(bb[j]) >> (8-mask_temp):
                        mask_max = mask
                        dev_up_ip = [b[i], b[0], b[1]]

    if dev_up_ip:
        logger.info('Local closest address is %s in dev %s(%s)' % (
                    dev_up_ip[0], dev_up_ip[1], dev_up_ip[2])
                )
    else:
        logger.warning('Addresses without the same mask')


def check_net_base(npara):
    if npara.args.cpu_mask:
        npara.cpu_mask_old = get_sys_data(
                            "cat /sys/kernel/debug/tracing/tracing_cpumask")
        npara.cpu_mask_old = npara.cpu_mask_old[:-1]

    sysctl = get_sys_data("sysctl -a")

    icmp = r'net.ipv4.icmp_echo_ignore_all = ([0-9]+)'
    s = re.search(icmp, sysctl)
    if s and s.group(1) == '1':
        logger.error('ICMP is ignored, net.ipv4.icmp_echo_ignore_all = 1')

    arp = r'net.ipv4.neigh.default.gc_thresh3 = ([0-9]+)'
    arp_num = get_arp_num()
    s = re.search(arp, sysctl)
    if s:
        gc_thresh3 = s.group(1)
        npara.sysctl['gc_thresh3'] = int(gc_thresh3)

        if int(gc_thresh3) <= int(arp_num) or \
            int(gc_thresh3) - int(arp_num) < 10:
            logger.warning('ARP is almost full, entry=%s gc_thresh3=%s'%
                           (arp_num, gc_thresh3))


def ipv6_to_string(ip0, ip1, ip2, ip3):
    return inet_ntop(AF_INET6, pack('IIII', ip0, ip1, ip2, ip3))


def get_sys_data(cmd):
    return get_output(cmd)[1]
