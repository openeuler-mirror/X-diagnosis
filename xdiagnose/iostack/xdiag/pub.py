# coding: utf-8
import re
import os
import io
from subprocess import getstatusoutput as get_output

from xdiagnose.cmdfile.eftrace import xd_make_cmd
from xdiagnose.common.logger import logger
from xdiagnose.common.logger import raw_logger
from xdiagnose.common.config import config

KPROBE_FILTER = "echo \"devname=='%s' && partno==%s\" >/sys/kernel/debug/tracing/events/kprobes/filter\n\n"

re_base = {
    'cpu':       r'\[(\d+)\]',
    'timestamp': r'\s(\d+\.\d+)\:',
    'function':  r'\ (\w+)\:',
    'devname':   r'devname="(\w+)\"',
    'partno':    r'skb=(?:0x)?([a-f0-9]+)',
    'ret':       r'ret=(?:0x)?([a-f0-9]+)$',
}


class DiagParam(object):

    def __init__(self, args):
        self.running = True

        self.kprobe_filter = None

        self.all_func = {}
        self.ret_func = {}
        self.cpu_last_func = {}
        self.regex = re_base 
        self.args = args

        self.base_key = ['cpu', 'timestamp', 'function']
        self.proto_key = []
        self.host_dict = {}
        self.parse_scsi()

    def update_regex(self, new_regex=None):
        regex = {} 
        if new_regex:
            regex = new_regex
        else:
            regex = re_base

        for k,v in regex.items():
            self.regex[k] = re.compile(v)

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

        #if self.handle_retwarn(line, pkt_dict):
        #    return line

        pkt_dict['cpu'] = int(pkt_dict['cpu'])
        pkt_dict['timestamp'] = float(pkt_dict['timestamp'])

        self.proto_trace(line, pkt_dict)
        return line

    def read_trace(self):
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
            while True:
                lines = file_obj.readlines(1000)
                if not lines:
                    break
                for line in lines:
                    self.handle_one_trace_line(line)


def read_one_cmd_filter(npara, fd, line):
    if fd:
        fd.write(KPROBE_FILTER % (npara.args.devname, npara.args.partno))
    else:
        os.system(KPROBE_FILTER % (npara.args.devname, npara.args.partno))


def read_one_cmd(npara, fd, cmd_file):
    with io.open(cmd_file, 'r', encoding='utf-8') as file_obj:
        for line in file_obj.readlines():
            line = line.lstrip()
            if line.startswith('echo'):
                s = re.search(r':(\w+)\s', line)
                if s:
                    npara.all_func[s.group(1)] = 1
                if fd:
                    fd.write(line)
                else:
                    os.system(line)
                #read_one_cmd_filter(npara, fd, line)

def read_kprobe_cmd(npara):
    if npara.cmd_source:
        cmd_file = os.path.join(
            config.get('diaglog', 'FtraceFile'), npara.cmd_file)
        if not os.path.exists(cmd_file):
            xd_make_cmd(npara.cmd_source, cmd_file)

        read_one_cmd(npara, None, cmd_file)
        os.system('echo 1 > /sys/kernel/debug/tracing/events/kprobes/enable')

    npara.enable_events()

def write_kprobe_cmd(npara):
    npara.write_events(npara.args.write_file)

    if npara.cmd_source:
        cmd_file = os.path.join(
            config.get('diaglog', 'FtraceFile'), npara.cmd_file)
        if not os.path.exists(cmd_file):
            xd_make_cmd(npara.cmd_source, cmd_file)

        with io.open(npara.args.write_file, 'a+', encoding='utf-8') as fobj:
            read_one_cmd(npara, fobj, cmd_file)

def get_sys_data(cmd):
    return get_output(cmd)[1]
