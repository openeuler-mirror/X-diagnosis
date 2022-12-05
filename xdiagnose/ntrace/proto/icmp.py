# coding: utf-8

import re
from socket import IPPROTO_ICMP, AF_INET, AF_INET6

from xdiagnose.ntrace.xdiag import pub
from xdiagnose.ntrace.parse.params import parse_expression
from . import icmp_handler as handlers

re_icmp = {
    'icmp_type': 'icmp_type=(?:0x)?([a-f0-9]+)',
    'icmp_code': 'icmp_code=(?:0x)?([a-f0-9]+)',
    'icmp_id':   'icmp_id=(?:0x)?([a-f0-9]+)',
    'icmp_seq':  'icmp_seq=(?:0x)?([a-f0-9]+)',
}

class IcmpProto(pub.DiagParam):
    def __init__(self, args):
        super(IcmpProto, self).__init__()

        self.proto = IPPROTO_ICMP
        self.args = args
        self.parse_args()
        self.update_regex()
        self.update_regex(re_icmp)

        self.cmd_file = 'icmp_cmd.sh'
        self.cmd_source = 'icmp_kprobe.src'

        self.base_key += ['skb']
        self.proto_key += ['srcip', 'dstip', 'icmp_type', 'icmp_code', 'icmp_id', 'icmp_seq']

        self.kprobe_func = {}
        self.kretprobe_func = {}

    def _register_kprobe(self):
        for item in dir(handlers):
            if item.startswith('func_') and not item.endswith('_r'):
                self.kprobe_func[item[5:]] = getattr(handlers, item)

    def _register_kretprobe(self):
        for item in dir(handlers):
            if item.startswith('func_') and item.endswith('_r'):
                self.kretprobe_func[item[5:-2]] = getattr(handlers, item)

    def parse_args(self):
        parsed, ipv4_flag = parse_expression(
                                    'icmp' + ' '.join(self.args.expression))
        self.kprobe_filter = parsed
        if ipv4_flag:
            self.family = AF_INET
        else:
            self.family = AF_INET6

        for elem in parsed:
            if 'ip_proto' in elem:
                proto = re.search(r'ip_proto==(\d+)', elem)
                if proto:
                    proto_num = int(proto.group(1))
                    if proto_num not in {1, 17, 6, 58}:
                        raise Exception('protocol not supported')
                    self.proto = proto_num

    def proto_init(self):
        self._register_kprobe()
        self._register_kretprobe()

    def proto_trace(self, line, pkt_dict):
        cpu = pkt_dict['cpu']
        function = pkt_dict['function']

        if function in self.kprobe_func:
            self.kprobe_func[function](self, line, pkt_dict)
        self.cpu_last_func[cpu] = [pkt_dict, line]

    def proto_ret(self, line, pkt_dict):
        cpu = int(pkt_dict['cpu'])
        func = pkt_dict['function']
        orig_func = func[:-2]

        if orig_func not in self.kretprobe_func:
            return 0

        prev_pack = self.cpu_last_func[cpu]
        self.kretprobe_func[orig_func](self, line, pkt_dict, prev_pack)
        return 1
