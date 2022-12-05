# coding: utf-8
import re
from socket import IPPROTO_UDP, AF_INET, AF_INET6

from xdiagnose.ntrace.xdiag import pub
from xdiagnose.ntrace.parse.params import parse_expression
from . import udp_handler as handlers


re_udp = {
    'srcport': r' srcport=(?:0x)?([a-f0-9]+)',
    'dstport': r' dstport=(?:0x)?([a-f0-9]+)',
}


class UdpProto(pub.DiagParam):
    def __init__(self, args):
        super(UdpProto, self).__init__()

        self.proto = IPPROTO_UDP
        self.args = args
        self.parse_args()

        self.cmd_file = 'udp_cmd.sh'
        self.cmd_source = 'udp_kprobe.src'

        self.update_regex()
        self.update_regex(re_udp)

        self.base_key += ['skb']
        self.proto_key += ['srcip', 'dstip', 'srcport', 'dstport']

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
                                        'udp' + ' '.join(self.args.expression))
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
