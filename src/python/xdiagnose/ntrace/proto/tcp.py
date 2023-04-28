# coding: utf-8
import re
from socket import IPPROTO_TCP, AF_INET, AF_INET6

from xdiagnose.utils.logger import logger
from ..xdiag import pub
from ..parse.params import parse_expression
from . import tcp_handler as handlers


re_tcp = {
    'srcport': r' srcport=(?:0x)?([a-f0-9]+)',
    'dstport': r' dstport=(?:0x)?([a-f0-9]+)',
    'tcp_seq': r' tcp_seq=(?:0x)?([a-f0-9]+)',
    'tcp_ack': r' tcp_ack=(?:0x)?([a-f0-9]+)',
    'tcp_flag_syn': r' tcp_flag_syn=([0-1])',
    'tcp_flag_ack': r' tcp_flag_ack=([0-1])',
    'tcp_flag_fin': r' tcp_flag_fin=([0-1])',
    'tcp_flag_rst': r' tcp_flag_rst=([0-1])',
    'tcp_win': r' tcp_win=(?:0x)?([a-f0-9]+)',
    'tcp_check': r' tcp_check=(?:0x)?([a-f0-9]+)',
}


tcp_event_log = {
    'tcp_finish_connect': "finish tcp connect",
    'tcp_close': "app close tcp",
    'tcp_fin': "rcv remote FIN",
    'tcp_write_err': "something error",
    'tcp_send_active_reset': "active send RST"
}


class TcpProto(pub.DiagParam):
    def __init__(self, args):
        super(TcpProto, self).__init__()

        self.proto = IPPROTO_TCP
        self.args = args
        self.parse_args()

        self.cmd_file = 'tcp_cmd.sh'
        self.cmd_source = 'tcp_kprobe.src'

        self.update_regex()
        self.update_regex(re_tcp)

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
        if self.args.expression:
            parsed, ipv4_flag = parse_expression(
                                            'tcp' + ' '.join(self.args.expression))
        else:
            parsed = []
            ipv4_flag = True

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

        if self.args.brief and function in tcp_event_log:
            pkt_dict2 = self.analysis_traceline(line)
            logger.info("tcp %s:%s > %s:%s event: %s func: %s" % (
                    pkt_dict2['srcip'], pkt_dict2['srcport'],
                    pkt_dict2['dstip'], pkt_dict2['dstport'],
                    tcp_event_log[function], function)
                )

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
