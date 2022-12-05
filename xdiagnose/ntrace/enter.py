# coding: utf-8
import os
import sys
from xdiagnose.common.logger import logger
from xdiagnose.ntrace.xdiag import pub
from xdiagnose.ntrace.proto.tcp import TcpProto
from xdiagnose.ntrace.proto.udp import UdpProto
from xdiagnose.ntrace.proto.icmp import IcmpProto


protos = {
    'tcp': TcpProto,
    'udp': UdpProto,
    'icmp': IcmpProto,
}


class NetModule(object):
    def __init__(self, args):
        self.npara = None

        if args.protocol in protos:
            self.npara = protos[args.protocol](args)
        else:
            raise NotImplementedError()

        logger.info('Starts with parameters: %s' % ' '.join(sys.argv[1:]))

    def run(self):
        if self.npara.args.read_file:
            self.npara.read_trace_file()
        elif self.npara.args.write_file:
            pub.write_kprobe_cmd(self.npara)
        else:
            pub.check_net_base(self.npara)
            pub.read_kprobe_cmd(self.npara)
            self.npara.read_trace()

    def stop(self):
        self.npara.running = False
        logger.info('Stop ntrace, clear kprobe events')

        kp_events = '/sys/kernel/debug/tracing/kprobe_events'
        kp_enable = '/sys/kernel/debug/tracing/events/kprobes/enable'

        if os.path.exists(kp_enable):
            with open(kp_enable, 'w') as f:
                f.write('0')

        with open(kp_events, 'w') as f:
            f.write('')
