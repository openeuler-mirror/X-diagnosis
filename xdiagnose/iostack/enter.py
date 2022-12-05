# coding: utf-8
import sys 

from xdiagnose.common.logger import logger
from xdiagnose.iostack.proto import sd
from xdiagnose.iostack.xdiag import pub


class IoModule(object):
    def __init__(self, args):
        self.npara = sd.SdProbe(args)
        logger.info('Starts with parameters: %s' % ' '.join(sys.argv[1:]))

    def run(self):
        if self.npara.args.read_file:
            self.npara.read_trace_file()

        elif self.npara.args.write_file:
            pub.write_kprobe_cmd(self.npara)

        else:
            pub.read_kprobe_cmd(self.npara)
            self.npara.read_trace()

    def stop(self):
        self.npara.running = False
        self.npara.unable_events()
