# coding: utf-8
import threading

from xdiagnose.common.config import config

from .common.log_cpu import LogCpu
from .common.log_common_check import LogCommonCheck
from .net.log_ct import LogConntrack
from .net.log_qd import LogQdisc
from .net.log_proc import LogProc
from .net.log_sk import LogSockstat
from .net.log_net_check import LogNetCheck
from .net.log_nic_check import LogNicCheck
from .net.log_bond4_check import LogBond4Check

class Inspector(object):
    def __init__(self):
        self.timer = None
        self.modules = []
        self.interval = config.getint('inspect', 'Interval') or 3

    def reg_module(self, mod):
        self.modules.append(mod)

    def reg_net_module(self, *args, **kwargs):
        self.reg_module(LogConntrack())
        self.reg_module(LogQdisc())
        self.reg_module(LogProc('cat /proc/net/snmp'))
        self.reg_module(LogProc('cat /proc/net/netstat'))
        self.reg_module(LogSockstat())
        self.reg_module(LogSockstat('cat /proc/net/sockstat6'))
        self.reg_module(LogNetCheck())
        self.reg_module(LogNicCheck())
        self.reg_module(LogBond4Check())

    def reg_common_module(self, *args, **kwargs):
        self.reg_module(LogCpu())
        self.reg_module(LogCommonCheck())

    def start_inspect(self):
        self.timer = threading.Timer(self.interval, self.do_inspection)
        self.timer.start()

    def stop_inspect(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None

    def do_inspection(self):
        for mod in self.modules:
            mod.do_action()
        self.start_inspect()
