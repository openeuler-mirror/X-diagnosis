# coding: utf-8
import os
import threading
from configparser import ConfigParser

from xdiagnose.utils.config import config

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
        self.interval = config.getint('inspect', 'Interval') or 3
        self.configfile = os.path.join(os.path.dirname(__file__), 'sysmonitor.conf')
        if not os.path.exists(self.configfile):
            self.configfile = '/etc/x-diagnose/sysmonitor.conf'

        self.modules = {'cpucheck'      : [LogCpu(),True],
                        'commoncheck'   : [LogCommonCheck(),True],
                        'conntrackcheck': [LogConntrack(),True],
                        'qdisccheck'    : [LogQdisc(),True],
                        'snmpcheck'     : [LogProc('cat /proc/net/snmp'),True],
                        'netstatcheck'  : [LogProc('cat /proc/net/netstat'),True],
                        'sockstatcheck' : [LogSockstat(),True],
                        'sockstat6check': [LogSockstat('cat /proc/net/sockstat6'),True],
                        'netcheck'      : [LogNetCheck(),True],
                        'niccheck'      : [LogNicCheck(),True],
                        'bond4check'    : [LogBond4Check(),True]}

    def reg_modules(self):
        sysconfig = ConfigParser()
        sysconfig.read(self.configfile)
        modulelist = sysconfig['modules']
        for iterm in modulelist:
            if iterm in self.modules and sysconfig['modules'][iterm] == 'off':
                self.modules[iterm][1] = False

    def start_inspecttimer(self):
        self.timer = threading.Timer(self.interval, self.do_inspection)
        self.timer.start()

    def do_inspection(self):
        for mod in self.modules:
            if self.modules[mod][1] == True:
                self.modules[mod][0].do_action()
        self.start_inspecttimer()

    def start_inspect(self):
        self.reg_modules()
        self.start_inspecttimer()

    def stop_inspect(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None

