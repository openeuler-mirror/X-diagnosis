import re

from subprocess import getstatusoutput
from xdiagnose.common.logger import inspect_warn_logger as logger

class LogNicCheck(object):
    data = {
            'tx_timeout': [re.compile(r'.*?tx_timeout.*?:\s(\d+)')]
    }
    pause = {
            'rx_pause' : ['link_xoff_rx', 'rx_flow_control_xoff', 'rx_pause_ctrl_phy', 'mac_rx_pause_num', 'mac_rx_mac_pause_num'],
            'tx_pause' : ['link_xoff_tx', 'tx_flow_control_xoff', 'tx_pause_ctrl_phy', 'mac_tx_pause_num', 'mac_tx_mac_pause_num']
    }
    error_drop = {
            'rx_dropped' : 4,
            'tx_dropped' : 10,
            'rx_errors'  : 3,
            'tx_errors'  : 9
    }

    def __init__(self, cmd='ip a'):
        self.cmd = cmd
        self.info = {}
        self.old_info = {}
        stats = getstatusoutput(self.cmd)
        if stats[0] == 0:
            self.ip_info =  stats[1]

    def get_valid_port(self):
        up_port = []
        newlines = self.ip_info.split('\n')
        nic_filter = r'\w+:\s(\w+):.*?state UP'
        for line in newlines:
            f = re.search(nic_filter, line)
            if f:
                up_port.append(f.group(1))
        return up_port

    def check_nic(self, port):
        port_info = getstatusoutput('ethtool %s' % port)
        if port_info[0] == 0:
            support_port = re.search(r'\w+:\s((FIBRE)|(Twisted Pair))', port_info[1])
            if support_port:
                return True
        return False

    def get_pause(self, output, port):
        for k, v in self.pause.items():
            for key in v:
                cmd = r'\s%s:\s(\d+)' % key
                num = re.search(cmd, output)
                if num:
                    key_name = port + ':' + k
                    self.info[key_name] = int(num.group(1))

    def get_nic_stat(self, output, port):
        self.get_pause(output, port)

        for k, v in self.data.items():
            num = v[0].search(output)
            if num:
                key_name = port + ':' + k
                self.info[key_name] = int(num.group(1))

        er_stats = getstatusoutput('cat /proc/net/dev |grep %s' % port)
        if er_stats[0] == 0:
            num = er_stats[1].split()
            for k, v in self.error_drop.items():
                key_name = port + ':' + k
                self.info[key_name] = int(num[v])

    def do_action(self):
        speed = ''
        up_port = self.get_valid_port()
        try:
            for port in up_port:
                if not self.check_nic(port):
                    continue
                cmd = 'ethtool -S %s' % port
                nic_output = getstatusoutput(cmd)
                if nic_output[0] == 0:
                    port_info = getstatusoutput('ethtool %s' % port)
                    if port_info[0] == 0:
                        speed_info = re.search(r'.*?Speed:\s(\w+)', port_info[1])
                        if speed_info:
                            speed = speed_info.group(1)
                    self.get_nic_stat(nic_output[1], port)
                    if not self.old_info:
                        return
                    for k, v in self.info.items():
                        if k and self.info[k] - self.old_info[k] > 0:
                            logger.info('%s:speed=%s' % (port, speed))
                            logger.info('%s is increased form %s to %s' % (
                            k, self.old_info[k], self.info[k]))
        finally:
            self.old_info = self.info
