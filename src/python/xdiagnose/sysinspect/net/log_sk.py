# coding: utf-8
import re
from subprocess import getstatusoutput


class LogSockstat(object):
    log_v4 = {
        'TCP_mem': 'tcp memory',
        'UDP_mem': 'udp memory',
        'FRAG_memory': 'frag memory',
    }
    log_v6 = {
        'FRAG6_memory': 'frag6 memory',
    }
    log = dict(log_v4, **log_v6)

    def __init__(self, logger, _config, cmd='cat /proc/net/sockstat'):
        self.logger = logger
        self.cmd = cmd
        self.diff = {}
        self.sysctl = {}
        self.old_stats = ''
        self.get_sysctl()
        stats = getstatusoutput(self.cmd)
        if stats[0] == 0:
            self.old_stats = stats[1]
        else:
            self.logger.info('%s is not available' % self.cmd)

    def get_sysctl(self):
        out = getstatusoutput('sysctl -a')
        if out[0] == 0:
            tmem = r'net.ipv4.tcp_mem = (\d+)\s+(\d+)\s+(\d+)'
            s = re.search(tmem, out[1])
            if s:
                self.sysctl['tcp_mem'] = [int(s.group(1)), int(s.group(2)),
                                          int(s.group(3))]

            umem = r'net.ipv4.udp_mem = (\d+)\s+(\d+)\s+(\d+)'
            s = re.search(umem, out[1])
            if s:
                self.sysctl['udp_mem'] = [int(s.group(1)), int(s.group(2)),
                                          int(s.group(3))]

            iphigh = r'net.ipv4.ipfrag_high_thresh = ([0-9]+)'
            s = re.search(iphigh, out[1])
            if s:
                thresh = s.group().split()
                self.sysctl['ipfrag_high_thresh'] = int(thresh[2])

            ip6high = r'net.ipv6.ip6frag_high_thresh = ([0-9]+)'
            s = re.search(ip6high, out[1])
            if s:
                thresh = s.group().split()
                self.sysctl['ip6frag_high_thresh'] = int(thresh[2])

    def get_diff_value(self):
        self.diff = {}

        if not self.old_stats:
            return self.diff

        stats = getstatusoutput(self.cmd)
        if stats[0] != 0:
            return self.diff

        try:
            old_lines = self.old_stats.split('\n')
            new_lines = stats[1].split('\n')

            if len(old_lines) != len(new_lines):
                self.logger.info('%s line numbers not equal' % self.cmd)
                return self.diff

            for i in range(len(new_lines)):
                if old_lines[i] == new_lines[i]:
                    continue

                old_elems = old_lines[i].split(' ')
                new_elems = new_lines[i].split(' ')
                if len(old_elems) != len(new_elems):
                    self.logger.info('%s elems numbers not equal, line:%d'
                                     % (self.cmd, i + 1))
                    continue

                proto = new_elems[0][:-1]

                for j in range(len(new_elems)):
                    if (old_elems[j] != new_elems[j]
                            and j - 1 >= 0
                            and old_elems[j].isdigit()
                            and new_elems[j].isdigit()):
                        stats_name = proto + '_' + new_elems[j - 1]
                        self.diff[stats_name] = int(new_elems[j])
        finally:
            self.old_stats = stats[1]

        return self.diff

    def do_action(self):
        sock_stats = self.get_diff_value()
        for k, v in sock_stats.items():
            if k in self.log:
                if k == 'TCP_mem' and v > self.sysctl['tcp_mem'][2] - 10:
                    self.logger.info('%s: %s %s' % (k, v, self.log[k]))

                elif k == 'UDP_mem' and v > self.sysctl['udp_mem'][2] - 10:
                    self.logger.info('%s: %s %s' % (k, v, self.log[k]))

                elif (k == 'FRAG_memory'
                      and v > self.sysctl['ipfrag_high_thresh'] - 10):
                    self.logger.info('%s: %s %s' % (k, v, self.log[k]))

                elif (k == 'FRAG6_memory'
                      and v > self.sysctl['ip6frag_high_thresh'] - 10):
                    self.logger.info('%s: %s %s' % (k, v, self.log[k]))


class LogCheck(object):
    def __init__(self, logger, config):
        self.sock1 = LogSockstat(logger, config)
        self.sock2 = LogSockstat(logger, config, 'cat /proc/net/sockstat6')

    def do_action(self):
        self.sock1.do_action()
        self.sock2.do_action()
