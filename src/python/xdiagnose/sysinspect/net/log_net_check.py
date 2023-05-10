# coding: utf-8
import re
import os
from subprocess import getstatusoutput
from xdiagnose.utils.logger import inspect_warn_logger as logger

overflow_thresh = 10

class LogNetCheck(object):
    log = {
        'ip6route_cache': ['ipv6 route cache ',
                           re.compile(r'net.ipv6.route.gc_thresh\s=\s(\d+)'),
                           ''],
        'tw_num': ['timewait socket ',
                   re.compile(r'net.ipv4.tcp_max_tw_buckets\s=\s(\d+)'),
                   "cat /proc/net/tcp |awk '{print $4}'|grep -i '06' |wc -l"],
        'nf_num': ['nf_conntrack ',
                   re.compile(r'net.netfilter.nf_conntrack_max\s=\s(\d+)'),
                   'cat /proc/net/nf_conntrack |wc -l'],
        'v4_neigh_num': ['ipv4 neigh ',
                         re.compile(r'net.ipv4.neigh.default.gc_thresh3\s=\s(\d+)'),
                         'ip neigh show |wc -l'],
        'v6_neigh_num': ['ipv6 neigh ',
                         re.compile(r'net.ipv6.neigh.default.gc_thresh3\s=\s(\d+)'),
                         'ip -6 neigh show |wc -l']
    }

    def __init__(self, cmd='sysctl -a'):
        self.cmd = cmd
        self.num = {}
        self.thresh = {}
        self.sysctl = ''
        stats = getstatusoutput(self.cmd)
        if stats[0] == 0:
           self.sysctl =  stats[1]

    def get_thresh(self):
        for k, v in self.log.items():
            s = v[1].search(self.sysctl)
            if s:
                self.thresh[k] = int(s.group(1))

    def get_ip6route_cache(self):
        self.num['ip6route_cache'] = 0
        stats = getstatusoutput('cat /proc/net/rt6_stats')
        if stats[0] != 0:
            return
        new_lines = stats[1].split('\n')
        new_elems = new_lines[0].split(' ')
        if new_elems[5].isdigit():
            self.num['ip6route_cache'] = int(new_elems[5])

    def get_num(self):
        for k, v in self.log.items():
            if k == "ip6route_cache":
                continue
            self.num[k] = 0
            if v[2]:
                lines = v[2].split(' ')
                if lines[0].startswith('cat') and lines[1].startswith('/') and not os.path.isfile(lines[1]):
                    continue
                stats = getstatusoutput(v[2])
                if stats[0] != 0:
                    return
                self.num[k] = int(stats[1])

    def do_action(self):
        self.get_thresh()
        self.get_ip6route_cache()
        self.get_num()
        for k, v in self.log.items():
            if self.num[k] != 0 and self.num[k] > self.thresh[k] - overflow_thresh:
                logger.info('%s: is about to overflow (now:%s max:%s)' % (v[0], self.num[k], self.thresh[k]))
