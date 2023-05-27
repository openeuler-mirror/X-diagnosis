# coding: utf-8
from subprocess import getstatusoutput


class LogProc(object):
    netstat_log = {
        'InNoRoutes':          'Input packet no route',
        'InTruncatedPkts':     'Input packet len less than IP header len',
        'PAWSActive':          'active connections rejected because of '
                               'time stamp',
        'PAWSEstab':           'packets rejected in established connections '
                               'because of timestamp',
        'ListenOverflows':     'times the listen queue of a socket overflowed',
        'TCPBacklogDrop':      'TCPBacklogDrop',
        'PFMemallocDrop':      'times the skb was allocated from pfmemalloc '
                               'reserves',
        'IPReversePathFilter': 'IP Reverse Path Filter (rp_filter)',
        'TCPTimeWaitOverflow': 'times the timewait queue of a socket overflowed',
        'TCPReqQFullDrop':     'the request queue of a listen socket is full',
        'TCPOFODrop':          'TCPOFODrop',
        'TCPRcvQDrop':         'the rcvbuf is full',
    }

    snmp_log = {
        'InHdrErrors':     'Ip header error',
        'InAddrErrors':    'Ip address error',
        'OutNoRoutes':     'Output packet no route',
        'InUnknownProtos': 'Unknown protocol',
        'InDiscards':      'Discarded in packet',
        'OutDiscards':     'Discarded out packet',
        'ReasmTimeout':    'Reassemble timeout',
        'ReasmFails':      'Reassemble fail',
        'FragFails':       'Fragment fail',
        'InCsumErrors':    'Check sum error',
    }

    log = dict(netstat_log, **snmp_log)

    def __init__(self, logger, _, cmd):
        self.logger = logger
        self.cmd = cmd
        self.diff = {}
        self.old_stats = ''
        stats = getstatusoutput(self.cmd)
        if stats[0] == 0:
            self.old_stats = stats[1]
        else:
            self.logger.info('%s is not available' % self.cmd)

    def get_diff(self):
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
                return self.diff

            for i in range(len(new_lines)):
                if old_lines[i] == new_lines[i]:
                    continue

                if i < 1:
                    self.logger.info('%s no title line' % self.cmd)
                    return self.diff

                old_elems = old_lines[i].split(' ')
                new_elems = new_lines[i].split(' ')

                if len(old_elems) != len(new_elems):
                    return self.diff

                proto = new_elems[0][:-1]
                titles = new_lines[i - 1].split(' ')
                for j in range(1, len(new_elems)):
                    if old_elems[j] != new_elems[j]:
                        stats_name = proto + '_' + titles[j]
                        self.diff[stats_name] = (int(new_elems[j])
                                                 - int(old_elems[j]))
        finally:
            self.old_stats = stats[1]

        return self.diff

    def do_action(self):
        stats = self.get_diff()
        for k, v in stats.items():
            _, col = k.split('_')
            if col in self.log:
                self.logger.info('%s: %s %s' % (k, v, self.log[col]))


class LogCheck(object):
    def __init__(self, logger, config):
        self.proc1 = LogProc(logger, config, 'cat /proc/net/snmp')
        self.proc2 = LogProc(logger, config, 'cat /proc/net/netstat')

    def do_action(self):
        self.proc1.do_action()
        self.proc2.do_action()
