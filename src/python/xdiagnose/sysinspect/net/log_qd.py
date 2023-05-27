# coding: utf-8
import re
from subprocess import getstatusoutput


class LogCheck(object):
    log = {
        'backlog_p': 'Qdisc backlog packets',
        'dropped': 'Qdisc dropped packets',
    }

    dev_re = re.compile(r'dev\s(\w+)\s')
    pkt_re = re.compile(r'\s(\d+)\spkt')

    qdisc_re = re.compile(r'qdisc\s(\w+)\s(\d+):')
    bytes_re = re.compile(r'\s(\d+)\sbytes')

    dropped_re = re.compile(r'dropped\s(\d+)')
    backlog_re = re.compile(r'backlog\s(\d+)[kKmMgG]?b\s(\d+)p')

    def __init__(self, logger, _config):
        self.logger = logger
        self.cmd = 'tc -s qdisc'
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
                self.logger.info('%s line numbers not equal' % self.cmd)
                return self.diff

            dev = ''
            qdisc = ''
            for i in range(len(new_lines)):
                nline = new_lines[i]
                oline = old_lines[i]

                if nline.startswith('qdisc'):
                    dev_mat = self.dev_re.search(nline)
                    if dev_mat:
                        dev = dev_mat.group(1)

                    qdisc_mat = self.qdisc_re.search(nline)
                    if qdisc_mat:
                        qdisc = qdisc_mat.group(1) + qdisc_mat.group(2)
                    continue

                if oline == nline:
                    continue

                oline = oline.strip()
                nline = nline.strip()

                qdisc_name = dev + '#' + qdisc
                if nline.startswith('Sent'):
                    o_sent_bytes = self.bytes_re.search(oline).group(1)
                    n_sent_bytes = self.bytes_re.search(nline).group(1)

                    if o_sent_bytes != n_sent_bytes:
                        o_sent_pkt = self.pkt_re.search(oline).group(1)
                        n_sent_pkt = self.pkt_re.search(nline).group(1)
                        self.diff[qdisc_name + '#bytes'] = (int(n_sent_bytes)
                                                            - int(o_sent_bytes))
                        self.diff[qdisc_name + '#pkt'] = (int(n_sent_pkt)
                                                          - int(o_sent_pkt))

                    o_dropped = self.dropped_re.search(oline).group(1)
                    n_dropped = self.dropped_re.search(nline).group(1)
                    if o_dropped != n_dropped:
                        self.diff[qdisc_name + '#dropped'] = (int(n_dropped)
                                                              - int(o_dropped))

                elif nline.startswith('backlog'):
                    o_backlog = self.backlog_re.search(oline).group(2)
                    n_backlog = self.backlog_re.search(nline).group(2)

                    if o_backlog != n_backlog:
                        self.diff[qdisc_name + '#backlog_p'] = \
                            int(n_backlog) - int(o_backlog)
        finally:
            self.old_stats = stats[1]

        return self.diff

    def do_action(self):
        stats = self.get_diff()
        for k, v in stats.items():
            dev, qd, tp = k.split('#')
            if tp in self.log:
                self.logger.info('%s %s %s: %s %s' %
                                 (dev, qd, tp, v, self.log[tp]))
