# coding: utf-8
from subprocess import getstatusoutput
from xdiagnose.common.logger import inspect_warn_logger as logger


class LogConntrack(object):
    log = {
        'drop': 'Packet may not hit in window',
    }

    def __init__(self, cmd='cat /proc/net/stat/nf_conntrack'):
        self.cmd = cmd
        self.diff = {}
        self.old_stats = ''
        stats = getstatusoutput(self.cmd)
        if stats[0] == 0:
            self.old_stats = stats[1]
        else:
            logger.info('%s is not available' % self.cmd)

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
            title = new_lines[0].split()

            if len(old_lines) != len(new_lines):
                logger.info('%s line numbers not equal' % self.cmd)
                return self.diff

            for i in range(len(new_lines)):
                if old_lines[i] == new_lines[i]:
                    continue

                if i < 1:
                    logger.info('%s no title line' % self.cmd)
                    return self.diff

                old_elems = old_lines[i].split()
                new_elems = new_lines[i].split()
                if len(old_elems) != len(new_elems):
                    logger.info('%s elems numbers not equal' % self.cmd)
                    return self.diff

                for j in range(len(new_elems)):
                    if old_elems[j] != new_elems[j]:
                        stats_name = title[j] + '#cpu' + str(i - 1)
                        self.diff[stats_name] = int(new_elems[j], 16) - int(old_elems[j], 16)
        finally:
            self.old_stats = stats[1]

        return self.diff

    def do_action(self):
        stats = self.get_diff()
        for k, v in stats.items():
            col, cpu = k.split('#')
            if col in self.log:
                logger.info('conntrack: %s %s: %s %s' %
                            (cpu, col, v, self.log[col]))
