# coding: utf-8
import re


class LogCheck(object):
    cpu_cols = ['user', 'nice', 'system', 'idle', 'iowait', 'irq',
                'softirq', 'steal', 'guest', 'guest_nice']

    def __init__(self, logger, _config, **kwargs):
        self.logger = logger
        self.cpu_rate = {}
        self.cpu_high = {}
        self.cpu_stat = {}

        cpu_max = int(kwargs.get('cpumax'))
        if 0 < cpu_max <= 100:
            self.cpu_max = cpu_max
        else:
            self.cpu_max = 90
            self.logger.error('CPU usage threshold is not in range (0, 100], '
                              'use default 90')

    def do_action(self):
        f = open("/proc/stat", 'r')
        lines = f.readlines()

        cpus = []
        for line in lines:
            if re.search(r'cpu\d+', line):
                cpus.append(line.split())

        for cpu, cpu_data in enumerate(cpus):
            cpu_values = []
            for i, v in enumerate(cpu_data):
                if cpu not in self.cpu_stat:
                    self.cpu_stat[cpu] = [0] * len(self.cpu_cols)
                if i:
                    tmpv = int(v)
                    cpu_values.append(tmpv - self.cpu_stat[cpu][i - 1])
                    self.cpu_stat[cpu][i - 1] = tmpv
            total = sum(cpu_values)
            if total == 0:
                continue

            if cpu not in self.cpu_rate:
                self.cpu_rate[cpu] = [0, 0]
            # idle
            self.cpu_rate[cpu][0] = cpu_values[3] * 100 / float(total)

            if cpu not in self.cpu_high:
                self.cpu_high[cpu] = False

            idle = 100 - self.cpu_max
            if self.cpu_rate[cpu][0] < idle and not self.cpu_high[cpu]:
                self.cpu_high[cpu] = True
                self.logger.info(
                    "cpu:%d high rate:%.3f %s"
                    % (cpu, 100 - self.cpu_rate[cpu][0],
                       " ".join(
                           ["%s:%s" %
                            (self.cpu_cols[i], cpu_values[i]) for i
                            in range(len(cpu_values))]
                       ))
                )

            if self.cpu_rate[cpu][0] >= idle and self.cpu_high[cpu]:
                self.cpu_high[cpu] = False
                self.logger.info(
                    "cpu:%d low rate:%.3f %s"
                    % (cpu, 100 - self.cpu_rate[cpu][0],
                       " ".join(
                           ["%s:%s" %
                            (self.cpu_cols[i], cpu_values[i]) for i
                            in range(len(cpu_values))]
                       ))
                )
        f.close()
