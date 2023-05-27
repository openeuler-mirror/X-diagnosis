# coding: utf-8
from subprocess import getstatusoutput

class LogCheck(object):
    def __init__(self, logger, config):
        self.logger = logger
        self.config = config
        self.mem_alarm = False
        self.swap_alarm = False

        self.mem_max = self.config.getint('log_memory', 'mem_max')
        self.swap_max = self.config.getint('log_memory', 'swap_max')
        if not 0 < self.mem_max <= 100:
            self.mem_max = 85
            self.logger.error('Total memory usage threshold is not in range (0, 100], '
                              'use default 85')
        if not 0 < self.swap_max <= 100:
            self.swap_max = 80
            self.logger.error('Swap memory usage threshold is not in range (0, 100], '
                              'use default 80')

    def do_action(self):
        item = '[memory_check]'
        meminfo = {}

        cmd = 'cat /proc/meminfo'
        stats = getstatusoutput(cmd)
        if stats[0] != 0:
            self.logger.info('%s%s is not available' % (item, cmd))
            return
        lines = stats[1].split('\n')
        for line in lines:
            elems = line.split()
            meminfo[elems[0][:-1]] = elems[1]

        mem_total = int(meminfo['MemTotal'])
        mem_available = int(meminfo['MemAvailable'])
        swap_total = int(meminfo['SwapTotal'])
        swap_free = int(meminfo['SwapFree'])

        if mem_total <= 0 or mem_available <= 0:
            self.logger.error('%smeminfo get failed in /proc/meminfo' % item)
            return

        memory_percent = (mem_total - mem_available) * 100 / mem_total
        if memory_percent >= self.mem_max and not self.mem_alarm:
            self.mem_alarm = True
            slab_total = int(meminfo['Slab'])

            self.logger.info('%smemory usage alarm: %d%%' % (item, memory_percent))
            for line in lines:
                self.logger.info(line)
            cmd = 'ps -eo user,pid,ppid,%cpu,%mem,rsz,rss,stat,time,comm --sort=-rss | head -11'
            stats = getstatusoutput(cmd)
            if stats[0] != 0:
                self.logger.info('%s%s is not available' % (item, cmd))
                return
            lines = stats[1].split('\n')
            self.logger.info('%sThe top 10 processes with the most memory usage are:' % item)
            for line in lines:
                self.logger.info(line)

            if slab_total <= 0:
                self.logger.error('%sslabinfo get failed in /proc/meminfo'% item)
                return
            slab_percent = slab_total * 100 / mem_total
            if slab_percent > 20:
                num = 10
                slabinfo = []

                cmd = 'cat /proc/slabinfo'
                stats = getstatusoutput(cmd)
                if stats[0] != 0:
                    self.logger.info('%s%s is not available' % (item, cmd))
                    return
                lines = stats[1].split('\n')
                for i in range(2, len(lines)):
                    line = lines[i].split()
                    use = int(line[2]) * int(line[3]) / 1024 / 1024
                    slabinfo.append([line[0], use])
                slabinfo.sort(key=lambda x: x[1], reverse=True)
                if len(slabinfo) > num:
                    slabinfo = slabinfo[:num + 1]
                self.logger.info('%sThe top 10 objects with the most slab memory usage are:' % item)
                self.logger.info('%-25s%s' % ('slab_name', 'slab_memory_use(MB)'))
                for elems in slabinfo:
                    self.logger.info('%-25s%.2f' % (elems[0], elems[1]))

        elif memory_percent < self.mem_max and self.mem_alarm:
            self.mem_alarm = False
            self.logger.info('%smemory usage resume: %d%%' % (item, memory_percent))

        if swap_total > 0 and swap_free > 0:
            swap_percent = (swap_total - swap_free) * 100 / swap_total
            if swap_percent >= self.swap_max and not self.swap_alarm:
                self.swap_alarm = True
                self.logger.info('%sswap memory usage alarm: %d%%' % (item, swap_percent))
            elif swap_percent < self.swap_max and self.swap_alarm:
                self.swap_alarm = False
                self.logger.info('%smemory usage resume: %d%%' % (item, swap_percent))
