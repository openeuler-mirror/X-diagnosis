# coding: utf-8
import socket
import threading

from subprocess import getstatusoutput
from xdiagnose.common.logger import inspect_warn_logger as logger

class LogCommonCheck(object):

    def __init__(self):
        self.cmd = {'sysctl'    : 'cat /etc/sysctl.conf',
                    'arping'    : 'arping -D -c 3',
                    'memory'    : 'cat /proc/meminfo',
                    'sshd'      : 'cat /etc/ssh/sshd_config',
                    'disk'      : 'df -h',
                    'inode'     : 'df -i'}

        self.old_stats = {'sysctl' : 'NA'}

        self.sshd_config = {'AllowUsers'        : 'NA',
                            'DenyUsers'         : 'NA',
                            'MaxAuthTries'      : 'NA',
                            'MaxSessions'       : 'NA',
                            'PermitRootLogin'   : 'NA',
                            'UsePAM'            : 'NA'}

        self.service_status = {}

        self.diff = {}

    def service_status_check(self, name):
        cmd = 'systemctl status ' + name
        stats = getstatusoutput(cmd)

        if name not in self.service_status:
            self.service_status[name] = 0

        if self.service_status[name] != stats[0]:
            self.service_status[name] = stats[0]

            if stats[0] == 0:
                logger.info('service %s is active' % name)

            else:
                logger.info('service %s status error with return %d, use <%s> show details' %
                            (name, stats[0], cmd))

        return stats[0]

    def disk_check(self, cmd):
        stats = getstatusoutput(cmd)
        if stats[0] != 0:
            logger.info('%s is not available' % cmd)
            return

        lines = stats[1].split('\n')
        for i in range(1, len(lines)):
            elems = lines[i].split()
            if elems[0] == 'tmpfs' or elems[0] == 'devtmpfs':
                continue

            used = int(elems[4][:-1])
            if used >= 90:
                logger.info('[%s][%s] is used over %d%%, use <%s> show details'
                               % ('disk_check', elems[0], used, cmd))

    def memory_check(self, cmd):
        meminfo = {}

        stats = getstatusoutput(cmd)
        if stats[0] != 0:
            logger.info('%s is not available' % cmd)
            return

        lines = stats[1].split('\n')
        for line in lines:
            elems = line.split()
            meminfo[elems[0][:-1]] = elems[1]

        MemTotal = int(meminfo['MemTotal'])
        MemAvailable = int(meminfo['MemAvailable'])
        memory_percent = (MemTotal - MemAvailable) * 100 / MemTotal

        SwapTotal = int(meminfo['SwapTotal'])
        SwapFree = int(meminfo['SwapFree'])
        swap_percent = (SwapTotal - SwapFree) * 100 / SwapTotal

        if memory_percent > 80:
            logger.info('The memory has used over %d%%' % memory_percent)
        if swap_percent > 70:
            logger.info('The swap memory has used over %d%%' % swap_percent)

    def get_sysctl_diff(self):
        self.diff = {}

        if not self.old_stats['sysctl']:
            return self.diff

        stats = getstatusoutput(self.cmd['sysctl'])
        if stats[0] != 0:
            logger.info('%s is not available' % self.cmd['sysctl'])
            return self.diff

        if self.old_stats['sysctl'] == 'NA':
            self.old_stats['sysctl'] = stats[1]
            return self.diff

        try:
            old_lines = self.old_stats['sysctl'].split('\n')
            new_lines = stats[1].split('\n')

            if len(old_lines) != len(new_lines):
                logger.info('%s line numbers not equal' % self.cmd['sysctl'])
                return self.diff

            for i in range(len(new_lines)):
                if new_lines[i] == '' or new_lines[i][0] == '#':
                    continue

                if new_lines[i] == old_lines[i]:
                    continue

                old_elems = old_lines[i].split('=')
                new_elems = new_lines[i].split('=')

                if len(old_elems) != len(new_elems):
                    logger.info('%s elems numbers not equal' % self.cmd['sysctl'])
                    return self.diff

                if old_elems[1] != new_elems[1]:
                    self.diff[new_elems[0]] = old_elems[1] + ' -> ' + new_elems[1]

        finally:
            self.old_stats['sysctl'] = stats[1]

        return self.diff

    def sysctl_check(self, cmd):
        stats = self.get_sysctl_diff()
        for k, v in stats.items():
            logger.info('[%s]%s: %s' % ('sysctl_check', k, v))

    def ntp_check(self):
        cmd = 'ntpd'
        if self.service_status_check(cmd):
            return

        cmd = 'ntpq -p'
        stats = getstatusoutput(cmd)
        if stats[0] != 0:
            logger.info('%s is not available' % cmd)
            return

        lines = stats[1].split('\n')
        for i in range(2, len(lines)):
            ntp_server = lines[i].split()

            if ntp_server[0][0] == '*':
                ip_addr = ntp_server[0][1:]
                cmd = 'ntpdate -d ' + ip_addr

                stats = getstatusoutput(cmd)
                if stats[0] != 0:
                    logger.info('%s is not available' % cmd)
                return

        cmd = 'ntpq -p'
        logger.info('[ntp_check] ntp server status error, use <%s> show deatils' % cmd)

    def ip_conflict_check(self, ip_addr = '', device = ''):
        if ip_addr == '':
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(('8.8.8.8', 80))
                ip_addr = s.getsockname()[0]

            finally:
                s.close()

        cmd = self.cmd['arping'] + ' ' + ip_addr

        if device != '':
            cmd = cmd + ' -I ' + device

        stats = getstatusoutput(cmd)
        if stats[0] != 0:
            logger.info('[%s]%s\n%s' % ('ip_conflict_check', cmd, stats[1]))

    def get_sshd_diff(self):
        self.diff = {}

        if not self.sshd_config:
            return self.diff

        stats = getstatusoutput(self.cmd['sshd'])
        if stats[0] != 0:
            logger.info('%s is not available' % self.cmd[sshd])
            return self.diff
        lines = stats[1].split('\n')

        for line in lines:
            if line == '':
                continue

            elems = line.split()
            if elems[0] in self.sshd_config and self.sshd_config[elems[0]] != elems[1]:
                if self.sshd_config[elems[0]] != 'NA':
                    self.diff[elems[0]] = self.sshd_config[elems[0]] \
                        + ' -> ' + elems[1]

                self.sshd_config[elems[0]] = elems[1]

        return self.diff

    def sshd_check(self):
        stats = self.get_sshd_diff()
        for k, v in stats.items():
            logger.info('[%s]%s: %s' % ('sshd_check config', k, v))

    def dns_check(self,  host_name = ''):
        if host_name == '':
            host_name = socket.gethostname()

        try:
            ip_addr = socket.gethostbyname(host_name)

        except Exception:
             logger.info('dns[%s] parse timeout' % host_name)

    def do_action(self):
        self.disk_check(self.cmd['disk'])
        self.disk_check(self.cmd['inode'])
        self.memory_check(self.cmd['memory'])
        self.sysctl_check(self.cmd['sysctl'])
        self.ntp_check()
        self.sshd_check()
        self.ip_conflict_check()

        t = threading.Thread(target = self.dns_check())
        t.setDaemon(True)
        t.start()
        t.join(timeout = 2)

