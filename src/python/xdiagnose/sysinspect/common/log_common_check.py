# coding: utf-8
import socket
import threading
import traceback
from subprocess import getstatusoutput


class LogCheck(object):
    def __init__(self, logger, config):
        self.logger = logger
        self.config = config

        self.cmd = {
            'sysctl': 'sysctl -a',
            'arping': 'arping -w 3 -c 1',
            'memory': 'cat /proc/meminfo',
            'sshd':   'cat /etc/ssh/sshd_config',
            'disk':   'df -h',
            'inode':  'df -i'
        }

        self.sshd_config = {
            'AllowUsers':      'NA',
            'DenyUsers':       'NA',
            'MaxAuthTries':    'NA',
            'MaxSessions':     'NA',
            'PermitRootLogin': 'NA',
            'UsePAM':          'NA'
        }

        self.sysctl_stats = {}
        self.service_stats = {}
        self.diff = {}

        self.sysctl_init()

    def service_status_check(self, name):
        cmd = 'systemctl status ' + name
        stats = getstatusoutput(cmd)

        if name not in self.service_stats:
            self.service_stats[name] = 0

        if self.service_stats[name] != stats[0]:
            self.service_stats[name] = stats[0]

            if stats[0] == 0:
                self.logger.info('service %s is active' % name)

            else:
                self.logger.info(
                    'service %s status error with return %d, use <%s> show details' %
                    (name, stats[0], cmd))

        return stats[0]

    def disk_check(self, cmd):
        stats = getstatusoutput(cmd)
        if stats[0] != 0:
            self.logger.info('%s is not available' % cmd)
            return

        lines = stats[1].split('\n')
        for i in range(1, len(lines)):
            elems = lines[i].split()
            if elems[0] == 'tmpfs' or elems[0] == 'devtmpfs':
                continue
            if elems[4] == '-':
                continue

            used = int(elems[4][:-1])
            if used >= 90:
                self.logger.info(
                    '[%s][%s] is used over %d%%, use <%s> show details'
                    % ('disk_check', elems[0], used, cmd))

    def memory_check(self, cmd):
        meminfo = {}

        stats = getstatusoutput(cmd)
        if stats[0] != 0:
            self.logger.info('%s is not available' % cmd)
            return

        lines = stats[1].split('\n')
        for line in lines:
            elems = line.split()
            meminfo[elems[0][:-1]] = elems[1]

        SwapTotal = int(meminfo['SwapTotal'])
        SwapFree = int(meminfo['SwapFree'])

        if SwapTotal != 0 and SwapFree != 0:
            swap_percent = (SwapTotal - SwapFree) * 100 / SwapTotal
            if swap_percent > 70:
                self.logger.info(
                    'The swap memory has used over %d%%' % swap_percent)

        MemTotal = int(meminfo['MemTotal'])
        MemAvailable = int(meminfo['MemAvailable'])

        if MemTotal != 0 and MemAvailable != 0:
            memory_percent = (MemTotal - MemAvailable) * 100 / MemTotal
            if memory_percent > 80:
                self.logger.info(
                    'The memory has used over %d%%' % memory_percent)

    def sysctl_init(self):
        f = open("/etc/sysctl.conf", 'r')
        lines = f.readlines()

        for line in lines:
            if line == '' or line[0] == '#':
                continue

            elems = line.split('=')
            self.sysctl_stats[elems[0]] = 'NA'

        f.close()

    def get_sysctl_diff(self):
        self.diff = {}

        stats = getstatusoutput(self.cmd['sysctl'])
        if stats[0] != 0:
            self.logger.info('%s is not available' % self.cmd['sysctl'])
            return self.diff

        try:
            lines = stats[1].split('\n')

            for line in lines:
                elems = line.split()

                if (elems[0] in self.sysctl_stats
                        and self.sysctl_stats[elems[0]] != elems[2]):
                    if self.sysctl_stats[elems[0]] == 'NA':
                        self.diff[elems[0]] = elems[2]
                    else:
                        self.diff[elems[0]] = (self.sysctl_stats[elems[0]]
                                               + ' -> '
                                               + elems[2])

                    self.sysctl_stats[elems[0]] = elems[2]

        except Exception:
            self.logger.error('%s' % traceback.format_exc())

        return self.diff

    def sysctl_check(self):
        stats = self.get_sysctl_diff()
        for k, v in stats.items():
            self.logger.info('[%s]%s: %s' % ('sysctl_check', k, v))

    def fd_check(self):
        f = open("/proc/sys/fs/file-nr", 'r')
        line = f.readline()
        elems = line.split()

        if int(elems[0]) != 0:
            fd_used = int(elems[0]) * 100 / int(elems[2])

            if fd_used > 90:
                self.logger.info(
                    '[%s]%s has used over %d%%' % ('fd_check', 'fd', fd_used))

    def ntp_check(self):
        cmd = 'ntpd'
        if self.service_status_check(cmd):
            return

        cmd = 'ntpq -pn'
        stats = getstatusoutput(cmd)
        if stats[0] != 0:
            self.logger.info('%s is not available' % cmd)
            return

        lines = stats[1].split('\n')
        for i in range(2, len(lines)):
            ntp_server = lines[i].split()

            if ntp_server[0][0] == '*':
                ip_addr = ntp_server[0][1:]
                if ip_addr[:7] == '127.127':
                    return

                cmd = 'ntpdate -d ' + ip_addr
                stats = getstatusoutput(cmd)
                if stats[0] != 0:
                    self.logger.info('%s is not available' % cmd)
                return

        cmd = 'ntpq -p'
        self.logger.info(
            '[ntp_check] ntp server status error, use <%s> show details' % cmd)

    def ip_conflict_check(self, ip_addr='', device=''):
        if ip_addr == '':
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(('8.8.8.8', 80))
                ip_addr = s.getsockname()[0]

            except Exception:
                self.logger.error('%s' % traceback.format_exc())
            finally:
                s.close()

        if device == '':
            cmd = 'ip route | grep ' + ip_addr + ' | awk -F \'[ \\t*]\' \'{print $3}\''
            stats = getstatusoutput(cmd)
            if stats[0] != 0:
                self.logger.info('%s is not available' % cmd)
                return

            device = stats[1]

        cmd = self.cmd['arping'] + ' ' + ip_addr + ' -I ' + device
        stats = getstatusoutput(cmd)
        if stats[0] != 0:
            lines = stats[1].split('\n')
            if lines[len(lines) - 1] == 'Received 0 response(s)':
                return

            self.logger.info('[%s]%s return code = %d\n%s' % (
                'ip_conflict_check', cmd, stats[0], stats[1]))

    def get_sshd_diff(self):
        self.diff = {}

        if not self.sshd_config:
            return self.diff

        stats = getstatusoutput(self.cmd['sshd'])
        if stats[0] != 0:
            self.logger.info('%s is not available' % self.cmd[sshd])
            return self.diff
        lines = stats[1].split('\n')

        for line in lines:
            if line == '':
                continue

            elems = line.split()
            if elems[0] in self.sshd_config and \
                    self.sshd_config[elems[0]] != elems[1]:
                if self.sshd_config[elems[0]] != 'NA':
                    self.diff[elems[0]] = \
                        self.sshd_config[elems[0]] + ' -> ' + elems[1]

                self.sshd_config[elems[0]] = elems[1]

        return self.diff

    def sshd_check(self):
        stats = self.get_sshd_diff()
        for k, v in stats.items():
            self.logger.info('[%s]%s: %s' % ('sshd_check config', k, v))

    def dns_check(self, host_name=''):
        if host_name == '':
            host_name = socket.gethostname()

        try:
            ip_addr = socket.gethostbyname(host_name)
        except Exception:
            self.logger.info('dns[%s] parse timeout' % host_name)

    def do_action(self):
        self.disk_check(self.cmd['disk'])
        self.disk_check(self.cmd['inode'])
        self.memory_check(self.cmd['memory'])
        self.sysctl_check()
        self.fd_check()
        self.ntp_check()
        self.sshd_check()
        self.ip_conflict_check()

        t = threading.Thread(target=self.dns_check())
        t.setDaemon(True)
        t.start()
        t.join(timeout=2)
