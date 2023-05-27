# coding: utf-8
import re
from subprocess import getstatusoutput

slave_sync_stat = 0x3c


class LogCheck(object):
    bond_fields = ['MII Status', 'Speed', 'port state']

    def __init__(self, logger, _config):
        self.logger = logger
        self.bond_info = {}
        self.slave_info = {}

    @staticmethod
    def get_valid_bond():
        stats = getstatusoutput('lsmod|grep bonding')
        if stats[0]:
            return []

        res = []
        stats = getstatusoutput('cat /sys/class/net/bonding_masters')
        if stats[0] == 0:
            bond_port = stats[1].split()
            for bond in bond_port:
                bond_mode = getstatusoutput(
                    'cat /sys/class/net/%s/bonding/mode' % bond)
                if bond_mode[0] == 0 and bond_mode[1] == '802.3ad 4':
                    res.append(bond)
                    return res
        return res

    def get_bond4_stat2(self, bond):
        self.bond_info[bond] = []
        stats = getstatusoutput('cat /proc/net/bonding/%s' % bond)
        if stats[0] == 0:
            info_blocks = stats[1].split('\n\n')
            for info in info_blocks:
                if info.startswith('Slave Interface:'):
                    slave = [i.split('\n')[0].strip() for i in
                             info.split('Slave Interface: ')][1]
                    self.bond_info[bond].append(slave)
                    self.slave_info[slave] = {}
                    for field in self.bond_fields:
                        res = re.findall(r'%s:\s+(\w+)' % field, info)
                        self.slave_info[slave][field] = res

    def do_action(self):
        bond_ports = self.get_valid_bond()
        for bond in bond_ports:
            slave_speed = []
            lacp_failed = {}
            self.get_bond4_stat2(bond)
            bond_speed = getstatusoutput('cat /sys/class/net/%s/speed' % bond)
            for slave in self.bond_info[bond]:
                if self.slave_info[slave]['MII Status'][0] == 'up':
                    lacp_failed[slave] = []
                    speed = getstatusoutput(
                        'cat /sys/class/net/%s/speed' % slave)
                    slave_speed.append(int(speed[1]))
                    if not slave_sync_stat & int(
                            self.slave_info[slave]['port state'][0]):
                        lacp_failed[slave].append('actor')
                    if not slave_sync_stat & int(
                            self.slave_info[slave]['port state'][1]):
                        lacp_failed[slave].append('partner')
                if len(set(slave_speed)) != 1:
                    self.logger.info(
                        '{} slave\'s speed is different {}, '
                        'please check slave speed!!!'.format(bond, slave_speed))
                    return
                if sum(slave_speed) != int(bond_speed[1]):
                    self.logger.info(
                        '{} speed is abnormal!!! '
                        'slave_speed:{} bond_speed:{}'.format(
                            bond, sum(slave_speed), int(bond_speed[1])))
                    for k, v in lacp_failed.items():
                        if v:
                            self.logger.info(
                                '{}: {} is not synchronization({})'.format(
                                    bond, k, ' '.join(v)))
