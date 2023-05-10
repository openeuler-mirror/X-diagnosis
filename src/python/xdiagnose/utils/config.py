# coding: utf-8
import os
from configparser import ConfigParser


config = None


def read_conf():
    global config

    if config:
        return

    conf = os.path.join(os.path.dirname(__file__), '../../../../config/', 'diag.conf')
    if not os.path.exists(conf):
        conf = '/etc/x-diagnose/diag.conf'

    config = ConfigParser()
    config.read(conf)
