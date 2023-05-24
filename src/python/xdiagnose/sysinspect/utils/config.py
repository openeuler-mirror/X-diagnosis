# coding: utf-8
import os
from configparser import ConfigParser

CONF_NAME = 'sysinspect.conf'
SYS_CONF_DIR = '/etc/X-diagnosis'
REL_CONF_DIR = '../../../../../config'


def read_conf():
    conf = os.path.join(os.path.dirname(__file__), REL_CONF_DIR, CONF_NAME)
    if not os.path.exists(conf):
        conf = os.path.join(SYS_CONF_DIR, CONF_NAME)

    config = ConfigParser()
    config.read(conf)
    return config
