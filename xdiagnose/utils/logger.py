# coding: utf-8
import os
import sys
import gzip
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler

from .config import config


logger = None
raw_logger = None

inspect_warn_logger = None


def gz_namer(name):
    return name + ".gz"


def gz_rotator(source, dest):
    sf = open(source, 'rb')
    df = gzip.open(dest, 'wb', compresslevel=1)
    df.writelines(sf)
    df.close()
    sf.close()
    os.remove(source)


class DiagFormatter(logging.Formatter):
    converter = datetime.fromtimestamp
    def formatTime(self, record, date_fmt=None):
        conv = self.converter(record.created)
        if date_fmt:
            s = conv.strftime(date_fmt)
        else:
            t = conv.strftime("%Y-%m-%d %H:%M:%S")
            s = "%s,%03d" % (t, record.msecs)
        return s


log_formatter = DiagFormatter(
    fmt='%(asctime)s|%(levelname)s| %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S.%f')
inspect_formatter = DiagFormatter(
    fmt='%(asctime)s\n%(message)s\n',
    datefmt='%Y-%m-%d %H:%M:%S.%f')


def logger_init():
    global logger
    global raw_logger
    global inspect_warn_logger

    if not logger:
        logger = get_rotate_logger(
                                'DIAG_LOG',
                                config.get('diaglog', 'LogFile'),
                                config.getint('diaglog', 'LogMaxMB'),
                                config.getint('diaglog', 'LogCount'),
                                log_formatter, None, True)

    if not raw_logger:
        raw_logger = get_rotate_logger(
                                'RAW_LOG',
                                config.get('rawlog', 'LogFile'),
                                config.getint('rawlog', 'LogMaxMB'),
                                config.getint('rawlog', 'LogCount'),
                                None, gz_rotator, False)

    if not inspect_warn_logger:
        inspect_warn_logger = get_rotate_logger(
                                'INSPECT_WARN_LOG',
                                config.get('inspect', 'WarnLogFile'),
                                config.getint('inspect', 'WarnLogMaxMB'),
                                config.getint('inspect', 'WarnLogCount'),
                                log_formatter, None, False)


def get_rotate_logger(name, log_file, max_mb, backups,
                      formatter, rotator, term):
    log_path = os.path.dirname(log_file)
    if not os.path.exists(log_path):
        os.makedirs(log_path)
        os.chmod(log_path, 0o0755)

    handler = RotatingFileHandler(filename=log_file, maxBytes=max_mb*1024*1024,
                                  backupCount=backups, encoding='utf-8')
    handler.setLevel(logging.DEBUG)

    if formatter:
        handler.setFormatter(formatter)

    if rotator:
        handler.rotator = rotator
        handler.namer = gz_namer

    _logger = logging.getLogger(name)
    _logger.setLevel(logging.DEBUG)
    _logger.addHandler(handler)

    if term:
        _logger.addHandler(logging.StreamHandler(sys.stdout))

    return _logger
