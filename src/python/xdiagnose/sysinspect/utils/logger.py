# coding: utf-8
import os
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler

from .config import read_conf

inspect_logger = None
inspect_handler = None


class InsFormatter(logging.Formatter):
    converter = datetime.fromtimestamp

    def formatTime(self, record, date_fmt=None):
        conv = self.converter(record.created)
        if date_fmt:
            s = conv.strftime(date_fmt)
        else:
            t = conv.strftime("%Y-%m-%d %H:%M:%S")
            s = "%s,%03d" % (t, record.msecs)
        return s


log_formatter = InsFormatter(
    fmt='%(asctime)s|%(levelname)s| %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S.%f')


def logger_init():
    global inspect_logger

    config = read_conf()
    inspect_logger = get_rotate_logger(
        'inspect_log',
        config.get('inspect', 'WarnLogFile'),
        config.getint('inspect', 'WarnLogMaxMB'),
        config.getint('inspect', 'WarnLogCount'),
        log_formatter
    )
    return inspect_logger


def reload_logger():
    global inspect_logger, inspect_handler

    config = read_conf()
    inspect_logger.removeHandler(inspect_handler)
    inspect_handler = get_handler(
        config.get('inspect', 'WarnLogFile'),
        config.getint('inspect', 'WarnLogMaxMB'),
        config.getint('inspect', 'WarnLogCount'),
        log_formatter
    )
    inspect_logger.addHandler(inspect_handler)


def get_handler(logfile, max_mb, backups, formatter):
    handler = RotatingFileHandler(filename=logfile,
                                  maxBytes=max_mb * 1024 * 1024,
                                  backupCount=backups,
                                  encoding='utf-8')
    handler.setLevel(logging.DEBUG)

    if formatter:
        handler.setFormatter(formatter)
    return handler


def get_rotate_logger(name, logfile, max_mb, backups, formatter):
    global inspect_handler

    log_path = os.path.dirname(logfile)
    if not os.path.exists(log_path):
        os.makedirs(log_path)
        os.chmod(log_path, 0o0755)

    inspect_handler = get_handler(logfile, max_mb, backups, formatter)
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(inspect_handler)
    return logger
