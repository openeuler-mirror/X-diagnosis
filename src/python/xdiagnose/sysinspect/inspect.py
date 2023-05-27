# coding: utf-8
import os
import threading
import importlib

from .utils.logger import logger_init, reload_logger
from .utils.config import read_conf

FILE_DIR = os.path.dirname(__file__)
MOD_DIRS = ['common', 'net', 'custom']


class Inspector(object):
    def __init__(self):
        self.timer = None
        self.modules = []
        self.config = read_conf()
        self.logger = logger_init()
        self.interval = self.config.getint('inspect', 'Interval', fallback=3)

    def reg_modules(self):
        for mod_dir in MOD_DIRS:
            mod_files = os.listdir(os.path.join(FILE_DIR, mod_dir))
            for mod_file in mod_files:
                if not mod_file.endswith('.py'):
                    continue
                mod = mod_file[:-3]
                if (mod in self.config['modules']
                        and self.config['modules'][mod] == 'on'):
                    i_mod = importlib.import_module(__name__.rsplit('.', 1)[0]
                                                    + '.' + mod_dir
                                                    + '.' + mod)
                    importlib.reload(i_mod)
                    self.modules.append(
                        i_mod.LogCheck(self.logger, self.config))

    def start_inspecttimer(self):
        self.timer = threading.Timer(self.interval, self.do_inspection)
        self.timer.start()

    def do_inspection(self):
        for mod in self.modules:
            mod.do_action()
        self.start_inspecttimer()

    def start_inspect(self):
        self.reg_modules()
        self.start_inspecttimer()

    def stop_inspect(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None

    def reload(self):
        self.stop_inspect()
        self.config = read_conf()
        reload_logger()
        self.modules = []
        self.start_inspect()
