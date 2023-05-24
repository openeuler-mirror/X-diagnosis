# coding: utf-8
import sys
import signal
import time
import traceback

from .arguments import parser
from .utils.logger import logger
from .sysinspect.inspect import Inspector
from .cmdfile.eftrace import EftraceModule

from .ntrace.enter import NetModule


inspector = None
modules = {
    'ntrace': NetModule,
    'eftrace': EftraceModule,
}


def sig_handler(signum, _f):
    if signum == signal.SIGHUP:
        inspector.reload()
    else:
        sys.exit(0)


def main():
    global inspector
    mod = None

    try:
        signal.signal(signal.SIGINT,  sig_handler)
        signal.signal(signal.SIGTERM, sig_handler)
        signal.signal(signal.SIGHUP,  sig_handler)

        args = parser.parse_args()
        if args.inspect:
            inspector = Inspector()
            inspector.start_inspect()

        if args.module in modules:
            mod = modules[args.module](args)
            mod.run()
        elif not args.inspect:
            parser.print_help()
            raise NotImplementedError()

        if args.inspect:
            while True:
                time.sleep(1)

    except NotImplementedError as e:
        logger.error(e)
    except Exception:
        logger.error('%s' % traceback.format_exc())
    finally:
        if mod and hasattr(mod, 'stop'):
            mod.stop()
        if inspector:
            inspector.stop_inspect()
