
import sys
import logging

from datetime import datetime as dt
from colorama import Fore, Style, init

init(autoreset=True)


class ColoredStreamHandler(logging.StreamHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stream = sys.stdout

    def emit(self, record):
        try:
            msg = self.format(record)
            level = record.levelname
            color = {
                'DEBUG': Fore.YELLOW,
                'INFO': Fore.BLUE,
                'WARNING': Fore.MAGENTA,
                'ERROR': Fore.RED,
                'CRITICAL': Fore.RED + Style.BRIGHT
            }.get(level, Fore.RESET)
            self.stream.write(color + msg + Style.RESET_ALL)
            self.stream.write(self.terminator)
        except RecursionError:  # See issue 36272
            raise
        except Exception:
            self.handleError(record)

app = "securityGroupManager"
current_time = dt.now().strftime("%Y%m%d")
logger = logging.getLogger(app)
logger.setLevel(logging.DEBUG)

console_handler = ColoredStreamHandler()
console_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)
