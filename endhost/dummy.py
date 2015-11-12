# Stdlib
import sys
import time

# SCION
from endhost.sciond import SCIONDaemon
from lib.log import init_logging
from lib.main import main_wrapper
from lib.packet.host_addr import haddr_parse
from lib.util import handle_signals


def main():
    handle_signals()
    init_logging("logs/sciond.%s.log" % sys.argv[2])
    SCIONDaemon.start(sys.argv[1], haddr_parse("IPV4", sys.argv[2]),
                      sys.argv[3], len(sys.argv) == 4)
    while True:
        time.sleep(1000)

if __name__ == "__main__":
    main_wrapper(main)
