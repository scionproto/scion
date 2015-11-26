# Stdlib
import os
import subprocess
import sys

# SCION
from endhost.sciond import SCIONDaemon
from lib.log import init_logging
from lib.main import main_wrapper
from lib.packet.host_addr import haddr_parse
from lib.util import handle_signals


def main():
    handle_signals()
    init_logging("logs/sciond.%s" % sys.argv[2])
    SCIONDaemon.start(sys.argv[1], haddr_parse("IPV4", sys.argv[2]),
                      sys.argv[3], len(sys.argv) == 5)
    cdir = os.path.dirname(os.path.realpath(__file__))
    cmd = os.path.join(cdir, sys.argv[4] + "_dispatcher")
    subprocess.call([cmd, sys.argv[2]])

if __name__ == "__main__":
    main_wrapper(main)
