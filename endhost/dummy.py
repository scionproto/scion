import sys
import time

from endhost.sciond import SCIONDaemon
from lib.packet.host_addr import haddr_parse

try:
    sd = SCIONDaemon.start(sys.argv[1], haddr_parse("IPV4", sys.argv[2]),
                           sys.argv[3], len(sys.argv) == 4)
    while True:
        time.sleep(1000)
except KeyboardInterrupt:
    print("exit")
    sys.exit(0)
