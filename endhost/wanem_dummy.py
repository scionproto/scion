import sys
import time

from endhost.wanem_sciond import SCIONDaemon
from lib.packet.host_addr import haddr_parse

try:
    sd = SCIONDaemon.start(haddr_parse("IPV4", sys.argv[1]), sys.argv[2],
                           len(sys.argv) == 3)
    while True:
        time.sleep(1000)
except KeyboardInterrupt:
    sd.clean()
    print("exit")
    sys.exit(0)
