import socket
import struct
import sys
import threading
import time

from endhost.sciond import SCIONDaemon
from lib.packet.host_addr import haddr_parse

try:
    sd = SCIONDaemon.start(haddr_parse("IPV4", sys.argv[1]), sys.argv[2], len(sys.argv) == 3)
    while True:
        time.sleep(1000)
except KeyboardInterrupt:
    print("exit")
    sys.exit(0)
