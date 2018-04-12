#!/usr/bin/python3
# Copyright 2016 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`tcp_test` --- Dummy TCP Client/Server test.
=================================================
"""
# TODO(PSz): drop this test when TCP is integrated within the end2end test.

# Stdlib
import random
import struct
import threading
import time

# SCION
from lib.packet.host_addr import haddr_parse
from lib.packet.scion_addr import ISD_AS, SCIONAddr
from lib.packet.svc import SVCType
from lib.tcp.socket import SCIONTCPSocket, SockOpt
from lib.util import recv_all
from integration.base_cli_srv import start_sciond

s_isd_as = ISD_AS("1-ff00:0:122")
s_ip = haddr_parse(1, "127.1.1.1")
c_isd_as = ISD_AS("2-ff00:0:222")
c_ip = haddr_parse(1, "127.2.2.2")
# TODO(PSz): test with 0
MAX_MSG_SIZE = 500000


def get_msg():
    size = random.randint(1, MAX_MSG_SIZE)
    return struct.pack("!I", size) + b"A"*size


def server(svc=False):
    print("server running")
    s = SCIONTCPSocket()
    print('setsockopt')
    s.setsockopt(SockOpt.SOF_REUSEADDR)
    print(s.getsockopt(SockOpt.SOF_REUSEADDR))
    addr = SCIONAddr.from_values(s_isd_as, s_ip)
    if svc:
        s.bind((addr, 6000), svc=SVCType.PS_A)
    else:
        s.bind((addr, 5000))
    s.listen()
    while True:
        new_sock, addr, path = s.accept()
        print("Accepted: addr and path:", addr, path)
        msg = get_msg()
        # time.sleep(10)
        new_sock.send(msg)
        new_sock.close()


def client(svc, counter):
    def get_path_info(myaddr, dst_isd_as):
        sd = start_sciond(myaddr)
        path = sd.get_paths(dst_isd_as)[0]
        if_id = path.get_fwd_if()
        return (path, sd.ifid2br[if_id].addr, sd.ifid2br[if_id].port)

    print("client %d running:" % counter)
    s = SCIONTCPSocket()
    caddr = SCIONAddr.from_values(c_isd_as, c_ip)
    s.bind((caddr, 0))
    path_info = get_path_info(caddr, s_isd_as)
    print(path_info)

    if svc:
        saddr = SCIONAddr.from_values(s_isd_as, SVCType.PS_A)
        s.connect(saddr, 0, *path_info)  # SVC does not have a port specified
    else:
        saddr = SCIONAddr.from_values(s_isd_as, s_ip)
        s.connect(saddr, 5000, *path_info)
    # s.set_recv_tout(5.0)
    # print(s.get_recv_tout())
    start = time.time()
    size = struct.unpack("!I", recv_all(s, 4, 0))[0]
    tmp = b''
    print("To receive: %dB" % size)
    while len(tmp) != size:
        tmp += s.recv(1024)
        print('.', end="", flush=True)
    print("\nMSG received, len, svc", len(tmp), svc)
    time_elapsed = time.time()-start
    print("Time elapsed: %s, speed %.2fkB/s\n" % (time_elapsed,
                                                  size/time_elapsed/1000))
    s.close()


threading.Thread(target=server, args=[False]).start()
threading.Thread(target=server, args=[True]).start()
time.sleep(0.5)
for i in range(10):
    # input()
    # time.sleep(0.005)
    # threading.Thread(target=client, args=[False, i]).start()
    svc = (i % 2 == 0)
    start = time.time()
    client(svc, i)
