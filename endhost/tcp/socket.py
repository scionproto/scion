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
:mod:`socket` --- SCION TCP socket.
===================================
"""
# Stdlib
import os
import socket as stdsock # To avoid name collision
import struct
import time
import uuid

# SCION
from lib.packet.host_addr import haddr_parse
from lib.packet.scion import SVCType
from lib.packet.scion_addr import ISD_AS, SCIONAddr

# TODO(PSz): that should be somewhere in the SCION python's lib:
SVC_BS = 0
SVC_PS = 1
SVC_CS = 2
SVC_SB = 3
NO_SVC = 0xffff  # No service associated with the socket

LWIP_SOCK_DIR = "/run/shm/lwip/"
RPCD_SOCKET = "/run/shm/lwip/lwip"
AF_SCION = 11
SOCK_STREAM = stdsock.SOCK_STREAM
MAX_MSG_LEN = 2<<31  # u32_t is used as size_t at rpcd
CMD_SIZE = 4
RESP_SIZE = CMD_SIZE + 2  # either "OK" or "ER" is appended


class error(stdsock.error):
    pass

def get_path(isd, ad):
    return b"PATH0PATH1PATH23"


class SCIONSocket(object):
    BUFLEN = 1024

    def __init__(self, family, type_, proto=0, name=''):
        assert family == AF_SCION
        assert type_ == SOCK_STREAM
        assert proto == 0
        self._family = family
        self._type = type_
        self._proto = proto
        self._lwip_sock = None
        self._lwip_accept = None
        self._recv_buf = b''
        self._name = name # debug only

    def bind(self, addr_port, svc=NO_SVC):
        addr, port = addr_port
        haddr_type = addr.host.TYPE
        req = b"BIND" + struct.pack("HHB", port, svc, haddr_type) + addr.pack()
        self._to_lwip(req)
        rep = self._from_lwip()
        if rep != b"BINDOK":
            raise error("bind() failed: %s" % rep)

    def connect(self, addr_port, path=None):
        addr, port = addr_port
        haddr_type = addr.host.TYPE
        if path is None:
            path = get_path(addr.isd_as[0], addr.isd_as[1])
        req = (b"CONN" + struct.pack("HH", port, len(path)) + path +
               struct.pack("B", haddr_type) + addr.pack())
        self._to_lwip(req)
        rep = self._from_lwip()
        if rep != b"CONNOK":
            raise error("connect() failed: %s" % rep)

    def create_socket(self):
        assert self._lwip_sock is None
        # Create a socket to LWIP
        self._lwip_sock = stdsock.socket(stdsock.AF_UNIX, stdsock.SOCK_STREAM)
        self._lwip_sock.connect(RPCD_SOCKET)
        # Register it
        req = b"NEWS"
        self._to_lwip(req)
        rep = self._from_lwip()
        if rep != b"NEWSOK":
            self._lwip_sock.close()
            raise error("socket() failed: %s" % rep)

    def _to_lwip(self, req):
        print(self._name, "Sending to LWIP(%dB):" % len(req), req[:20])
        self._lwip_sock.sendall(req)  # TODO(PSz): we may consider send(). For
        # now assuming that local socket is able to transfer req.

    def _from_lwip(self, buflen=None):
        if buflen is None:
            buflen=self.BUFLEN
        rep = self._lwip_sock.recv(buflen)  # read in a loop
        print(self._name, "Reading from LWIP(%dB):" % len(rep), rep[:20])
        return rep

    def listen(self): # w/o backlog for now, let's use LWIP's default
        req = b"LIST"
        self._to_lwip(req)
        rep = self._from_lwip()
        if rep != b"LISTOK":
            raise error("list() failed: %s" % rep)

    def accept(self):
        self._init_accept_sock()
        self._lwip_accept.listen(5)  # should be consistent with LWIP's backlog
        req = b"ACCE" + self._lwip_accept.getsockname()[-36:].encode('ascii')
        self._to_lwip(req)

        rep = self._from_lwip()
        if rep[:6] != b"ACCEOK":
            raise error("accept() failed (old sock): %s" % rep)
        print(self._name, "path, addr", rep)
        rep = rep[6:]
        path_len, = struct.unpack("H", rep[:2])
        rep = rep[2:]
        # TODO(PSz): instantiate path
        path = rep[:path_len]
        rep = rep[path_len:]
        addr = SCIONAddr((rep[0], rep[1:]))

        new_sock, _ = self._lwip_accept.accept()
        rep = new_sock.recv(self.BUFLEN)
        if rep != b"ACCEOK":
            raise error("accept() failed (new sock): %s" % rep)
        print(self._name, "From accept socket: ", rep)
        sock = SCIONSocket(self._family, self._type, self._proto, name="NEW_ACC%s"
                           % time.time())
        sock.set_lwip_sock(new_sock)
        return sock, addr, path

    def set_lwip_sock(self, sock):  # Can be only executed by accept().
        self._lwip_sock = sock

    def _init_accept_sock(self):
        if self._lwip_accept:
            return
        fname = "%s%s" % (LWIP_SOCK_DIR, uuid.uuid4())
        while os.path.exists(fname):  # TODO(PSz): add max_tries
            fname = "%s%s" % (LWIP_SOCK_DIR, uuid.uuid4())
        print(self._name, "_init_accept:", fname)
        self._lwip_accept = stdsock.socket(stdsock.AF_UNIX, stdsock.SOCK_STREAM)
        self._lwip_accept.bind(fname)

    def send(self, msg):
        # Due to underlying LWIP this method is quite binary: it returns length
        # of msg if it is sent, or throws exception otherwise.  Thus it might be
        # safer to use it with smaller msgs.
        if len(msg) > MAX_MSG_LEN:
            raise error("send() msg too long: %d" % len(msg))
        req = b"SEND" + struct.pack("I", len(msg)) + msg
        self._to_lwip(req)
        rep = self._from_lwip()
        if rep != b"SENDOK":
            raise error("send() failed: %s" % rep)
        return len(msg)

    def recv(self, bufsize):
        if self._recv_buf:
            ret = self._recv_buf[:bufsize]
            self._recv_buf = self._recv_buf[bufsize:]
            return ret
        # Local recv_buf is empty, request LWIP and fulfill it.
        self._fill_recv_buf()
        # recv buf is ready
        return self.recv(bufsize)

    def _fill_recv_buf(self):
        req = b"RECV"
        self._to_lwip(req)
        rep = self._from_lwip()
        if rep is None or len(rep) < RESP_SIZE or rep[:RESP_SIZE] != b"RECVOK":
            raise error("recv() failed: %s" % rep)
        size, = struct.unpack("H", rep[RESP_SIZE:RESP_SIZE+2])
        self._recv_buf = rep[RESP_SIZE+2:]
        while len(self._recv_buf) < size:
            rep = self._from_lwip()
            if rep is None:
                raise error("recv() failed, partial read() %s" % rep)
            self._recv_buf += rep
        if len(self._recv_buf) != size:
            raise error("recv() read too much: ", len(self._recv_buf), size)

    def close(self):
        req = b"CLOS"
        self._to_lwip(req)
        self._lwip_sock.close()
        if self._lwip_accept:
            fname = self._lwip_accept.getsockname()
            self._lwip_accept.close()
            os.unlink(fname)


def socket(family, type_, proto=0, name=''):
    sock = SCIONSocket(family, type_, proto, name)
    sock.create_socket()
    return sock
