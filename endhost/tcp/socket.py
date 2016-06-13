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
import logging
import os
import socket as stdsock  # To avoid name collision
import struct
import uuid

# SCION
from lib.packet.path import SCIONPath
from lib.packet.scion import SVCType
from lib.packet.scion_addr import SCIONAddr

LWIP_SOCK_DIR = "/run/shm/lwip/"
RPCD_SOCKET = "/run/shm/lwip/lwip"
AF_SCION = 11
SOCK_STREAM = stdsock.SOCK_STREAM
MAX_MSG_LEN = 2 << 31  # u32_t is used as size_t at middleware
CMD_SIZE = 4
RESP_SIZE = CMD_SIZE + 1  # either return (error) code is appended.


class error(stdsock.error):
    pass


class timeout(stdsock.timeout):
    pass


class LWIPError(object):
    ERR_OK = 0  # No error, everything OK.
    ERR_MEM = -1  # Out of memory error.
    ERR_BUF = -2  # Buffer error.
    ERR_TIMEOUT = -3  # Timeout.
    ERR_RTE = -4  # Routing problem.
    ERR_INPROGRESS = -5  # Operation in progress
    ERR_VAL = -6  # Illegal value.
    ERR_WOULDBLOCK = -7  # Operation would block.
    ERR_USE = -8  # Address in use.
    ERR_ISCONN = -9  # Already connected.
    ERR_ABRT = -10  # Connection aborted.
    ERR_RST = -11  # Connection reset.
    ERR_CLSD = -12  # Connection closed.
    ERR_CONN = -13  # Not connected.
    ERR_ARG = -14  # Illegal argument.
    ERR_IF = -15  # Low-level netif error.
    # PSz: codes below are added by me.
    ERR_NEW = -126  # netconn_new() error.
    ERR_MW = -127  # API/TCP middleware error.
    ERR_SYS = -128  # System's call error.

    ERR2STR = {
        ERR_OK: "Ok.",
        ERR_MEM: "Out of memory error.",
        ERR_BUF: "Buffer error.",
        ERR_TIMEOUT: "Timeout.",
        ERR_RTE: "Routing problem.",
        ERR_INPROGRESS: "Operation in progress.",
        ERR_VAL: "Illegal value.",
        ERR_WOULDBLOCK: "Operation would block.",
        ERR_USE: "Address in use.",
        ERR_ISCONN: "Already connected.",
        ERR_ABRT: "Connection aborted.",
        ERR_RST: "Connection reset.",
        ERR_CLSD: "Connection closed.",
        ERR_CONN: "Not connected.",
        ERR_ARG: "Illegal argument.",
        ERR_IF: "Low-level netif error.",
        ERR_NEW: "netconn_new() error.",
        ERR_MW: "API/TCP middleware error.",
        ERR_SYS: "System's call error.",
        }

    @classmethod
    def is_fatal(cls, err):
        return err < cls.ERR_ISCONN

    @classmethod
    def err2str(cls, err):
        if err in cls.ERR2STR:
            return cls.ERR2STR[err]
        logging.error("Unknown error code.")
        return None


class SCIONSocket(object):
    BUFLEN = 1024

    def __init__(self, family, type_, proto=0):
        assert family == AF_SCION
        assert type_ == SOCK_STREAM
        assert proto == 0
        self._family = family
        self._type = type_
        self._proto = proto
        self._lwip_sock = None
        self._lwip_accept = None
        self._recv_buf = b''

    def _handle_reply(self, cmd, reply):
        reply = reply[:RESP_SIZE]
        if reply is None or len(reply) < RESP_SIZE or cmd != reply[:CMD_SIZE]:
            logging.error("%s: incorrect reply: %s" % (cmd, reply))
            raise error("%s: incorrect reply: %s" % (cmd, reply))
        err_code, = struct.unpack("b", reply[-1:])
        if err_code:
            err_str = LWIPError.err2str(err_code)
            msg = "%s: (%d) %s" % (cmd, err_code, err_str)
            if LWIPError.is_fatal(err_code):
                logging.error(msg)
            else:
                logging.warning(msg)
            if err_code == LWIPError.ERR_TIMEOUT:
                raise timeout(msg)
            else:
                raise error(msg)

    def bind(self, addr_port, svc=None):
        if svc is None:
            svc = SVCType.NONE
        addr, port = addr_port
        haddr_type = addr.host.TYPE
        req = (b"BIND" + struct.pack("H", port) + svc.pack() +
               struct.pack("B", haddr_type) + addr.pack())
        self._to_lwip(req)
        rep = self._from_lwip()
        self._handle_reply(req[:CMD_SIZE], rep)

    def connect(self, addr_port, path_info):
        addr, port = addr_port
        haddr_type = addr.host.TYPE
        path, first_ip, first_port = path_info
        path = path.pack()
        # TODO(PSz): change order of packing, don't assume ipv4
        req = (b"CONN" + struct.pack("HH", port, len(path)) + path +
               struct.pack("B", haddr_type) + addr.pack() + first_ip.pack() +
               struct.pack("H", first_port))
        self._to_lwip(req)
        rep = self._from_lwip()
        self._handle_reply(req[:CMD_SIZE], rep)

    def create_socket(self):
        assert self._lwip_sock is None
        # Create a socket to LWIP
        self._lwip_sock = stdsock.socket(stdsock.AF_UNIX, stdsock.SOCK_STREAM)
        self._lwip_sock.connect(RPCD_SOCKET)
        # Register it
        req = b"NEWS"
        self._to_lwip(req)
        rep = self._from_lwip()
        self._handle_reply(req, rep)
        # self._lwip_sock.close()

    def _to_lwip(self, req):
        logging.debug("Sending to LWIP(%dB): %s..." % (len(req), req[:20]))
        self._lwip_sock.sendall(req)

    def _from_lwip(self, buflen=None):
        if buflen is None:
            buflen = self.BUFLEN
        rep = self._lwip_sock.recv(buflen)  # TODO(PSz): read in a loop.
        logging.debug("Reading from LWIP(%dB): %s..." % (len(rep), rep[:20]))
        return rep

    def listen(self):  # w/o backlog for now, let's use LWIP's default
        req = b"LIST"
        self._to_lwip(req)
        rep = self._from_lwip()
        self._handle_reply(req, rep)

    def accept(self):
        self._init_accept_sock()
        self._lwip_accept.listen(5)  # FIXME(PSz): consistent with LWIP backlog
        req = b"ACCE" + self._lwip_accept.getsockname()[-36:].encode('ascii')
        self._to_lwip(req)

        rep = self._from_lwip()
        self._handle_reply(req[:CMD_SIZE], rep)
        logging.debug("accept() raw reply: %s", rep)
        rep = rep[RESP_SIZE:]
        path_len, = struct.unpack("H", rep[:2])
        rep = rep[2:]
        path = SCIONPath(rep[:path_len])
        rep = rep[path_len:]
        addr = SCIONAddr((rep[0], rep[1:]))

        new_sock, _ = self._lwip_accept.accept()
        rep = new_sock.recv(self.BUFLEN)
        self._handle_reply(req[:CMD_SIZE], rep)
        sock = SCIONSocket(self._family, self._type, self._proto)
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
        logging.debug("_init_accept_sock(): %s", fname)
        self._lwip_accept = stdsock.socket(stdsock.AF_UNIX, stdsock.SOCK_STREAM)
        self._lwip_accept.bind(fname)

    def send(self, msg):
        # Due to underlying LWIP this method is quite binary: it returns length
        # of msg if it is sent, or throws exception otherwise.  Thus it might be
        # safer to use it with smaller msgs.
        if len(msg) > MAX_MSG_LEN:
            logging.error("send() msg too long: %d" % len(msg))
            raise error("send() msg too long: %d" % len(msg))
        req = b"SEND" + struct.pack("I", len(msg)) + msg
        self._to_lwip(req)
        rep = self._from_lwip()
        self._handle_reply(req[:CMD_SIZE], rep)
        return len(msg)

    def recv(self, bufsize):
        if self._recv_buf:
            ret = self._recv_buf[:bufsize]
            self._recv_buf = self._recv_buf[bufsize:]
            return ret
        # Local recv_buf is empty, request LWIP and fulfill it
        self._fill_recv_buf()
        # Recv buf is ready
        return self.recv(bufsize)

    def _fill_recv_buf(self):
        req = b"RECV"
        self._to_lwip(req)
        rep = self._from_lwip()
        self._handle_reply(req, rep)

        size, = struct.unpack("H", rep[RESP_SIZE:RESP_SIZE+2])
        self._recv_buf = rep[RESP_SIZE+2:]
        while len(self._recv_buf) < size:
            rep = self._from_lwip()
            if rep is None:
                logging.error("recv() failed, partial read() %s" % rep)
                raise error("recv() failed, partial read() %s" % rep)
            self._recv_buf += rep

        if len(self._recv_buf) != size:
            logging.error("recv() read too much: %d/%d",
                          len(self._recv_buf), size)
            raise error("recv() read too much: ", len(self._recv_buf), size)

    def set_recv_tout(self, timeout):  # Timeout is given as a float
        if 0.0 < timeout < 0.001:
            raise error("set_recv_tout(): incorrect value")
        # Convert to miliseconds
        timeout = int(timeout * 1000)
        req = b"SRTO" + struct.pack("I", timeout)
        self._to_lwip(req)
        rep = self._from_lwip()
        if rep != b"SRTOOK":
            logging.error("set_recv_tout() failed: %s" % rep)
            raise error("set_recv_tout() failed: %s" % rep)

    def get_recv_tout(self):
        req = b"GRTO"
        self._to_lwip(req)
        rep = self._from_lwip()
        self._handle_reply(req, rep)
        timeout, = struct.unpack("I", rep[RESP_SIZE:])
        # Convert to seconds
        return 0.001 * timeout

    def close(self):
        req = b"CLOS"
        self._to_lwip(req)
        self._lwip_sock.close()
        if self._lwip_accept:
            fname = self._lwip_accept.getsockname()
            self._lwip_accept.close()
            os.unlink(fname)


def socket(family, type_, proto=0):
    sock = SCIONSocket(family, type_, proto)
    sock.create_socket()
    return sock
