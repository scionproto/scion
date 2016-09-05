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
import socket
import struct
import threading
import uuid

# SCION
from lib.defines import DEFAULT_DISPATCHER_ID, DISPATCHER_DIR
from lib.errors import SCIONIOError
from lib.packet.path import SCIONPath
from lib.packet.scion_addr import SCIONAddr
from lib.packet.svc import SVCType
from lib.util import recv_all

LWIP_SOCK_DIR = os.path.join(DISPATCHER_DIR, "lwip")
AF_SCION = 11
SOCK_STREAM = socket.SOCK_STREAM
MAX_MSG_LEN = 2 << 31  # u32_t is used as size_t at middleware
CMD_SIZE = 4
RESP_SIZE = CMD_SIZE + 1  # either return (error) code is appended.
PLD_SIZE = 2  # Each command/reply is prepended with 2B payload len field.
TCPMW_BUFLEN = 8192  # TCPMW's buffer. Each command has to fit it.
SOCK_PATH_LEN = 36  # Length of a string generated by uuid4()
MAX_CHUNK = TCPMW_BUFLEN - PLD_SIZE - CMD_SIZE  # Max payload length.


class error(socket.error):
    pass


class timeout(socket.timeout):
    pass


class LWIPError(object):
    # LWIP error codes.
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
    ERR_SYS = -128  # System call error.

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
        ERR_SYS: "System call error.",
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


class APICmd(object):
    # Middleware API commands.
    ACCEPT = b"ACCE"
    BIND = b"BIND"
    CLOSE = b"CLOS"
    CONNECT = b"CONN"
    GET_RECV_TOUT = b"GRTO"
    LISTEN = b"LIST"
    NEW_SOCK = b"NEWS"
    RECV = b"RECV"
    SEND = b"SEND"
    SET_RECV_TOUT = b"SRTO"
    SET_OPT = b"SOPT"
    RESET_OPT = b"ROPT"
    GET_OPT = b"GOPT"


class SockOpt(object):
    # LWIP's socket options.
    SOF_ACCEPTCONN = 0x02  # socket has had listen()
    SOF_REUSEADDR = 0x04  # allow local address reuse
    SOF_KEEPALIVE = 0x08  # keep connections alive
    SOF_BROADCAST = 0x20  # permit to send and to receive broadcast messages
    SOF_LINGER = 0x80  # linger on close if data present, PSz: unimplemented


def get_lwip_reply(sock):
    raw_len = recv_all(sock, PLD_SIZE, 0)
    if not raw_len:
        return None
    pld_len, = struct.unpack("H", raw_len)
    return recv_all(sock, RESP_SIZE + pld_len, 0)


class SCIONTCPSocket(object):
    BUFLEN = 1024

    def __init__(self, sock=None):
        self._lwip_sock = sock
        self._lwip_accept = None
        self._recv_buf = b''
        self._lock = threading.Lock()
        if sock is None:
            self._create_socket()

    def setsockopt(self, opt):
        req = APICmd.SET_OPT + struct.pack("H", opt)
        self._exec_cmd(req, True)

    def resetsockopt(self, opt):
        req = APICmd.RESET_OPT + struct.pack("H", opt)
        self._exec_cmd(req, True)

    def getsockopt(self, opt):
        req = APICmd.GET_OPT + struct.pack("H", opt)
        rep = self._exec_cmd(req, True)
        return struct.unpack("H", rep[RESP_SIZE:])[0]

    def _handle_reply(self, cmd, reply):
        if reply is None or len(reply) < RESP_SIZE or cmd != reply[:CMD_SIZE]:
            logging.error("%s: incorrect reply: %s" % (cmd, reply))
            raise error("%s: incorrect reply: %s" % (cmd, reply))
        err_code, = struct.unpack("b", reply[RESP_SIZE-1:RESP_SIZE])
        if err_code:
            err_str = LWIPError.err2str(err_code)
            msg = "%s: (%d) %s" % (cmd, err_code, err_str)
            if err_code in [LWIPError.ERR_CLSD, LWIPError.ERR_TIMEOUT]:
                logging.debug(msg)
            elif LWIPError.is_fatal(err_code):
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
        haddrtype = addr.host.TYPE
        req = (APICmd.BIND + struct.pack("H", port) + svc.pack() +
               struct.pack("B", haddrtype) + addr.pack())
        self._exec_cmd(req, True)

    def connect(self, addr, port, path, first_ip, first_port):
        haddrtype = addr.host.TYPE
        path = path.pack()
        # TODO(PSz): change order of packing, don't assume ipv4
        req = (APICmd.CONNECT + struct.pack("HH", port, len(path)) + path +
               struct.pack("B", haddrtype) + addr.pack() + first_ip.pack() +
               struct.pack("H", first_port))
        self._exec_cmd(req, True)

    def _create_socket(self):
        assert self._lwip_sock is None
        # Create a socket to LWIP
        self._lwip_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        env = os.getenv("DISPATCHER_ID") or DEFAULT_DISPATCHER_ID
        path = os.path.join(LWIP_SOCK_DIR, env + ".sock")
        self._lwip_sock.connect(path)
        # Register it
        req = APICmd.NEW_SOCK
        self._exec_cmd(req)

    def _to_lwip(self, req):
        logging.debug("Sending to LWIP(%dB): %.*s..." % (len(req), 20, req))
        assert PLD_SIZE + len(req) <= TCPMW_BUFLEN, "Cmd too long"
        pld_len = len(req) - CMD_SIZE
        if self._lwip_sock:
            self._lwip_sock.sendall(struct.pack("H", pld_len) + req)
        else:
            logging.debug("Sending via non-existing socket (_lwip_sock)")
            raise SCIONIOError

    def _from_lwip(self):
        if self._lwip_sock:
            rep = get_lwip_reply(self._lwip_sock)
        else:
            logging.debug("Reading from non-existing socket (_lwip_sock)")
            raise SCIONIOError
        if rep is None:
            replen = 0
        else:
            replen = len(rep)
        logging.debug("Reading from LWIP(%dB): %.*s..." % (replen, 20, rep))
        return rep

    def _exec_cmd(self, req, cmd_size=False):
        with self._lock:
            self._to_lwip(req)
            rep = self._from_lwip()
            if cmd_size:
                self._handle_reply(req[:CMD_SIZE], rep)
            else:
                self._handle_reply(req, rep)
        return rep

    def listen(self):  # w/o backlog for now, let's use LWIP's default
        req = APICmd.LISTEN
        self._exec_cmd(req)

    def accept(self):
        self._init_accept_sock()
        sockname = self._lwip_accept.getsockname()[-SOCK_PATH_LEN:]
        sockname = sockname.encode('ascii')
        # Confirmation from old (UNIX) socket.
        req = APICmd.ACCEPT + sockname
        self._exec_cmd(req, True)

        new_sock, _ = self._lwip_accept.accept()
        # Metadata (path and addr) from new (UNIX) socket.
        rep = get_lwip_reply(new_sock)
        self._handle_reply(req[:CMD_SIZE], rep)
        logging.debug("accept() raw reply: %s", rep)
        rep = rep[RESP_SIZE:]
        path_len, = struct.unpack("H", rep[:2])
        rep = rep[2:]
        path = SCIONPath(rep[:path_len])
        path.reverse()
        rep = rep[path_len:]
        addr = SCIONAddr((rep[0], rep[1:]))
        # Everything is ok, create new SCION TCP socket.
        sock = SCIONTCPSocket(new_sock)
        return sock, addr, path

    def _init_accept_sock(self):
        if self._lwip_accept:
            return
        fname = os.path.join(LWIP_SOCK_DIR, str(uuid.uuid4()))
        while os.path.exists(fname):  # TODO(PSz): add max_tries
            fname = "%s%s" % (LWIP_SOCK_DIR, uuid.uuid4())
        logging.debug("_init_accept_sock(): %s", fname)
        self._lwip_accept = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._lwip_accept.bind(fname)
        self._lwip_accept.listen(5)  # FIXME(PSz): consistent with LWIP backlog

    def send(self, msg):
        # Due to underlying LWIP this method is quite binary: it returns length
        # of msg if it is sent, or throws exception otherwise.  Thus it might be
        # safer to use it with smaller msgs.
        if len(msg) > MAX_MSG_LEN:
            logging.error("send() msg too long: %d" % len(msg))
            raise error("send() msg too long: %d" % len(msg))

        start = 0
        while start < len(msg):
            req = APICmd.SEND + msg[start:start+MAX_CHUNK]
            self._exec_cmd(req, True)
            start += MAX_CHUNK
        return len(msg)

    def recv(self, bufsize):
        if len(self._recv_buf) < bufsize:
            self._fill_recv_buf()
        ret = self._recv_buf[:bufsize]
        self._recv_buf = self._recv_buf[bufsize:]
        return ret

    def _fill_recv_buf(self):
        req = APICmd.RECV
        rep = self._exec_cmd(req)
        self._recv_buf += rep[RESP_SIZE:]

    def set_recv_tout(self, timeout):  # Timeout is given as a float
        if 0.0 < timeout < 0.001:
            raise error("settimeout(): incorrect value")
        # Convert to miliseconds
        timeout = int(timeout * 1000)
        req = APICmd.SET_RECV_TOUT + struct.pack("I", timeout)
        self._exec_cmd(req, True)

    def get_recv_tout(self):
        req = APICmd.GET_RECV_TOUT
        rep = self._exec_cmd(req)
        timeout, = struct.unpack("I", rep[RESP_SIZE:])
        # Convert to seconds
        return timeout / 1000.0

    def close(self):
        with self._lock:
            if self._lwip_sock:
                req = APICmd.CLOSE
                self._to_lwip(req)
                self._lwip_sock.close()
                self._lwip_sock = None
            else:
                logging.debug("Closing non-existing socket (_lwip_sock)")
            if self._lwip_accept:
                fname = self._lwip_accept.getsockname()
                self._lwip_accept.close()
                os.unlink(fname)
                self._lwip_accept = None
