# Copyright 2015 ETH Zurich
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
:mod:`socket` --- Low-level socket library
==========================================
"""
# Stdlib
import logging
import os
import selectors
import struct
import time
from abc import abstractmethod
from errno import EHOSTUNREACH, ENETUNREACH
from socket import (
    AF_INET,
    AF_INET6,
    AF_UNIX,
    MSG_DONTWAIT,
    SOCK_DGRAM,
    SOCK_STREAM,
    SOL_SOCKET,
    SO_REUSEADDR,
    socket,
)
import threading

# External
from external import ipaddress

# SCION
from lib.defines import SCION_BUFLEN, TCP_TIMEOUT
from lib.dispatcher import reg_dispatcher
from lib.errors import (
    SCIONBaseError,
    SCIONIOError,
    SCIONTCPError,
    SCIONTCPTimeout,
)
from lib.log import log_exception
from lib.msg_meta import TCPMetadata
from lib.packet.host_addr import haddr_get_type, haddr_parse_interface
from lib.packet.ctrl_pld import SignedCtrlPayload
from lib.packet.scmp.errors import SCMPUnreachHost, SCMPUnreachNet
from lib.util import recv_all
from lib.thread import kill_self
from lib.types import AddrType
from lib.util import hex_str


class Socket(object):
    """
    Base class for socket wrappers
    """
    @abstractmethod
    def bind(self, addr, *args, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def send(self, data, dst=None):
        raise NotImplementedError

    @abstractmethod
    def recv(self, block=True):
        raise NotImplementedError

    def close(self):  # pragma: no cover
        """
        Close the socket.
        """
        self.sock.close()

    def settimeout(self, timeout):  # pragma: no cover
        prev = self.sock.gettimeout()
        self.sock.settimeout(timeout)
        return prev

    def is_active(self):
        return True


class UDPSocket(Socket):
    """
    Thin wrapper around BSD/POSIX UDP sockets.
    """
    def __init__(self, bind=None, addr_type=AddrType.IPV6, reuse=False):
        """
        Initialize a UDP socket, then call superclass init for socket options
        and binding.

        :param tuple bind:
            Optional tuple of (`str`, `int`, `str`) describing respectively the
            address and port to bind to, and an optional description.
        :param addr_type:
            Socket domain. Must be one of :const:`~lib.types.AddrType.IPV4`,
            :const:`~lib.types.AddrType.IPV6` (default).
        :param reuse:
            Boolean value indicating whether SO_REUSEADDR option should be set.
        """
        assert addr_type in (AddrType.IPV4, AddrType.IPV6)
        self._addr_type = addr_type
        af_domain = AF_INET6
        if self._addr_type == AddrType.IPV4:
            af_domain = AF_INET
        self.sock = socket(af_domain, SOCK_DGRAM)
        if reuse:
            self.sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.port = None
        if bind:
            self.bind(*bind)
        self.active = True

    def bind(self, addr, port=0, desc=None):
        """
        Bind socket to the specified address & port. If `addr` is ``None``, the
        socket will bind to all interfaces.

        :param str addr: Address to bind to (can be ``None``, see above).
        :param int port: Port to bind to.
        :param str desc: Optional purpose of the port.
        """
        if addr is None:
            addr = "::"
            if self._addr_type == AddrType.IPV4:
                addr = ""
        try:
            self.sock.bind((addr, port))
        except OSError as e:
            logging.critical("Error binding to [%s]:%s: %s", addr, port, e)
            kill_self()
        self.port = self.sock.getsockname()[1]
        if desc:
            logging.debug("%s bound to %s:%d", desc, addr, self.port)

    def send(self, data, dst=None):
        """
        Send data to a specified destination.

        :param bytes data: Data to send.
        :param tuple dst:
            Tuple of (`str`, `int`) describing the destination address and port,
            respectively.
        """
        try:
            ret = self.sock.sendto(data, dst)
        except OSError as e:
            errno = e.args[0]
            logging.error("Error sending %dB to %s: %s", len(data), dst, e)
            if errno == ENETUNREACH:
                raise SCMPUnreachNet(dst)
            elif errno == EHOSTUNREACH:
                raise SCMPUnreachHost(dst)
            return False
        if ret != len(data):
            logging.error("Wanted to send %dB, only sent %dB", len(data), ret)
            return False
        return True

    def recv(self, block=True):
        """
        Read data from socket.

        :returns:
            Tuple of (`bytes`, (`str`, `int`) containing the data, and remote
            host/port respectively.
        """
        flags = 0
        if not block:
            flags = MSG_DONTWAIT
        while True:
            try:
                return self.sock.recvfrom(SCION_BUFLEN, flags)
            except InterruptedError:
                pass


class ReliableSocket(Socket):
    """
    Wrapper around Unix socket with message framing functionality baked in
    """
    COOKIE = bytes.fromhex("de00ad01be02ef03")
    COOKIE_LEN = len(COOKIE)

    def __init__(self, reg=None, bind_ip=(), bind_unix=None, sock=None):
        """
        Initialise a socket of the specified type, and optionally bind it to an
        address/port.

        :param tuple reg:
            Optional tuple of (`SCIONAddr`, `int`, `SVCType`, `bool`)
            describing respectively the address, port, SVC type, and init value
            to register with the dispatcher. In sockets that do not connect to
            the dispatcher, this argument is None.
        :param tuple bind_ip:
            Optional tuple of (`SCIONAddr`, `int`) describing the address and port
            of the bind address. Only needed if the bind address is different from
            the public address.
        :param tuple bind_unix:
            Optional tuple of (`str`, `str`) describing path to bind to, and an
            optional description.
        :param sock:
            Optional socket file object to build instance around.
        """
        self.sock = sock or socket(AF_UNIX, SOCK_STREAM)
        self.addr = None
        if reg:
            addr, port, init, svc = reg
            self.registered = reg_dispatcher(
                    self, addr, port, bind_ip, init, svc)
        if bind_unix:
            self.bind(*bind_unix)
        self.active = True

    @classmethod
    def from_socket(cls, sock):
        return cls(None, sock=sock)

    def bind(self, addr, desc=None):
        self.addr = addr
        try:
            self.sock.bind(addr)
        except OSError as e:
            logging.critical("Error binding to %s: %s", addr, e)
            kill_self()
        self.sock.listen(5)
        if desc:
            logging.debug("%s bound to %s", desc, addr)

    def accept(self, block=True):
        prev = self.sock.gettimeout()
        if not block:
            self.sock.settimeout(0)
        try:
            s = self.sock.accept()[0]
        except OSError as e:
            logging.error("error accepting socket: %s", e)
            return None
        finally:
            self.sock.settimeout(prev)
        return ReliableSocket.from_socket(s)

    def connect(self, addr):
        self.sock.connect(addr)

    def send(self, data, dst=None):
        """
        Send data through the socket.

        :param bytes data: Data to send.
        """
        if dst:
            dst_addr, dst_port = dst
            if isinstance(dst_addr, str):
                dst_addr = haddr_parse_interface(dst_addr)
            addr_type = struct.pack("B", dst_addr.TYPE)
            packed_dst = dst_addr.pack() + struct.pack("!H", dst_port)
        else:
            addr_type = struct.pack("B", AddrType.NONE)
            packed_dst = b""
        data_len = struct.pack("!I", len(data))
        data = b"".join([self.COOKIE, addr_type, data_len, packed_dst, data])
        try:
            self.sock.sendall(data)
            return True
        except OSError as e:
            logging.error("error in send: %s", e)
            return False

    def recv(self, block=True):
        """
        Read data from socket.

        :returns: bytestring containing received data.
        """
        flags = 0
        if not block:
            flags = MSG_DONTWAIT
        buf = recv_all(self.sock, self.COOKIE_LEN + 5, flags)
        if not buf:
            return None, None
        cookie, addr_type, packet_len = struct.unpack("!8sBI", buf)
        if cookie != self.COOKIE:
            logging.critical("Dispatcher socket out of sync")
            raise SCIONIOError
        port_len = 0
        if addr_type != AddrType.NONE:
            port_len = 2
        addr_len = haddr_get_type(addr_type).LEN
        # We know there is data coming, block here to avoid sync problems.
        buf = recv_all(self.sock, addr_len + port_len + packet_len, 0)
        if addr_len > 0:
            addr = buf[:addr_len]
            port = struct.unpack("!H", buf[addr_len:addr_len + port_len])
            sender = (str(ipaddress.ip_address(addr)), port)
        else:
            addr = ""
            port = 0
            sender = (None, None)
        packet = buf[addr_len + port_len:]
        return packet, sender

    def close(self):
        super().close()
        if not self.addr:
            return
        try:
            os.unlink(self.addr)
        except OSError as e:
            logging.critical("Error unlinking unix socket: %s", e)
            kill_self()


class SocketMgr(object):
    """
    :class:`Socket` manager.
    """
    def __init__(self):  # pragma: no cover
        self._sel = selectors.DefaultSelector()

    def add(self, sock, callback):  # pragma: no cover
        """
        Add new socket.

        :param UDPSocket sock: UDPSocket to add.
        """
        if not sock.is_active():
            return
        if isinstance(sock, TCPSocketWrapper):
            sock.sock.setblocking(False)
        self._sel.register(sock.sock, selectors.EVENT_READ, (sock, callback))

    def remove(self, sock):  # pragma: no cover
        """
        Remove socket.

        :param UDPSocket sock: UDPSocket to remove.
        """
        self._sel.unregister(sock.sock)

    def remove_inactive(self):
        """
        Removes inactive TCP sockets.
        """
        mapping = self._sel.get_map()
        if mapping:
            for entry in list(mapping.values()):
                sock = entry.data[0]
                if not sock.is_active():
                    self.remove(sock)
                    sock.close()

    def select_(self, timeout=None):
        """
        Return the set of UDPSockets that have data pending.

        :param float timeout:
            Number of seconds to wait for at least one UDPSocket to become
            ready. ``None`` means wait forever.
        """
        for key, _ in self._sel.select(timeout=timeout):
            yield key.data

    def close(self):
        """
        Close all sockets.
        """
        mapping = self._sel.get_map()
        if mapping:
            for entry in list(mapping.values()):
                sock = entry.data[0]
                self.remove(sock)
                sock.close()
        self._sel.close()


class TCPSocketWrapper(object):
    """
    Base class for accepted and connected TCP sockets used by SCION services.
    """
    RECV_SIZE = 8092

    def __init__(self, sock, addr, path, active=True):
        self._buf = bytearray()
        self._tcp_sock = sock
        self.sock = None  # Used by the selector.
        if self._tcp_sock:
            self.sock = self._tcp_sock._lwip_sock
        self.active = active
        self._addr = addr
        self._path = path
        self._lock = threading.RLock()
        self._last_io = time.time()

    def _get_meta(self):
        return TCPMetadata.from_values(ia=self._addr.isd_as,
                                       host=self._addr.host, path=self._path,
                                       sock=self)

    def _get_msg(self):
        if len(self._buf) < 4:
            return None
        msg_len = struct.unpack("!I", self._buf[:4])[0]
        if msg_len + 4 > len(self._buf):
            return None
        msg = self._buf[4:4 + msg_len]
        self._buf = self._buf[4 + msg_len:]
        try:
            return SignedCtrlPayload.from_raw(msg).pld()
        except SCIONBaseError:
            log_exception("Error parsing message: %s" % hex_str(msg),
                          level=logging.ERROR)
            return None

    def get_msg_meta(self):
        with self._lock:
            msg = self._get_msg()
            if msg:
                return msg, self._get_meta()
            if not self.active:
                logging.debug("TCP: get_msg_meta(): inactive socket")
                return None, self._get_meta()
            try:
                read = self._tcp_sock.recv(self.RECV_SIZE)
                if not read:
                    self.active = False
                    return None, None
                self._buf += read
                self._last_io = time.time()
            except SCIONTCPTimeout:
                return None, self._get_meta()
            except SCIONTCPError:
                logging.debug("TCP: inactivating socket after socket error")
                self.active = False
            return self._get_msg(), self._get_meta()

    def send_msg(self, raw):
        with self._lock:
            if not self.active:
                logging.debug("TCP: send_msg(): inactive socket")
                return False
            try:
                self._tcp_sock.send(raw)
                self._last_io = time.time()
                return True
            except SCIONTCPError:
                logging.debug("TCP: inactivating after socket error")
                self.active = False
        return False

    def close(self):
        with self._lock:
            if not self.active:
                logging.debug("TCP: close(): inactive socket")
                return
            try:
                self._tcp_sock.close()
            except SCIONTCPError as e:
                logging.warning("Error on close(): %s", e)
            self.active = False
            logging.debug("Leaving close()")

    def is_active(self):
        return self.active and (time.time() - self._last_io <= TCP_TIMEOUT)
