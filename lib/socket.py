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
import ipaddress
import logging
import selectors
import struct
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

# SCION
from lib.defines import SCION_BUFLEN
from lib.dispatcher import reg_dispatcher
from lib.errors import SCIONIOError
from lib.packet.host_addr import haddr_parse_interface
from lib.packet.scmp.errors import SCMPUnreachHost, SCMPUnreachNet
from lib.util import recv_all
from lib.thread import kill_self
from lib.types import AddrType


class Socket(object):
    """
    Base class for socket wrappers
    """
    def __init__(self, sock_type, bind=None, addr_type=AddrType.IPV6,
                 reuse=False):
        """
        Initialise a socket of the specified type, and optionally bind it to an
        address/port.

        :param tuple bind:
            Optional tuple of (`str`, `int`, `str`) describing respectively the
            address and port to bind to, and an optional description.
        :param addr_type:
            Socket domain. Must be one of :const:`~lib.types.AddrType.IPV4`,
            :const:`~lib.types.AddrType.IPV6` (default).
        """
        assert addr_type in (AddrType.IPV4, AddrType.IPV6, AddrType.UNIX)
        self._addr_type = addr_type
        af_domain = AF_INET6
        if self._addr_type == AddrType.IPV4:
            af_domain = AF_INET
        elif self._addr_type == AddrType.UNIX:
            af_domain = AF_UNIX
        self.sock = socket(af_domain, sock_type)
        if reuse:
            self.sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.port = None
        if bind:
            self.bind(*bind)
        else:
            # TODO: Replace with dispatcher-assigned port
            self.port = 30045

    def bind(self, addr, port, desc=None):
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

    def close(self):  # pragma: no cover
        """
        Close the socket.
        """
        self.sock.close()

    def settimeout(self, timeout):  # pragma: no cover
        prev = self.sock.gettimeout()
        self.sock.settimeout(timeout)
        return prev


class UDPSocket(Socket):
    """
    Thin wrapper around BSD/POSIX UDP sockets.
    """
    def __init__(self, bind=None, addr_type=AddrType.IPV6, reuse=False):
        super().__init__(SOCK_DGRAM, bind, addr_type, reuse)

    def send(self, data, dst, sock=None):
        """
        Send data to a specified destination.

        :param bytes data: Data to send.
        :param tuple dst:
            Tuple of (`str`, `int`) describing the destination address and port,
            respectively.
        """
        if sock is None:
            sock = self.sock
        try:
            ret = sock.sendto(data, dst)
        except OSError as e:
            errno = e.args[0]
            logging.error("Error sending %dB to %s: %s", len(data), dst, e)
            if errno == ENETUNREACH:
                raise SCMPUnreachNet(dst)
            elif errno == EHOSTUNREACH:
                raise SCMPUnreachHost(dst)
            return
        if ret != len(data):
            logging.error("Wanted to send %dB, only sent %dB", len(data), ret)

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


class DispatcherSocket(Socket):
    """
    Wrapper around Unix socket with dispatcher-specific functionality baked in
    """
    COOKIE = bytes.fromhex("de00ad01be02ef03")
    COOKIE_LEN = len(COOKIE)

    def __init__(self, addr, port, init=True, svc=None):
        super().__init__(SOCK_STREAM, None, AddrType.UNIX)
        self.registered = reg_dispatcher(self, addr, port, init, svc)

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
            addr_len = struct.pack("B", len(dst_addr))
            packed_dst = dst_addr.pack() + struct.pack("H", dst_port)
        else:
            addr_len = struct.pack("B", 0)
            packed_dst = b""
        data_len = struct.pack("I", len(data))
        data = b"".join([self.COOKIE, addr_len, data_len, packed_dst, data])
        try:
            self.sock.sendall(data)
        except OSError as e:
            logging.error("error sending to dispatcher: %s", e)

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
        cookie, addr_len, packet_len = struct.unpack("=8sBI", buf)
        if cookie != self.COOKIE:
            logging.critical("Dispatcher socket out of sync")
            raise SCIONIOError
        port_len = 0
        if addr_len > 0:
            port_len = 2
        # We know there is data coming, block here to avoid sync problems.
        buf = recv_all(self.sock, addr_len + port_len + packet_len, 0)
        if addr_len > 0:
            addr = buf[:addr_len]
            port = buf[addr_len:addr_len + port_len]
        else:
            addr = ""
            port = 0
        packet = buf[addr_len + port_len:]
        sender = (not addr or str(ipaddress.ip_address(addr)), port)
        return packet, sender


class SocketMgr(object):
    """
    :class:`UDPSocket` manager.
    """
    def __init__(self):  # pragma: no cover
        self._sel = selectors.DefaultSelector()

    def add(self, sock):  # pragma: no cover
        """
        Add new socket.

        :param UDPSocket sock: UDPSocket to add.
        """
        self._sel.register(sock.sock, selectors.EVENT_READ, sock)

    def remove(self, sock):  # pragma: no cover
        """
        Remove socket.

        :param UDPSocket sock: UDPSocket to remove.
        """
        self._sel.unregister(sock.sock)

    def select_(self, timeout=None):
        """
        Return the set of UDPSockets that have data pending.

        :param float timeout:
            Number of seconds to wait for at least one UDPSocket to become
            ready. ``None`` means wait forever.
        """
        ret = []
        for key, _ in self._sel.select(timeout=timeout):
            ret.append(key.data)
        return ret

    def close(self):
        """
        Close all sockets.
        """
        mapping = self._sel.get_map()
        if mapping:
            for entry in list(mapping.values()):
                sock = entry.data
                self.remove(sock)
                sock.close()
        self._sel.close()
