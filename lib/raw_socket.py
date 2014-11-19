#raw_socket.py

#Copyright 2014 ETH Zurich

#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at

#http://www.apache.org/licenses/LICENSE-2.0

#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.
"""
:mod:`raw_socket` --- raw IP socket for network communication
=============================================================
"""

import socket

from lib.packet.host_addr import IPv4HostAddr
from lib.packet.ipv4 import IPv4Header, IPv4Packet


class RawSocket(object):
    """
    Raw IP socket for network communications.
    """

    def __init__(self, proto=socket.IPPROTO_RAW):
        """
        Constructor.

        Create a new ``RawSocket`` instance using the protocol number *proto*.
        The protocol number must be selected from the `list of IP protocol
        numbers
        <http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml>`.
        """
        self._sock = socket.socket(socket.AF_INET,
                                   socket.SOCK_RAW,
                                   proto)

    def bind(self, addr):
        """
        Bind the socket to an address.

        Bind the ``RawSocket`` object to an IPv4 address. The address must be a
        string of the form ``'X.X.X.X'``.

        :param addr: the IPv4 address to which to bind.
        :type addr: str
        """
        assert isinstance(addr, str)
        self._sock.bind((addr, 0))

    def close(self):
        """
        Close the socket.
        """
        self._sock.close()

    def send(self, src, dst, data, proto=40):
        """
        Send a raw IP packet.

        Send a raw IP packet from *src* to *dst*. The source and destination
        addresses must be in dotted-quad format (such as '127.0.0.1'). The
        protocol named in *proto* must be selected from the `list of protocol
        numbers
        <http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml>`.

        :param src: the source IP address.
        :type src: str
        :param dst: the destination IPv4 address.
        :type dst: str
        :param data: the IP packet payload.
        :type data: bytes
        :param proto: the Layer 4 protocol to use.
        :type proto: int
        """
        assert isinstance(data, bytes)

        # Create encapsulating IP Packet.
        pkt = IPv4Packet()
        pkt.hdr = IPv4Header()
        pkt.hdr.hdr_len = 5
        pkt.hdr.v = 4
        pkt.hdr.tos = 0
        pkt.hdr.total_len = len(data) + pkt.hdr.hdr_len
        pkt.hdr.frag = 0
        pkt.hdr.ttl = 64
        pkt.hdr.protocol = proto
        pkt.hdr.check_sum = 0
        pkt.hdr.srcip = IPv4HostAddr(src)
        pkt.hdr.dstip = IPv4HostAddr(dst)
        pkt.payload = data

        self._sock.sendto(pkt.pack(), (dst, 0))

    def recv(self, nbytes=1024, timeout=None):
        """
        Tries to receive data up to a pretermined amount.

        :param bytes: the maximum number of bytes to return.
        :type bytes: int
        :param timeout: the socket timeout, or ``None`` to disable the timeout.
        :type timeout: float
        :returns: the received data and the sending address in the form ``(bytes, address)``.
        :rtype: pair
        """
        self._sock.settimeout(timeout)
        return self._sock.recvfrom(nbytes)
