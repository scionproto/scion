"""
raw_socket.py

Copyright 2014 ETH Zurich

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import socket

from lib.packet.host_addr import IPv4HostAddr
from lib.packet.ipv4 import IPv4Header, IPv4Packet


class RawSocket(object):
    """
    Raw IP socket for network communications.
    """
    def __init__(self, proto=socket.IPPROTO_RAW):
        self._sock = socket.socket(socket.AF_INET,
                                   socket.SOCK_RAW,
                                   proto)

    def bind(self, addr):
        """
        Binds the socket to an address.

        @param addr: An IPv4 address in the form 'X.X.X.X'
        """
        assert isinstance(addr, str)
        self._sock.bind((addr, 0))

    def close(self):
        """
        Closes the socket.
        """
        self._sock.close()

    def send(self, src, dst, data, proto=40):
        """
        Sends a raw IP packet from src to dst.

        @param src: IPv4 address in the form 'X.X.X.X'.
        @param dst: IPv4 address in the form 'X.X.X.X'.
        @param data: The payload of the IP packet (in bytes).
        @param proto: Layer 4 protocol to be used.
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

        @param bytes: The maximum amount of bytes to return.
        @param timeout: Sets the socket timeout. 'None' disables it.
        @return: data and (src, port) pair
        """
        self._sock.settimeout(timeout)
        return self._sock.recvfrom(nbytes)
