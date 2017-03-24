# Copyright 2017 ETH Zurich
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
:mod:`host_info` --- Host info objects
======================================
"""
# Stdlib
import logging

# External
import capnp  # noqa

# SCION
import proto.sciond_capnp as P
from lib.packet.host_addr import HostAddrIPv4, HostAddrIPv6
from lib.packet.packet_base import Cerealizable
from lib.types import AddrType


class HostInfo(Cerealizable):  # pragma: no cover
    NAME = "HostInfo"
    P_CLS = P.HostInfo

    @classmethod
    def from_values(cls, addrs, port):
        """
        Returns a HostInfo object with the specified entries.

        :param addrs: The list of HostAddr objects.
        :param port: The first hop port.
        """
        p = cls.P_CLS.new_message()
        if port:
            p.port = port
        for addr in addrs:
            if addr.TYPE == AddrType.IPV4:
                p.addrs.ipv4 = addr.pack()
            elif addr.TYPE == AddrType.IPV6:
                p.addrs.ipv6 = addr.pack()
            else:
                logging.warning("Unsupported address type: %s" % addr.TYPE)
        return cls(p)

    def ipv4(self):
        if self.p.addrs.ipv4:
            return HostAddrIPv4(self.p.addrs.ipv4)
        return None

    def ipv6(self):
        if self.p.addrs.ipv6:
            return HostAddrIPv6(self.p.addrs.ipv6)
        return None

    def short_desc(self):
        return ("IPv4: %s IPv6: %s Port: %d" %
                (self.ipv4() or "unset", self.ipv6() or "unset", self.p.port))
