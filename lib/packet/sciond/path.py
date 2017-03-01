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
:mod:`base` --- SCIOND path requests and replies
==============================================
"""
# Stdlib
import logging

# External
import capnp  # noqa

# SCION
import proto.sciond_capnp as P
from lib.packet.host_addr import HostAddrIPv4, HostAddrIPv6
from lib.packet.packet_base import Cerealizable
from lib.packet.path import SCIONPath
from lib.packet.sciond.base import SCIONDMsgBase
from lib.packet.scion_addr import ISD_AS
from lib.types import AddrType, SCIONDMsgType as SMT


class SCIONDPathRequest(SCIONDMsgBase):  # pragma: no cover
    """SCIOND path request message."""
    NAME = "SCIONDPathReq"
    MSG_TYPE = SMT.PATH_REQUEST
    P_CLS = P.PathReq

    @classmethod
    def from_values(cls, dst_ia, src_ia=0, flush=False, sibra=False):
        p = cls.P_CLS.new_message(dst=int(dst_ia), src=int(src_ia))
        p.flags.flush = flush
        p.flags.sibra = sibra
        return cls(p)

    def dst_ia(self):
        return ISD_AS(self.p.dst)

    def src_ia(self):
        return ISD_AS(self.p.src)

    def short_desc(self):
        desc = "%s: dst=%s" % (self.NAME, self.dst_ia())
        if self.p.src:
            desc += " src=%s" % self.src_ia()
        if self.p.flush:
            desc += " FLUSH"
        if self.p.sibra:
            desc += " SIBRA"
        return desc


class SCIONDPathReply(SCIONDMsgBase):  # pragma: no cover
    """SCIOND path reply message."""
    NAME = "SCIONDPathReply"
    MSG_TYPE = SMT.PATH_REPLY
    P_CLS = P.PathReply

    @classmethod
    def from_values(cls, path_entries):
        """
        Returns a SCIONDPathReply object with the specified entries.

        :param entries: List of SCIONDPathReplyEntry objects.
        """
        p = cls.P_CLS.new_message()
        entries = p.init("entries", len(path_entries))
        for i, entry in enumerate(path_entries):
            entries[i] = entry.p
        return cls(p)

    def iter_entries(self):
        for entry in self.p.entries:
            yield SCIONDPathReplyEntry(entry)

    def short_desc(self):
        desc = ["%s:" % self.NAME]
        for entry in self.iter_entries():
            for line in entry.short_desc().splitlines():
                desc.append("  %s" % line))
        return "\n".join(desc)


class SCIONDPathReplyEntry(Cerealizable):  # pragma: no cover
    NAME = "SCIONDPathReplyEntry"
    P_CLS = P.PathReplyEntry

    def __init__(self, p):
        super().__init__(p)
        self._path = None

    @classmethod
    def from_values(cls, path, addrs, port):
        """
        Returns a SCIONDPathReplyEntry object with the specified entries.

        :param path: The SCIONPath object.
        :param addr: The list of first hop HostAddr object.
        :param port: The first hop port.
        """
        p = cls.P_CLS.new_message(path=path.p, port=port)
        for addr in addrs:
            if addr.TYPE == AddrType.IPV4:
                p.addrs.ipv4 = addr.pack()
            elif addr.TYPE == AddrType.IPV6:
                p.addrs.ipv6 = addr.pack()
            else:
                logging.warning("Unsupported address type: %s" % addr.TYPE)
        return cls(p)

    def path(self):
        if not self._path:
            self._path = SCIONPath(self.p.path)
        return self._path

    def ipv4(self):
        if self.p.ipv4:
            return HostAddrIPv4(self.p.addrs.ipv4)
        return None

    def ipv6(self):
        if self.p.ipv6:
            return HostAddrIPv6(self.p.addrs.ipv6)
        return None

    def short_desc(self):
        desc = ["%s:" % self.NAME]
        desc.append("  %s", self.path().short_desc())
        fh_str = "  First Hop: "
        if self.ipv4():
            fh_str += " IPv4: %s" % self.ipv4()
        if self.ipv6():
            fh_str += " IPv6: %s" % self.ipv6()
        fh_str += " Port: %d" % self.p.port
        desc.append(fh_str)
        return "\n".join(desc)
