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
:mod:`path_req` --- SCIOND path requests and replies
====================================================
"""
# Stdlib
import logging

# External
import capnp  # noqa

# SCION
import proto.sciond_capnp as P
from lib.packet.host_addr import HostAddrIPv4, HostAddrIPv6
from lib.packet.packet_base import Cerealizable
from lib.packet.scion_addr import ISD_AS
from lib.sciond_api.base import SCIONDMsgBase
from lib.sciond_api.path_meta import FwdPathMeta
from lib.types import AddrType, SCIONDMsgType as SMT


class SCIONDPathRequest(SCIONDMsgBase):  # pragma: no cover
    """SCIOND path request message."""
    NAME = "SCIONDPathReq"
    MSG_TYPE = SMT.PATH_REQUEST
    P_CLS = P.PathReq

    @classmethod
    def from_values(cls, id_, dst_ia, src_ia=None, max_paths=5,
                    flush=False, sibra=False):
        p = cls.P_CLS.new_message(
            id=id_, dst=int(dst_ia), maxPaths=max_paths)
        if src_ia:
            p.src = int(src_ia)
        p.flags.flush = flush
        p.flags.sibra = sibra
        return cls(p)

    def dst_ia(self):
        return ISD_AS(self.p.dst)

    def src_ia(self):
        if self.p.src:
            return ISD_AS(self.p.src)
        return None

    def short_desc(self):
        desc = ["id=%d, dst=%s" % (self.p.id, self.dst_ia())]
        if self.p.src:
            desc.append("src=%s" % self.src_ia())
        desc.append("max_paths=%d" % self.p.maxPaths)
        if self.p.flags.flush:
            desc.append("FLUSH")
        if self.p.flags.sibra:
            desc.append("SIBRA")
        return " ".join(desc)


class SCIONDPathReplyError:  # pragma: no cover
    OK = 0
    NO_PATHS = 1
    PS_TIMEOUT = 2
    INTERNAL = 3

    @classmethod
    def describe(cls, code):
        if code == cls.OK:
            return "OK"
        if code == cls.NO_PATHS:
            return "No paths available."
        if code == cls.PS_TIMEOUT:
            return "SCIOND timed out while requesting paths."
        if code == cls.INTERNAL:
            return "SCIOND experienced an internal error."
        return "Unknown error"


class SCIONDPathReply(SCIONDMsgBase):  # pragma: no cover
    """SCIOND path reply message."""
    NAME = "SCIONDPathReply"
    MSG_TYPE = SMT.PATH_REPLY
    P_CLS = P.PathReply

    @classmethod
    def from_values(cls, id_, path_entries, error=SCIONDPathReplyError.OK):
        """
        Returns a SCIONDPathReply object with the specified entries.

        :param entries: List of SCIONDPathReplyEntry objects.
        """
        p = cls.P_CLS.new_message(id=id_, errorCode=error)
        entries = p.init("entries", len(path_entries))
        for i, entry in enumerate(path_entries):
            entries[i] = entry.p
        return cls(p)

    def iter_entries(self):
        for entry in self.p.entries:
            yield SCIONDPathReplyEntry(entry)

    def path_entry(self, idx):
        return SCIONDPathReplyEntry(self.p.entries[idx])

    def short_desc(self):
        desc = ["id=%d error_code=%d" % (self.p.id, self.p.errorCode)]
        for entry in self.iter_entries():
            for line in entry.short_desc().splitlines():
                desc.append("  %s" % line)
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

        :param path: The FwdPathMeta object.
        :param addr: The list of first hop HostAddr object.
        :param port: The first hop port.
        """
        assert isinstance(path, FwdPathMeta)
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
            self._path = FwdPathMeta(self.p.path)
        return self._path

    def ipv4(self):
        if self.p.addrs.ipv4:
            return HostAddrIPv4(self.p.addrs.ipv4)
        return None

    def ipv6(self):
        if self.p.addrs.ipv6:
            return HostAddrIPv6(self.p.addrs.ipv6)
        return None

    def short_desc(self):
        desc = ["%s:" % self.NAME]
        desc.append("  %s" % self.path())
        fh_str = ["  First Hop:"]
        if self.ipv4():
            fh_str.append("IPv4: %s" % self.ipv4())
        if self.ipv6():
            fh_str.append("IPv6: %s" % self.ipv6())
        fh_str.append("Port: %d" % self.p.port)
        desc.append(" ".join(fh_str))
        return "\n".join(desc)
