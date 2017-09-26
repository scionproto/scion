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
# External
import capnp  # noqa

# SCION
import proto.sciond_capnp as P
from lib.packet.packet_base import Cerealizable
from lib.packet.scion_addr import ISD_AS
from lib.sciond_api.host_info import HostInfo
from lib.sciond_api.path_meta import FwdPathMeta


class SCIONDPathRequest(Cerealizable):  # pragma: no cover
    """SCIOND path request message."""
    NAME = "SCIONDPathReq"
    P_CLS = P.PathReq

    @classmethod
    def from_values(cls, dst_ia, src_ia=None, max_paths=5,
                    flush=False, sibra=False):
        p = cls.P_CLS.new_message(dst=int(dst_ia), maxPaths=max_paths)
        if src_ia is not None:
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
        desc = ["dst=%s" % self.dst_ia()]
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


class SCIONDPathReply(Cerealizable):  # pragma: no cover
    """SCIOND path reply message."""
    NAME = "SCIONDPathReply"
    P_CLS = P.PathReply

    @classmethod
    def from_values(cls, path_entries, error=SCIONDPathReplyError.OK):
        """
        Returns a SCIONDPathReply object with the specified entries.

        :param entries: List of SCIONDPathReplyEntry objects.
        """
        p = cls.P_CLS.new_message(errorCode=error)
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
        desc = ["error_code=%d" % self.p.errorCode]
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
    def from_values(cls, path, first_hop):
        """
        Returns a SCIONDPathReplyEntry object with the specified entries.

        :param path: The FwdPathMeta object.
        :param first_hop: A HostInfo object for the first hop of the path.
        """
        assert isinstance(path, FwdPathMeta), type(path)
        p = cls.P_CLS.new_message(path=path.p, hostInfo=first_hop.p)
        return cls(p)

    def path(self):
        if not self._path:
            self._path = FwdPathMeta(self.p.path)
        return self._path

    def first_hop(self):
        return HostInfo(self.p.hostInfo)

    def short_desc(self):
        desc = ["%s:" % self.NAME]
        desc.append("  %s" % self.path())
        desc.append("  First Hop: %s" % self.first_hop().short_desc())
        return "\n".join(desc)

    def __str__(self):
        return self.short_desc()
