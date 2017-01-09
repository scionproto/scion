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
:mod:`id` --- Zookeeper IDs
===========================
"""

# External
import capnp  # noqa

# SCION
import proto.zkid_capnp as P
from lib.packet.host_addr import haddr_parse
from lib.packet.packet_base import Cerealizable
from lib.packet.scion_addr import ISD_AS


class ZkID(Cerealizable):  # pragma: no cover
    NAME = "RevocationInfo"
    P_CLS = P.ZkId

    @classmethod
    def from_values(cls, isd_as, id_, addr_infos):
        p = cls.P_CLS.new_message(isdas=int(isd_as), id=id_)
        p.init("addrs", len(addr_infos))
        for i, (addr, port) in enumerate(addr_infos):
            p.addrs[i].type = addr.TYPE
            p.addrs[i].addr = addr.pack()
            p.addrs[i].port = port
        return cls(p)

    def isd_as(self):  # pragma: no cover
        return ISD_AS(self.p.isdas)

    def addr(self, idx):  # pragma: no cover
        return (haddr_parse(self.p.addrs[idx].type, self.p.addrs[idx].addr),
                self.p.addrs[idx].port)

    def iter_addrs(self, start=0):  # pragma: no cover
        for i in range(start, len(self.p.addrs)):
            yield self.addr(i)

    def __eq__(self, other):
        # XXX(kormat): comparing capnp objects always fails if they contain
        # lists, even if the list contents are the same :(
        return str(self) == str(other)

    def __str__(self):
        s = []
        for a, p in self.iter_addrs():
            s.append("[%s]:%d" % (a, p))
        return "ISD-AS: %s Id: %s (%s)" % (
            self.isd_as(), self.p.id, ", ".join(s))
