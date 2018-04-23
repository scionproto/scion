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
:mod:`path_meta` --- FwdPathMeta packet
=======================================
"""
# External
import capnp  # noqa

# SCION
import proto.sciond_capnp as P
from lib.errors import SCIONIndexError
from lib.packet.packet_base import Cerealizable
from lib.packet.path import SCIONPath
from lib.packet.scion_addr import ISD_AS


class FwdPathMeta(Cerealizable):  # pragma: no cover
    """Object containing a FwdPath and meta information."""
    NAME = "FwdPathMeta"
    P_CLS = P.FwdPathMeta

    def __init__(self, p):
        super().__init__(p)
        self._fwd_path = None

    @classmethod
    def from_values(cls, fwd_path, interfaces, mtu, exp_time):
        p = cls.P_CLS.new_message(fwdPath=fwd_path.pack(), mtu=mtu, expTime=exp_time)
        ifs = p.init("interfaces", len(interfaces))
        for i, if_ in enumerate(interfaces):
            ifs[i] = if_.p
        return cls(p)

    def fwd_path(self):
        if not self._fwd_path:
            self._fwd_path = SCIONPath(self.p.fwdPath)
        return self._fwd_path

    def src_ia(self):
        return PathInterface(self.p.interfaces[0]).isd_as()

    def dst_ia(self):
        return PathInterface(self.p.interfaces[-1]).isd_as()

    def iter_ifs(self):
        for if_ in self.p.interfaces:
            yield PathInterface(if_)

    def short_desc(self):
        if_str = ", ".join([if_.short_desc() for if_ in self.iter_ifs()])
        return "Interfaces: %s MTU: %d" % (if_str, self.p.mtu)

    def __eq__(self, other):
        return list(self.iter_ifs()) == list(other.iter_ifs())


class PathInterface(Cerealizable):  # pragma: no cover
    """ISD-AS and interface tuple in forwarding paths."""
    P_CLS = P.PathInterface

    @classmethod
    def from_values(cls, isd_as, if_id):
        p = cls.P_CLS.new_message(isdas=int(isd_as), ifID=if_id)
        return cls(p)

    def isd_as(self):
        return ISD_AS(self.p.isdas)

    def __getitem__(self, idx):
        if idx == 0:
            return self.isd_as()
        elif idx == 1:
            return self.p.ifID
        raise SCIONIndexError(
            "Invalid index used on PathInterface object: %d" % idx)

    def short_desc(self):
        return "%s:%s" % (self.isd_as(), self.p.ifID)

    def __str__(self):
        return self.short_desc()

    def __eq__(self, other):
        return self.p.isdas == other.p.isdas and self.p.ifID == other.p.ifID
