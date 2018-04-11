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
:mod:`seg_req` --- Path Segment request
============================================
"""
# External
import capnp  # noqa

# SCION
import proto.path_mgmt_capnp as P
from lib.defines import PATH_FLAG_CACHEONLY, PATH_FLAG_SIBRA
from lib.packet.hp_cfg import HPCfgId
from lib.packet.packet_base import Cerealizable
from lib.packet.path_mgmt.seg_recs import PathSegmentRecords
from lib.packet.scion_addr import ISD_AS


class PathSegmentReq(Cerealizable):  # pragma: no cover
    """Describes a request for path segment(s)"""
    NAME = "PathSegmentReq"
    P_CLS = P.SegReq

    @classmethod
    def from_values(cls, src_ia, dst_ia, flags=None, hp_cfg_ids=None):
        if not flags:
            flags = set()
        if not hp_cfg_ids:
            hp_cfg_ids = []
        p = cls.P_CLS.new_message(srcIA=int(src_ia), dstIA=int(dst_ia))
        if PATH_FLAG_SIBRA in flags:
            p.flags.sibra = True
        if PATH_FLAG_CACHEONLY in flags:
            p.flags.cacheOnly = True
        p.meta.init("hpCfgIds", len(hp_cfg_ids))
        for i, hp_cfg_id in enumerate(hp_cfg_ids):
            p.meta.hpCfgIds[i] = hp_cfg_id.p
        return cls(p)

    def src_ia(self):
        return ISD_AS(self.p.srcIA)

    def dst_ia(self):
        return ISD_AS(self.p.dstIA)

    def flags(self):
        flags = set()
        if self.p.flags.sibra:
            flags.add(PATH_FLAG_SIBRA)
        if self.p.flags.cacheOnly:
            flags.add(PATH_FLAG_CACHEONLY)
        return tuple(flags)

    def hp_cfg_id(self, idx):
        return HPCfgId(self.p.meta.hpCfgIds[idx])

    def iter_hp_cfg_ids(self, start=0):
        for i in range(start, len(self.p.meta.hpCfgIds)):
            yield self.hp_cfg_id(i)

    def __eq__(self, other):
        return (self.p.srcIA == other.p.srcIA and
                self.p.dstIA == other.p.dstIA and
                self.flags() == other.flags())

    def short_desc(self):
        desc = "%s -> %s %s" % (self.src_ia(), self.dst_ia(), self.flags())
        cfg_strs = []
        for cfg_id in self.iter_hp_cfg_ids():
            cfg_strs.append(cfg_id.short_desc())
        if cfg_strs:
            return "%s HPCfgIds: %s" % (desc, ", ".join(cfg_strs))
        return desc


class PathSegmentReply(Cerealizable):  # pragma: no cover
    NAME = "PathSegmentReply"
    P_CLS = P.SegReply

    @classmethod
    def from_values(cls, req, recs):
        p = cls.P_CLS.new_message(req=req.p, recs=recs.p)
        return cls(p)

    def req(self):
        return PathSegmentReq(self.p.req)

    def recs(self):
        return PathSegmentRecords(self.p.recs)

    def short_desc(self):
        return "Req: %s\n%s" % (self.req(), self.recs())
