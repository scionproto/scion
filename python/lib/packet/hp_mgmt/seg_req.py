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
:mod:`seg_req` --- Hidden Path Segment request
==============================================
"""
# External
import capnp  # noqa

# SCION
import proto.path_mgmt_capnp as P
from lib.errors import SCIONSigVerError
from lib.defines import PATH_FLAG_CACHEONLY, PATH_FLAG_SIBRA
from lib.packet.hp_mgmt.config import HiddenPathConfigId
from lib.packet.hp_mgmt.base import HiddenPathMgmtPayloadBase
from lib.packet.scion_addr import ISD_AS
from lib.types import PathMgmtType as PMT


class HiddenPathSegmentReq(HiddenPathMgmtPayloadBase):  # pragma: no cover
    """Describes a request for path segment(s)"""
    NAME = "HiddenPathSegmentReq"
    PAYLOAD_TYPE = PMT.REQUEST
    LEN = 1 + 2 * ISD_AS.LEN
    P_CLS = P.SegReq
    VER = len(P_CLS.schema.fields) - 1

    @classmethod
    def from_values(cls, src_ia, dst_ia, hp_cfg_ids, timestamp, flags=None):
        """
        :param src_ia: ISD_AS of source AS
        :param dst_ia: ISD_AS of destination AS
        :param hp_cfg_ids: list of hidden path configs
        :param timestamp: creation timestamp
        :param flags:
        """
        if not flags:
            flags = set()
        p = cls.P_CLS.new_message(srcIA=int(src_ia), dstIA=int(dst_ia))
        if PATH_FLAG_SIBRA in flags:
            p.flags.sibra = True
        if PATH_FLAG_CACHEONLY in flags:
            p.flags.cacheOnly = True
        p.meta.init("hpCfgIds", len(hp_cfg_ids))
        for i, hp_cfg_id in enumerate(hp_cfg_ids):
            p.meta.hpCfgIds[i] = hp_cfg_id.p
        return cls(p, timestamp)

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
        return HiddenPathConfigId(self.p.meta.hpCfgIds[idx])

    def iter_hp_cfg_ids(self, start=0):
        for i in range(start, len(self.p.meta.hpCfgIds)):
            yield self.hp_cfg_id(i)

    def sig_pack(self):
        """
        Pack for signing version 3 (defined by highest field number).
        """
        if self.VER != 3:
            raise SCIONSigVerError("HiddenPathSegmentReq.sig_pack cannot support version %s",
                                   self.VER)
        b = []
        b.append(self.p.srcIA.to_bytes(4, 'big'))
        b.append(self.p.dstIA.to_bytes(4, 'big'))
        b.append(self.p.flags.sibra.to_bytes(1, 'big'))
        b.append(self.p.flags.cacheOnly.to_bytes(1, 'big'))
        for hp_cfg_id in self.iter_hp_cfg_ids():
            b.append(hp_cfg_id.sig_pack1())
        return b"".join(b)

    def short_desc(self):
        return "%s -> %s %s" % (self.src_ia(), self.dst_ia(), self.flags())
