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
:mod:`segment` --- SIBRA steady path segment
============================================
"""
# Stdlib
import struct

# SCION
from lib.crypto.asymcrypto import sign
from lib.defines import SIBRA_STEADY_ID_LEN
from lib.packet.scion_addr import ISD_AS
from lib.sibra.ext.info import ResvInfoSteady
from lib.sibra.ext.sof import SibraOpaqueField
from lib.util import Raw, SCIONTime, hex_str, iso_timestamp


class SibraSegment(object):
    """
    Contains a SIBRA steady path segment.
    """
    NAME = "SibraSegment"
    TS_LEN = 4
    SIG_LEN = 64
    MIN_LEN = (SIBRA_STEADY_ID_LEN + TS_LEN + ResvInfoSteady.LEN + ISD_AS.LEN +
               1 + SIG_LEN)

    def __init__(self, raw=None):
        self.id = None
        self.timestamp = None
        self.info = None
        self.src_ia = None
        self.dst_ia = None
        self._sofs = []
        self.sig = bytes(self.SIG_LEN)
        if raw is not None:
            self._parse(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.MIN_LEN, min_=True)
        self.id = data.pop(SIBRA_STEADY_ID_LEN)
        self.timestamp = struct.unpack("!I", data.pop(self.TS_LEN))[0]
        self.info = ResvInfoSteady(data.pop(ResvInfoSteady.LEN))
        self._set_src()
        self.dst_ia = ISD_AS(data.pop(ISD_AS.LEN))
        num_hops = data.pop(1)
        for _ in range(num_hops):
            sof = SibraOpaqueField(data.pop(SibraOpaqueField.LEN))
            self._sofs.append(sof)
        self.sig = data.pop(self.SIG_LEN)

    @classmethod
    def from_values(cls, id_, info, dst_ia, sofs, ts=None):
        inst = cls()
        assert len(id_) == SIBRA_STEADY_ID_LEN
        assert isinstance(dst_ia, ISD_AS)
        assert len(sofs) > 0
        inst.id = id_
        inst.timestamp = ts or int(SCIONTime.get_time())
        inst.info = info
        inst._set_src()
        inst.dst_ia = dst_ia
        inst._sofs = sofs
        return inst

    def pack(self):
        packed = []
        packed.append(self.id)
        packed.append(struct.pack("!I", self.timestamp))
        packed.append(self.info.pack())
        packed.append(self.dst_ia.pack())
        packed.append(struct.pack("!B", len(self._sofs)))
        for sof in self._sofs:
            packed.append(sof.pack())
        packed.append(self.sig)
        return b"".join(packed)

    def _pack_sig(self, key):
        # Exclude the existing key (if any) from the input for the new
        # signature.
        data = self.pack()[:-self.SIG_LEN]
        return sign(data, key)

    def sign(self, key):
        self.sig = self._pack_sig(key)

    def verify(self, key):
        return self.sig == self._pack_sig()

    def num_hops(self):
        return len(self._sofs)

    def expiry(self):
        return self.info.exp_ts()

    def _set_src(self):
        self.src_ia = ISD_AS(self.id[:ISD_AS.LEN])

    def __len__(self):
        return self.MIN_LEN + len(self._sofs) * SibraOpaqueField.LEN

    def __str__(self):
        s = [self.short_desc()]
        s.append("  %s" % self.info)
        return "\n".join(s)

    def short_desc(self):
        return ("%s(%dB): %s->%s hops:%s id:%s ts:%s sig:%s..." % (
            self.NAME, len(self), self.src_ia, self.dst_ia, len(self._sofs),
            hex_str(self.id), iso_timestamp(self.timestamp),
            hex_str(self.sig)[:8],
        ))
