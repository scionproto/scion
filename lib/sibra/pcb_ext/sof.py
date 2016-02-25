# Copyright 2015 ETH Zurich
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
:mod:`sof` --- SIBRA Segment SOF PCB extension
================================================
"""
# SCION
from lib.sibra.ext.sof import SibraOpaqueField
from lib.packet.pcb_ext import BeaconExtType, BeaconExtension


class SibraSegSOF(BeaconExtension):  # pragma: no cover
    """
    SIBRA Segment SOF PCB extension. Used to attach a Sibra Opaque Field
    PathSegment when registering a SIBRA steady path.
    """
    EXT_TYPE_STR = "SibraSegSOF"
    EXT_TYPE = BeaconExtType.SIBRA_SEG_SOF
    LEN = SibraOpaqueField.LEN

    def __init__(self, raw=None):
        self.sof = None
        super().__init__(raw)

    def _parse(self, raw):
        self.sof = SibraOpaqueField(raw)

    @classmethod
    def from_values(cls, sof):
        inst = cls()
        assert isinstance(sof, SibraOpaqueField)
        inst.sof = sof
        return inst

    def pack(self):
        return self.sof.pack()

    def __len__(self):
        return self.LEN

    def __str__(self):
        return "%s(%dB): %s" % (self.EXT_TYPE_STR, self.LEN, self.sof)
