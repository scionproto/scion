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
:mod:`info` --- SIBRA Segment Info PCB extension
================================================
"""
# SCION
from lib.defines import SIBRA_STEADY_ID_LEN
from lib.packet.pcb_ext import BeaconExtType, BeaconExtension
from lib.sibra.ext.info import ResvInfoSteady
from lib.util import Raw, hex_str


class SibraSegInfo(BeaconExtension):  # pragma: no cover
    """
    SIBRA Segment Info PCB extension. Used to attach reservation info to a
    PathSegment when registering a SIBRA steady path.
    """
    EXT_TYPE_STR = "SibraSegInfo"
    EXT_TYPE = BeaconExtType.SIBRA_SEG_INFO
    LEN = SIBRA_STEADY_ID_LEN + ResvInfoSteady.LEN

    def __init__(self, raw=None):
        self.id = None
        self.info = None
        super().__init__(raw)

    def _parse(self, raw):
        data = Raw(raw, self.EXT_TYPE_STR, self.LEN)
        self.id = data.pop(SIBRA_STEADY_ID_LEN)
        self.info = ResvInfoSteady(data.pop(ResvInfoSteady.LEN))

    @classmethod
    def from_values(cls, id_, info):
        inst = cls()
        assert isinstance(info, ResvInfoSteady)
        inst.id = id_
        inst.info = info
        return inst

    def exp_ts(self):
        return self.info.exp_ts()

    def pack(self):
        return self.id + self.info.pack()

    def __len__(self):
        return self.LEN

    def __str__(self):
        return "%s(%dB): id:%s info:%s" % (
            self.EXT_TYPE_STR, self.LEN, hex_str(self.id), self.info)

    def short_desc(self):
        return str(self)
