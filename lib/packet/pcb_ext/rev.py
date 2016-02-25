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
:mod:`rev` --- Beacon revocation extension
==========================================
"""
# SCION
from lib.packet.pcb_ext import BeaconExtType, BeaconExtension
from lib.packet.rev_info import RevocationInfo


class RevPcbExt(BeaconExtension):  # pragma: no cover
    """
    Length of REVExtension
    """
    EXT_TYPE = BeaconExtType.REV
    LEN = 32

    def __init__(self, raw=None):
        """
        Initialize an instance of the class REVExtension

        :param raw:
        :type raw:
        """
        self.rev_info = None
        super().__init__(raw)

    def _parse(self, raw):
        self.rev_info = RevocationInfo(raw)

    @classmethod
    def from_values(cls, rev):
        """
        Construct extension with `rev` value.
        """
        inst = cls()
        inst.rev_info = rev
        return inst

    def pack(self):
        return self.rev_info.pack()

    def __len__(self):
        return len(self.rev_info)

    def __str__(self):
        return str(self.rev_info)
