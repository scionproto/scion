# Copyright 2014 ETH Zurich
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
:mod:`rev_obj` --- Revocation object
====================================
"""
# Stdlib
import struct

# SCION
from lib.packet.packet_base import Serializable
from lib.packet.path_mgmt.rev_info import RevocationInfo
from lib.util import Raw


class RevocationObject(Serializable):
    """
    Revocation object that gets stored to Zookeeper.
    """
    NAME = "RevocationObject"

    def __init__(self, raw=None):
        self.if_id = 0
        self.isd_as = 0
        self.rev_info = None
        super().__init__(raw)

    def _parse(self, raw):
        """
        Parses raw bytes and populates the fields.
        """
        data = Raw(raw, self.NAME)
        self.if_id, self.isd_as = struct.unpack("!II", data.pop(8))
        self.rev_info = RevocationInfo.from_raw(data.pop())

    @classmethod
    def from_values(cls, if_id, isd_as, rev_info):
        """
        Returns a RevocationInfo object with the specified values.

        :param int if_id: The interface id of the corresponding interface.
        :param int isd_as: The isd, as of the corresponding interface.
        :param RevocationInfo rev_info: revocation info of interface
        """
        inst = cls()
        inst.if_id = if_id
        inst.isd_as = isd_as
        inst.rev_info = rev_info
        return inst

    def pack(self):
        """
        Returns a bytes object from the fields.
        """
        return (struct.pack("!II", self.if_id, self.isd_as) +
                self.rev_info.copy().pack())

    def __len__(self):
        raise NotImplementedError

    def __str__(self):
        return "%s: IF id: %s ISD_AS: %s Rev info: %s" % (
            self.NAME, self.if_id, self.isd_as, self.rev_info)
