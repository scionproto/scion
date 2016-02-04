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
from lib.packet.path_mgmt import RevocationInfo
from lib.util import Raw


class RevocationObject(object):
    """
    Revocation object that gets stored to Zookeeper.
    """

    LEN = 8 + RevocationInfo.LEN

    def __init__(self, raw=None):
        self.if_id = 0
        self.hash_chain_idx = -1
        self.rev_info = None

        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Parses raw bytes and populates the fields.
        """
        data = Raw(raw, "RevocationObject", self.LEN)
        (self.if_id, self.hash_chain_idx) = struct.unpack("!II", data.pop(8))
        self.rev_info = RevocationInfo(data.pop(RevocationInfo.LEN))

    def pack(self):
        """
        Returns a bytes object from the fields.
        """
        return (struct.pack("!II", self.if_id, self.hash_chain_idx) +
                self.rev_info.pack())

    @classmethod
    def from_values(cls, if_id, index, rev_token):
        """
        Returns a RevocationInfo object with the specified values.

        :param if_id: The interface id of the corresponding interface.
        :type if_id: int
        :param index: The index of the rev_token in the hash chain.
        :type index: int
        :param rev_token: revocation token of interface
        :type: bytes
        """
        rev_obj = cls()
        rev_obj.if_id = if_id
        rev_obj.hash_chain_idx = index
        rev_obj.rev_info = RevocationInfo.from_values(rev_token)

        return rev_obj
