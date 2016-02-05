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
:mod:`opt` --- OPT extension header and its handler
=================================================================
"""
# SCION
from Crypto.Hash import SHA256

from lib.crypto.symcrypto import cbcmac, compute_session_key
from lib.packet.ext_hdr import HopByHopExtension
from lib.packet.packet_base import PayloadBase
from lib.util import Raw
from lib.types import ExtHopByHopType


class OPTExt(HopByHopExtension):
    """
    OPT extension Header.

    This extension header supports retroactive Pathtrace from the OPT-Protocol.

    0B       1        2        3        4        5        6        7
    +--------+--------+--------+--------+--------+--------+--------+--------+
    | xxxxxxxxxxxxxxxxxxxxxxxx |                    padding                 |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                               Session ID...                           |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                            ...Session ID                              |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                                  PVF...                               |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                               ...PVF                                  |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    """
    NAME = "OPTExt"
    EXT_TYPE = ExtHopByHopType.OPT
    SESSION_ID_LEN = 16
    PVF_LEN = 16
    PADDING_LEN = 5
    LEN = PADDING_LEN + SESSION_ID_LEN + PVF_LEN
    NUMBER_OF_ADDITION_LINES = 4

    def __init__(self, raw=None):
        """
        Initialize an instance of the class OPTExt

        :param raw:
        :type raw:
        """
        super().__init__()
        self.session_id = None
        self.pvf = None
        if raw:
            self._parse(raw)

    def _parse(self, raw):
        """
        Parse payload.
        """
        data = Raw(raw, self.NAME, self.LEN)
        super()._parse(data)
        # drop padding
        data.pop(self.PADDING_LEN)

        self.session_id = data.pop(self.SESSION_ID_LEN)
        self.pvf = data.pop(self.PVF_LEN)

    @classmethod
    def from_values(cls, session_id, pvf=None):
        """
        Construct extension

        :param session_id: Session ID (16 B)
        :type session_id: bytes
        :param pvf: Path verification Field (16 B)
        :type pvf: bytes
        :returns: returns an instance
        :rtype: OPTExt
        """
        inst = OPTExt()
        inst.session_id = session_id
        inst.pvf = pvf
        inst._init_size(inst.NUMBER_OF_ADDITION_LINES)
        return inst

    def pack(self):
        packed = []
        packed.append(bytes(self.PADDING_LEN))
        packed.append(self.session_id)
        packed.append(self.pvf)
        raw = b"".join(packed)
        self._check_len(raw)
        return raw

    def reverse(self):
        self.pvf = None

    @staticmethod
    def compute_intermediate_pvf(session_key, pvf):
        """
        Compute the intermediate pvf.

        This method is used by process to update the PVF field.

        :param session_key: The session key of the AS (16 B)
        :type session_key: bytes
        :param pvf: The PVF value (16 B)
        :type pvf: bytes
        :returns: the updated PVF value (16 B)
        :rtype: bytes
        """
        return cbcmac(session_key, pvf)

    def process(self, secret_value):
        """
        Process the header.

        This method is used by AS to process the extension header.

        :param secret_value: The secret value of the AS (16 B)
        :type secret_value: bytes
        :returns: empty list
        :rtype: list
        """
        session_key = compute_session_key(secret_value, self.session_id)
        self.pvf = self.compute_intermediate_pvf(session_key, self.pvf)
        return []

    @staticmethod
    def compute_data_hash(payload):
        """
        Compute the DataHash of the payload.

        :param payload: The payload
        :type payload: PayloadBase
        :returns: the DataHash of the payload (16 B)
        :rtype: bytes
        """
        assert isinstance(payload, PayloadBase)
        # TODO(rsd) use better hash function ?
        return SHA256.new(payload.pack()).digest()[:16]

    @staticmethod
    def compute_initial_pvf(session_key_dst, data_hash):
        """
        Compute the initial value of the PVF.

        :param session_key_dst: The session key of the destination (16 B)
        :type session_key_dst: bytes
        :param data_hash: The DataHash of the payload (16 B)
        :type data_hash: bytes
        :returns: the initial PVF value (16 B)
        :rtype: bytes
        """
        return cbcmac(session_key_dst, data_hash)

    def set_initial_pvf(self, session_key_dst, payload):
        """

        :param session_key_dst: The session key of the destination (16 B)
        :type session_key_dst: bytes
        :param payload: The payload of the packet
        :type payload: PayloadBase
        """

        data_hash = self.compute_data_hash(payload)
        self.pvf = self.compute_initial_pvf(session_key_dst, data_hash)

    def __str__(self):
        return '%s(%sB):\nsession id:%s\npvf: %s' % \
               (self.NAME, len(self), self.session_id, self.pvf)
