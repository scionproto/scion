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
:mod:`ext_hdr` --- Extension header classes
===========================================
"""
# Stdlib
import binascii
import struct

# SCION
from lib.errors import SCIONParseError
from lib.packet.packet_base import HeaderBase
from lib.util import Raw


class ExtensionType(object):
    """
    Constants for two types of extensions. These values are shared with L4
    protocol values, and an appropriate value is placed in next_hdr type.
    """
    HOP_BY_HOP = 0
    END_TO_END = 222


class ExtensionHeader(HeaderBase):
    """
    Base base class for extension headers.

    :cvar MIN_LEN:
    :type MIN_LEN: int
    :ivar next_hdr:
    :type next_hdr:
    :ivar _hdr_len:
    :type _hdr_len:
    :ivar parsed:
    :type parsed:
    """
    LINE_LEN = 8  # Length of extension must be multiplication of LINE_LEN.
    MIN_LEN = LINE_LEN
    EXT_TYPE = None  # Type of extension (hop-by-hop or end-to-end).
    EXT_NO = None  # Number of extension.
    SUBHDR_LEN = 3
    MIN_PAYLOAD_LEN = MIN_LEN - SUBHDR_LEN

    def __init__(self, raw=None):
        """
        Initialize an instance of the class ExtensionHeader.

        :param raw:
        :type raw:
        :param _hdr_len: encoded length of extension header. The length in
                         bytes is calculated as (next_hdr + 1) * 8.
        :type _hdr_len: int
        :param next_hdr: indication of a next extension header. Must be set
                         by SCIONHeader's pack().
        :type next_hdr: int
        """
        super().__init__()
        self.next_hdr = 0
        self._hdr_len = 0
        self.payload = b"\x00" * self.MIN_PAYLOAD_LEN
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Initialize an instance of the class ExtensionHeader.

        :param raw:
        :type raw:
        """
        data = Raw(raw, "ExtensionHeader", self.MIN_LEN, min_=True)
        self.next_hdr, self._hdr_len, ext_no = \
            struct.unpack("!BBB", data.pop(self.SUBHDR_LEN))
        if ext_no != self.EXT_NO:
            raise SCIONParseError("Extension chain formed incorrectly")
        if len(raw) != len(self):
            raise SCIONParseError("Incorrect length of extensions")
        self.set_payload(data.pop())
        self.parsed = True

    def _init_size(self, additional_lines):
        """
        Initialize `additional_lines` of payload.
        All extensions have to have constant size.
        """
        self._hdr_len = additional_lines
        first_row = b"\x00" * self.MIN_PAYLOAD_LEN
        # Allocate additional lines.
        self.set_payload(first_row + b"\x00" * self.LINE_LEN * additional_lines)

    def set_payload(self, payload):
        """
        Set payload. Payload length must be equal to allocated space for the
        extensions.
        """
        payload_len = len(payload)
        # Length of extension must be padded to 8B.
        assert not (payload_len + self.SUBHDR_LEN) % self.LINE_LEN
        # Encode payload length.
        pay_len_enc = (payload_len + self.SUBHDR_LEN) // self.LINE_LEN - 1
        # Check whether payload length is correct.
        assert self._hdr_len == pay_len_enc
        self.payload = payload

    def pack(self):
        """
        Pack to byte array.
        """
        return (struct.pack("!BBB", self.next_hdr, self._hdr_len, self.EXT_NO) +
                self.payload)

    def __len__(self):
        """
        Return length of extenion header in bytes.
        """
        return (self._hdr_len + 1) * self.LINE_LEN

    def __str__(self):
        """

        """
        payload_hex = binascii.hexlify(self.payload)
        return "[EH next hdr: %u, len: %u, payload: %s]" % (
            self.next_hdr, len(self), payload_hex)


class HopByHopExtension(ExtensionHeader):
    """
    Base class for hop-by-hop extensions.
    """
    EXT_TYPE = ExtensionType.HOP_BY_HOP


class EndToEndExtension(ExtensionHeader):
    """
    Base class for end-to-end extensions.
    """
    EXT_TYPE = ExtensionType.END_TO_END
