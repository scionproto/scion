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

# SCION
from lib.packet.packet_base import HeaderBase
from lib.util import Raw


class ExtensionClass(object):
    """
    Constants for two types of extensions. These values are shared with L4
    protocol values, and an appropriate value is placed in next_hdr type.
    """
    HOP_BY_HOP = 0
    END_TO_END = 222  # (Expected:-) number for SCION end2end extensions.


class ExtensionHeader(HeaderBase):
    """
    Base class for extension headers.

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
    EXT_CLASS = None  # Class of extension (hop-by-hop or end-to-end).
    EXT_TYPE = None  # Type of extension.
    EXT_TYPE_STR = None  # Name of extension.
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
        self._hdr_len = 0
        if raw is not None:
            self._parse(raw)

    def _parse(self, raw):
        """
        Initialize an instance of the class ExtensionHeader.

        :param raw:
        :type raw:
        """
        data = Raw(raw, "ExtensionHeader", self.MIN_LEN, min_=True)
        self._hdr_len = self.bytes_to_hdr_len(len(data))
        self._set_payload(data.pop())

    def _init_size(self, additional_lines):
        """
        Initialize `additional_lines` of payload.
        All extensions have to have constant size.
        """
        self._hdr_len = additional_lines
        # Allocate additional lines.
        self._set_payload(bytes(self.MIN_PAYLOAD_LEN + self.LINE_LEN *
                                additional_lines))

    def _set_payload(self, payload):
        """
        Set payload. Payload length must be equal to allocated space for the
        extensions.
        """
        # Check whether payload length is correct.
        assert self._hdr_len == self.bytes_to_hdr_len(len(payload))
        self._raw = payload

    def __len__(self):
        """
        Return length of extenion header in bytes.
        """
        return self.hdr_len_to_bytes(self._hdr_len)

    def hdr_len(self):
        return self._hdr_len

    @classmethod
    def bytes_to_hdr_len(cls, bytes_):
        total_len = (bytes_ + cls.SUBHDR_LEN)
        assert total_len % cls.LINE_LEN == 0
        return (total_len // cls.LINE_LEN) - 1

    @classmethod
    def hdr_len_to_bytes(cls, hdr_len):
        return (hdr_len + 1) * cls.LINE_LEN

    def __str__(self):
        """

        """
        payload_hex = binascii.hexlify(self._raw)
        return "[EH hdr. class: %s type: %s len: %d payload: %s]" % (
            self.EXT_CLASS_STR, self.EXT_TYPE_STR, len(self), payload_hex)


class HopByHopExtension(ExtensionHeader):
    """
    Base class for hop-by-hop extensions.
    """
    EXT_CLASS = ExtensionClass.HOP_BY_HOP
    EXT_CLASS_STR = "Hop-by-hop"


class EndToEndExtension(ExtensionHeader):
    """
    Base class for end-to-end extensions.
    """
    EXT_CLASS = ExtensionClass.END_TO_END
    EXT_CLASS_STR = "End-to-end"
