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
# SCION
from lib.types import ExtensionClass
from lib.packet.packet_base import Serializable
from lib.util import hex_str


class ExtensionHeader(Serializable):
    """
    Base class for extension headers.
    """
    NAME = "ExtensionHeader"
    LINE_LEN = 8  # Length of extension must be multiplication of LINE_LEN.
    MIN_LEN = LINE_LEN
    EXT_CLASS = None  # Class of extension (hop-by-hop or end-to-end).
    EXT_TYPE = None  # Type of extension.
    EXT_TYPE_STR = None  # Name of extension.
    SUBHDR_LEN = 3
    MIN_PAYLOAD_LEN = MIN_LEN - SUBHDR_LEN

    def __init__(self, raw=None):  # pragma: no cover
        self._hdr_len = 1
        super().__init__(raw)

    def _parse(self, raw):  # pragma: no cover
        self._hdr_len = self.bytes_to_hdr_len(len(raw))

    def _init_size(self, additional_lines):  # pragma: no cover
        """
        Initialize `additional_lines` of payload.
        All extensions have to have constant size.
        """
        self._hdr_len = additional_lines + 1

    def _check_len(self, payload):  # pragma: no cover
        """
        Check whether payload length is equal to the allocated space for the
        extension.
        """
        assert self._hdr_len == self.bytes_to_hdr_len(len(payload))

    def __len__(self):  # pragma: no cover
        """
        Return length of extenion header in bytes.
        """
        return self.hdr_len_to_bytes(self._hdr_len)

    def hdr_len(self):  # pragma: no cover
        return self._hdr_len

    @classmethod
    def bytes_to_hdr_len(cls, bytes_):
        total_len = (bytes_ + cls.SUBHDR_LEN)
        assert total_len % cls.LINE_LEN == 0
        return total_len // cls.LINE_LEN

    @classmethod
    def hdr_len_to_bytes(cls, hdr_len):  # pragma: no cover
        return hdr_len * cls.LINE_LEN

    def reverse(self):  # pragma: no cover
        pass

    def get_next_ifid(self):  # pragma: no cover
        pass

    def __str__(self):
        return "%s(%dB): class: %s payload: %s" % (
            self.NAME, len(self), ExtensionClass.to_str(self.EXT_CLASS),
            hex_str(self.pack()))


class HopByHopExtension(ExtensionHeader):
    """
    Base class for hop-by-hop extensions.
    """
    EXT_CLASS = ExtensionClass.HOP_BY_HOP


class EndToEndExtension(ExtensionHeader):
    """
    Base class for end-to-end extensions.
    """
    EXT_CLASS = ExtensionClass.END_TO_END
