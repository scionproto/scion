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
from lib.types import ExtensionClass, TypeBase
from lib.packet.packet_base import HeaderBase


class HopByHopType(TypeBase):
    TRACEROUTE = 0
    SIBRA = 1
    SCMP = 2


class EndToEndType(TypeBase):
    PATH_TRANSPORT = 0


class ExtensionHeader(HeaderBase):
    """
    Base class for extension headers.

    An extension header consists of a three-byte subheader containing metadata
    and a payload consisting of extension-specific data. The lengths of the
    subheader and payload must sum to a multiple of `LINE_LEN` bytes.

    Attributes:
        NAME (str): the class name.
        LINE_LEN (int): the length of a line in the extension header. The
            length of an extension in bytes must be a multiple of this number.
        MIN_LEN (int): the minimum length of an extension header in bytes.
        EXT_CLASS (int): the class of the extension header (hop-by-hop or
            end-to-end). The possible values are defined in
            `lib.types.ExtensionClass`.
        EXT_TYPE (int): the type of extension.
        EXT_TYPE_STR (int): the name of the extension.
        SUBHDR_LEN (int): length in bytes of the extension subheader, which
            contains metadata (namely, the next header's type, current
            extension header length, and the current extension type.
        MIN_PAYLOAD_LEN (int): the minimum allowed length of the payload in
            bytes.
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

    def _parse(self, raw):  # pragma: no cover
        """
        Initialize an instance of the class ExtensionHeader.

        :param raw:
        :type raw:
        """
        self._hdr_len = self.bytes_to_hdr_len(len(raw))

    def _init_size(self, additional_lines):  # pragma: no cover
        """
        Initialize `additional_lines` of payload.
        All extensions have to have constant size.
        """
        self._hdr_len = additional_lines

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
        return (total_len // cls.LINE_LEN) - 1

    @classmethod
    def hdr_len_to_bytes(cls, hdr_len):  # pragma: no cover
        return (hdr_len + 1) * cls.LINE_LEN

    def __str__(self):
        payload_hex = binascii.hexlify(self.pack())
        return "[%s(%dB): class: %s payload: %s]" % (
            self.NAME, len(self), ExtensionClass.to_str(self.EXT_CLASS),
            payload_hex)


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
