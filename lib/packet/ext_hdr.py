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
import logging
import struct

# SCION
from lib.packet.packet_base import HeaderBase


class ExtensionHeader(HeaderBase):
    """
    Base class for extension headers.
    For each extension header there should be a subclass of this class (e.g
    StrideExtensionHeader).

    :cvar MIN_LEN:
    :type MIN_LEN: int
    :ivar next_hdr:
    :type next_hdr:
    :ivar _hdr_len:
    :type _hdr_len:
    :ivar parsed:
    :type parsed:
    """
    MIN_LEN = 8
    TYPE = 200  # Type for a plain extension.

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
        HeaderBase.__init__(self)
        self.next_hdr = 0
        self._hdr_len = 0
        self.payload = b"\x00" * 6
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Initialize an instance of the class ExtensionHeader.

        :param raw:
        :type raw:
        """
        assert isinstance(raw, bytes)
        dlen = len(raw)
        if dlen < self.MIN_LEN:
            logging.warning("Data too short to parse extension hdr: "
                            "data len %u", dlen)
            return
        self.next_hdr, self._hdr_len = struct.unpack("!BB", raw[:2])
        assert dlen == len(self)
        self.set_payload(raw[2:])
        self.parsed = True

    def set_payload(self, payload):
        """
        Set payload, pad to 8 bytes if necessary, and update _hdr_len.
        """
        payload_len = len(payload)
        if payload_len < 6:  # FIXME(PSz): Should we (or ext developer) pad it?
            logging.warning("Extension is unpadded, adding padding.")
            payload += b"\x00" * (6 - payload_len)
            payload_len = 6
        payload_len -= 6  # After -6 it should be a multiplication of 8.
        to_pad = payload_len % self.MIN_LEN
        if to_pad:  # FIXME(PSz): Should we (or ext developer) pad it?
            logging.warning("Extension is unpadded, adding padding.")
            payload += b"\x00" * (self.MIN_LEN - to_pad)
            payload_len += self.MIN_LEN - to_pad
        self._hdr_len = payload_len // self.MIN_LEN
        self.payload = payload

    def pack(self):
        """

        """
        return struct.pack("!BB", self.next_hdr, self._hdr_len) + self.payload

    def __len__(self):
        """
        Return length of extenion header in bytes.
        """
        return (self._hdr_len + 1) * self.MIN_LEN

    def __str__(self):
        """

        """
        return "[EH next hdr: %u, len: %u, payload: %s]" % (self.next_hdr,
                                                            len(self),
                                                            self.payload)
