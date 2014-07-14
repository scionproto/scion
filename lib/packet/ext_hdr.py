"""
ext_hdr.py

Copyright 2014 ETH Zurich

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import logging

from bitstring import BitArray
import bitstring

from lib.packet.packet_base import HeaderBase


class ExtensionHeader(HeaderBase):
    """
    Base class for extension headers.

    For each extension header there should be a subclass of this class (e.g
    StrideExtensionHeader).
    """

    MIN_LEN = 2

    def __init__(self, raw=None):
        HeaderBase.__init__(self)
        self.next_ext = 0
        self.hdr_len = 0
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        assert isinstance(raw, bytes)
        dlen = len(raw)
        if dlen < ExtensionHeader.MIN_LEN:
            logging.warning("Data too short to parse extension hdr: "
                "data len %u", dlen)
            return
        bits = BitArray(bytes=raw)
        self.next_ext, self.hdr_len = bits.unpack("uintle:8, uintle:8")
        self.parsed = True

    def pack(self):
        return bitstring.pack("uintle:8, uintle:8",
                              self.next_ext, self.hdr_len).bytes

    def __len__(self):
        return 8

    def __str__(self):
        return "[EH next hdr: %u, len: %u]" % (self.next_ext, self.hdr_len)


class ICNExtHdr(ExtensionHeader):
    """
    The extension header for the SCION ICN extension.

    0          8         16      24                                           64
    | next hdr | hdr len |  type  |                reserved                    |
    """

    MIN_LEN = 8
    TYPE = 220  # Extension header type

    def __init__(self, raw=None):
        ExtensionHeader.__init__(self)
        self.fwd_flag = 0  # Tells the edge router whether to forward this pkt
                           # to the local Content Cache or to the next AD.
#         self.src_addr_len = 0  # src addr len (6 bits)
#         self.dst_addr_len = 0  # dst addr len (6 bits)
#         self.cid = 0  # Content ID (20 bytes)
#         self.src_addr = None  # src address (4, 8 or 20 bytes)
#         self.dst_addr = None  # dst address (4, 8 or 20 bytes)

        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        assert isinstance(raw, bytes)
        dlen = len(raw)
        if dlen < ExtensionHeader.MIN_LEN:
            logging.warning("Data too short to parse ICN extension hdr: "
                "data len %u", dlen)
            return
        bits = BitArray(bytes=raw)
        (self.next_ext, self.hdr_len, self.fwd_flag, _rsvd) = \
            bits.unpack("uintle:8, uintle:8, uintle:8, uintle:40")
        self.parsed = True
        return

    def pack(self):
        return bitstring.pack("uintle:8, uintle:8, uintle:8, uintle:40",
            self.next_ext, self.hdr_len, self.fwd_flag, 0).bytes

    def __len__(self):
        return ICNExtHdr.MIN_LEN

    def __str__(self):
        return ("[ICN EH next hdr: %u, len: %u, fwd_flag: %u]" %
                (self.next_ext, self.hdr_len, self.fwd_flag))
