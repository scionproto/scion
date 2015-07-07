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
    :ivar next_ext:
    :type next_ext:
    :ivar hdr_len:
    :type hdr_len:
    :ivar parsed:
    :type parsed:
    """
    MIN_LEN = 2

    def __init__(self, raw=None):
        """
        Initialize an instance of the class ExtensionHeader.

        :param raw:
        :type raw:
        """
        HeaderBase.__init__(self)
        self.next_ext = 0
        self.hdr_len = 0
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
        self.next_ext, self.hdr_len = struct.unpack("!BB", raw)
        self.parsed = True

    def pack(self):
        """

        """
        return struct.pack("!BB", self.next_ext, self.hdr_len)

    def __len__(self):
        """

        """
        return 8

    def __str__(self):
        """

        """
        return "[EH next hdr: %u, len: %u]" % (self.next_ext, self.hdr_len)


class ICNExtHdr(ExtensionHeader):
    """
    The extension header for the SCION ICN extension.

    0          8         16      24                                           64
    | next hdr | hdr len |  type  |                reserved                    |

    :cvar MIN_LEN:
    :type MIN_LEN: int
    :cvar TYPE:
    :type TYPE: int
    :ivar fwd_flag:
    :type fwd_flag: int
    """
    MIN_LEN = 8
    TYPE = 220  # Extension header type

    def __init__(self, raw=None):
        """
        Initialize an instance of the class ICNExtHdr.
        Tells the edge router whether to forward this pkt to the local Content
        Cache or to the next AD.

        :param raw:
        :type raw:
        """
        ExtensionHeader.__init__(self)
        self.fwd_flag = 0
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """


        :param raw:
        :type raw:
        """
        assert isinstance(raw, bytes)
        dlen = len(raw)
        if dlen < self.MIN_LEN:
            logging.warning("Data too short to parse ICN extension hdr: "
                            "data len %u", dlen)
            return
        (self.next_ext, self.hdr_len, self.fwd_flag, _rsvd1, _rsvd2) = \
            struct.unpack("!BBBIB", raw)
        self.parsed = True
        return

    def pack(self):
        """


        :returns:
        :rtype:
        """
        # reserved field is stored in 2 parts - 32 + 8 bits
        return struct.pack("!BBBIB", self.next_ext, self.hdr_len,
                           self.fwd_flag, 0, 0)

    def __len__(self):
        """


        :returns:
        :rtype:
        """
        return ICNExtHdr.MIN_LEN

    def __str__(self):
        """


        :returns:
        :rtype:
        """
        return ("[ICN EH next hdr: %u, len: %u, fwd_flag: %u]" %
                (self.next_ext, self.hdr_len, self.fwd_flag))
