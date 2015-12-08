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
:mod:`scmp` --- SCION ICMP
==========================
"""
# Stdlib
import struct

# External
import scapy.utils

# SCION
from lib.errors import SCIONParseError
from lib.packet.packet_base import HeaderBase, PacketBase
from lib.util import Raw


class SCMPType(object):
    """
    SCMP types.

    This class contains a list of constants representing the current SCMP
    types. The set of types is loosely based on the ICMP types. At the moment
    only the currently-supported types are included.
    """

    ECHO_REPLY = 0
    # TODO: Add support for following constants in the near future
    #DEST_UNREACHABLE = 1
    #INVALID_PATH = 2


class SCMPHeader(HeaderBase):
    """
    Packet header for SCMP messages.

    Attributes:
        type_: An int representing the SCMP message type.
        code: An int representing the SCMP message subtype.
        checksum: An int representing the SCMP header checksum.
        rest: An int representing type-dependent header information.
    """

    LEN = 8

    def __init__(self, raw=None):
        super().__init__()
        self.type_ = None
        self.code = None
        self.checksum = None
        self.rest = None
        if raw is not None:
            self._parse(raw)

    def _parse(self, raw):
        """
        Parse a raw bytes string to populate the instance attributes.

        Args:
            raw: a `bytes` string representing the header data to be parsed.

        Raises:
            SCIONParseError: An error occurred in verifying the supplied
                checksum with the other supplied fields.
        """
        data = Raw(raw, "SCMPHeader", self.LEN)
        self.type_, self.code, self.checksum, self.rest = \
            struct.unpack("!BBHI", data.pop(self.LEN))
        if not self.verify_checksum():
            raise SCIONParseError(
                    "SCMPHeader: checksum in header (%s) does not match "
                    "checksum of supplied data (%s)" % (
                        hex(self.checksum), hex(self.compute_checksum())))

    def pack(self):
        pass

    def __len__(self):
        return self.LEN

    def __str__(self):
        return ("[SCMP type: %d, code: %d, checksum: %x, rest: %x]" %
                    self.type_, self.code, self.checksum, self.rest)


    def verify_checksum(self):
        """
        Attempt to verify the checksum in the header.

        Returns:
            A bool representing whether the checksum stored in the header was
            successfully verified.
        """
        return self.checksum == self.compute_checksum()

    def update_checksum(self):
        """
        Update the instance's checksum field based on the contents of the other
        fields.

        Set the `checksum` attribute of the instance to the checksum of the
        other fields. Any existing value in the `checksum` attribute is
        overwritten. A postcondition of this method is that the checksum is
        guaranteed to verify successfully.
        """
        self.checksum = self.compute_checksum()

    def compute_checksum(self):
        """
        Compute and return the checksum of the SCMP header.

        Compute the SCMP header checksum. The checksum is the same as used for
        the ICMP header, i.e., the Internet checksum described in RFC 1071. The
        basic approach of the Internet checksum is that the header (with 0 in
        place of the checksum field) is split into 2-byte words, these words
        are summed together using ones-complement arithmetic, and the
        ones-complement of this sum is used as the checksum.

        Returns:
            An int representing the checksum.
        """
        pseudo_header = struct.pack('!BBHI', self.type_, self.code, 0,
                                    self.rest)
        return scapy.utils.checksum(pseudo_header)


class SCMPPacket(PacketBase):
    """
    Packet format for SCMP messages.
    """

    def __init__(self, raw=None):
        pass

    def _parse(self, raw):
        pass

    def from_values(self, *args, **kwargs):
        pass

    def pack(self):
        pass

    def __len__(self):
        pass

    def __str__(self):
        pass
