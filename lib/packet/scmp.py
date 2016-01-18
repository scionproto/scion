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
:mod:`scmp` --- SCION Control Message Protocol
==============================================
"""
# Stdlib
import struct

# External
import scapy.utils

# SCION
from lib.defines import L4_SCMP
from lib.errors import SCIONParseError
from lib.packet.ext_hdr import HopByHopExtension, HopByHopType
from lib.packet.packet_base import L4HeaderBase
from lib.util import Raw


class SCMPType(object):
    """
    SCMP types.

    This class contains a list of constants representing the current SCMP
    types. The set of types is loosely based on the ICMP types.

    .. warning::

       Not all types defined are supported!

    Attributes:
        ECHO_REQUEST (int): the type for an echo request (ping) message.
        ECHO_REPLY (int): the type for an echo reply (pong) message.
        DEST_UNREACHABLE (int): the type for a destination unreachable message,
            which indicates that the destination network, host, protocol, or
            port is unreachable.
        INVALID_PATH (int): the type for an invalid path message, which
            indicates that the path being used is invalid (e.g., the segment or
            opaque field on the segment has expired). This type is a
            hop-by-hop message, which means that an :class:`SCMPHopByHopExt`
            extension must be present in the packet to alert the router that it
            must check the payload.
    """

    ECHO_REQUEST = 0
    ECHO_REPLY = 1
    DEST_UNREACHABLE = 2
    INVALID_PATH = 3


class SCMPHopByHopExt(HopByHopExtension):
    """
    Extension to indicate the presence of a hop-by-hop SCMP message.

    SCION extension used to signal a hop-by-hop SCMP message. In this case, the
    router must ignore all other extensions and examine the payload, which will
    contain an SCMP message.
    """

    EXT_TYPE = HopByHopType.SCMP
    EXT_TYPE_STR = "SCMPHopByHopExt"
    SIGNAL = '\x01'
    PAD_BYTE = '\x00'

    def __init__(self):  # pragma: no cover
        super().__init__()
        self._set_payload(self.construct_payload())

    def construct_payload(self):
        """
        Construct the extension payload.

        Using the class variables `SIGNAL` and `PAD_BYTE`, construct a payload
        for the extension header that consists of `SIGNAL` and an appropriate
        number of `PAD_BYTE`s. The number of padding bytes is selected such
        that the total length of the payload plus the length of the subheader
        is a multiple of `ExtensionHeader.LINE_LEN`.

        Returns:
            A str representing the extension payload.
        """
        pad_len = ((self.LINE_LEN - self.SUBHDR_LEN - len(self.SIGNAL))
                    % self.LINE_LEN)
        return self.SIGNAL + pad_len * self.PAD_BYTE

class SCMPHeader(L4HeaderBase):
    """
    Packet header for SCMP messages.

    Attributes:
        type_: An int representing the SCMP message type.
        code: An int representing the SCMP message subtype.
        checksum: An int representing the SCMP header checksum.
        rest: An int representing type-dependent header information.
    """

    LEN = 8
    TYPE = L4_SCMP
    NAME = "SCMP"

    def __init__(self, raw=None):  # pragma: no cover
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

    @classmethod
    def from_values(cls, type_, code, rest=0):
        """
        Create a new SCMP header instance by specifying the field values.

        Create and return a SCMPHeader instance from a type, subtype, and
        rest-of-header. The checksum is computed automatically from the
        supplied values.

        Args:
            type_: An int representing the type of the SCMP message.
            code: An int representing the subtype of the SCMP message.
            rest: An int representing the rest of the header, whose format
                depends on the type.

        Returns:
            A `SCMPHeader` instance with the specified field values and
                appropriately-set checksum.
        """
        inst = cls()
        inst.type_ = type_
        inst.code = code
        inst.rest = rest
        inst.update_checksum()
        return inst

    def pack(self):
        """
        Return the raw byte string representation of the SCMPHeader instance.

        Pack the SCMPHeader instance's field values into a raw byte string. The
        checksum is *not* verified when packing the field values.
        """
        return struct.pack("!BBHI", self.type_, self.code, self.checksum,
                           self.rest)

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
