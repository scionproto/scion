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
:mod:`scion` --- SCION packets
==============================
"""
# Stdlib
import logging
import struct

# SCION
from lib.defines import L4_PROTO, DEFAULT_L4_PROTO
from lib.errors import SCIONIndexError, SCIONParseError
from lib.packet.ext_hdr import ExtensionClass, ExtensionHeader
from lib.packet.ext.traceroute import TracerouteExt
from lib.packet.host_addr import HostAddrSVC, haddr_get_type
from lib.packet.opaque_field import (
    InfoOpaqueField,
    OpaqueField,
    OpaqueFieldType as OFT,
)
from lib.packet.packet_base import HeaderBase, PacketBase
from lib.packet.path import (
    CorePath,
    CrossOverPath,
    EmptyPath,
    PathBase,
    PeerPath,
)
from lib.packet.scion_addr import ISD_AD, SCIONAddr
from lib.util import Raw

# Dictionary of supported extensions (i.e., parsed by SCIONHeader)
EXTENSIONS = {
    (ExtensionClass.HOP_BY_HOP, TracerouteExt.EXT_TYPE): TracerouteExt,
}


class PacketType(object):
    """
    Defines constants for the SCION packet types.
    """
    # Data packet
    DATA = HostAddrSVC(0, raw=False)
    # Path Construction Beacon
    BEACON = HostAddrSVC(1, raw=False)
    # Path management packet from/to PS
    PATH_MGMT = HostAddrSVC(2, raw=False)
    # TRC file request to parent AD
    TRC_REQ = HostAddrSVC(3, raw=False)
    # TRC file request to lCS
    TRC_REQ_LOCAL = HostAddrSVC(4, raw=False)
    # TRC file reply from parent AD
    TRC_REP = HostAddrSVC(5, raw=False)
    # cert chain request to parent AD
    CERT_CHAIN_REQ = HostAddrSVC(6, raw=False)
    # local cert chain request
    CERT_CHAIN_REQ_LOCAL = HostAddrSVC(7, raw=False)
    # cert chain reply from lCS
    CERT_CHAIN_REP = HostAddrSVC(8, raw=False)
    # IF ID packet to the peer router
    IFID_PKT = HostAddrSVC(9, raw=False)
    SRC = [BEACON, PATH_MGMT, CERT_CHAIN_REP, TRC_REP]
    DST = [PATH_MGMT, TRC_REQ, TRC_REQ_LOCAL, CERT_CHAIN_REQ,
           CERT_CHAIN_REQ_LOCAL, IFID_PKT]


def get_type(pkt):
    """
    Return the packet type; used for dispatching.

    :param pkt: the packet.
    :type pkt: bytes
    :returns: the packet type.
    :rtype: int
    """
    if pkt.hdr.src_addr.host_addr in PacketType.SRC:
        return pkt.hdr.src_addr.host_addr
    if pkt.hdr.dst_addr.host_addr in PacketType.DST:
        return pkt.hdr.dst_addr.host_addr
    return PacketType.DATA


class SCIONCommonHdr(HeaderBase):
    """
    Encapsulates the common header for SCION packets.
    """
    LEN = 8

    def __init__(self, raw=None):
        """
        Initialize an instance of the class SCIONCommonHdr.

        :param raw:
        :type raw:
        """
        super().__init__()
        self.version = 0  # Version of SCION packet.
        self.src_addr_type = None  # Type of the src address.
        self.src_addr_len = 0  # Length of the src address.
        self.dst_addr_type = None  # Length of the dst address.
        self.dst_addr_len = 0  # Length of the dst address.
        self.total_len = 0  # Total length of the packet.
        self.curr_iof_idx = 0  # Index of the current Info Opaque Field
        self.curr_of_idx = 0  # Index of the current Opaque Field
        self.next_hdr = 0  # Type of the next hdr field (IP protocol numbers).
        self.hdr_len = 0  # Header length including the path.

        if raw is not None:
            self.parse(raw)

    @classmethod
    def from_values(cls, src, dst, next_hdr):
        """
        Returns a SCIONCommonHdr object with the values specified.

        :param SCIONAddr src: Source address.
        :param SCIONAddr dst: Destination address.
        :param int next_hdr: Next header type.
        """
        assert isinstance(src, SCIONAddr)
        assert isinstance(dst, SCIONAddr)
        chdr = cls()
        chdr.src_addr_type = src.host_addr.TYPE
        chdr.src_addr_len = len(src)
        chdr.dst_addr_type = dst.host_addr.TYPE
        chdr.dst_addr_len = len(dst)
        chdr.next_hdr = next_hdr
        chdr.hdr_len = (SCIONCommonHdr.LEN + chdr.src_addr_len +
                        chdr.dst_addr_len)
        chdr.total_len = chdr.hdr_len

        return chdr

    def parse(self, raw):
        """
        Parses the raw data and populates the fields accordingly.
        """
        data = Raw(raw, "SCIONCommonHdr", self.LEN)
        (types, self.total_len, curr_iof_p, curr_of_p,
         self.next_hdr, self.hdr_len) = struct.unpack("!HHBBBB", data.pop())
        self.version = (types & 0xf000) >> 12
        self.src_addr_type = (types & 0x0fc0) >> 6
        self.src_addr_len = ISD_AD.LEN + \
            haddr_get_type(self.src_addr_type).LEN
        self.dst_addr_type = types & 0x003f
        self.dst_addr_len = ISD_AD.LEN + \
            haddr_get_type(self.dst_addr_type).LEN
        first_of_offset = self.LEN + self.src_addr_len + self.dst_addr_len
        # FIXME(kormat): NB this assumes that all OFs have the same length.
        self.curr_iof_idx = (curr_iof_p - first_of_offset) // OpaqueField.LEN
        self.curr_of_idx = (curr_of_p - first_of_offset) // OpaqueField.LEN

    def pack(self):
        """
        Returns the common header as 8 byte binary string.
        """
        types = ((self.version << 12) | (self.src_addr_type << 6) |
                 self.dst_addr_type)
        first_of_offset = self.LEN + self.src_addr_len + self.dst_addr_len
        curr_iof_p = first_of_offset + (self.curr_iof_idx * OpaqueField.LEN)
        curr_of_p = first_of_offset + (self.curr_of_idx * OpaqueField.LEN)
        return struct.pack("!HHBBBB", types, self.total_len,
                           curr_iof_p, curr_of_p,
                           self.next_hdr, self.hdr_len)

    def __len__(self):  # pragma: no cover
        return self.hdr_len

    def __str__(self):
        values = {
            "src_type": haddr_get_type(self.src_addr_type).NAME,
            "dst_type": haddr_get_type(self.dst_addr_type).NAME,
        }
        for i in ("version", "src_addr_len", "dst_addr_len", "total_len",
                  "curr_iof_idx", "curr_of_idx", "next_hdr", "hdr_len"):
            values[i] = getattr(self, i)
        return (
            "[CH ver: {version:d}, src type: {src_type:s}({src_addr_len:d}b), "
            "dst type: {dst_type:s}({dst_addr_len:d}b), "
            "total len: {total_len:d}b, current IOF idx: {curr_iof_idx:d}, "
            "current OF idx: {curr_of_idx:d}, next hdr: {next_hdr:d}, "
            "hdr len: {hdr_len:d}]"
        ).format(**values)


class SCIONHeader(HeaderBase):
    """
    The SCION packet header.
    """

    MIN_LEN = 16  # Update when values are fixed.

    def __init__(self, raw=None):
        """
        Initialize an instance of the class SCIONHeader.

        :param bytes raw:
        """
        super().__init__()
        self.common_hdr = None
        self.src_addr = None
        self.dst_addr = None
        self._path = None
        self.extension_hdrs = []
        self.l4_proto = DEFAULT_L4_PROTO

        if raw is not None:
            self.parse(raw)

    @classmethod
    def from_values(cls, src, dst, path=None, ext_hdrs=None,
                    l4_proto=DEFAULT_L4_PROTO):
        """
        Returns a SCIONHeader with the values specified.
        """
        assert isinstance(src, SCIONAddr)
        assert isinstance(dst, SCIONAddr)
        assert isinstance(path, (PathBase, type(None)))
        hdr = cls()
        if ext_hdrs is None:
            ext_hdrs = []
            next_hdr = l4_proto
        else:
            next_hdr = ext_hdrs[0].EXT_CLASS
        hdr.common_hdr = SCIONCommonHdr.from_values(src, dst, next_hdr)
        hdr.src_addr = src
        hdr.dst_addr = dst
        hdr.l4_proto = l4_proto
        hdr.set_path(path)
        hdr.add_extensions(ext_hdrs)

        return hdr

    def add_extensions(self, ext_hdrs):
        """
        Add extension headers and updates necessary fields.
        """
        for ext in ext_hdrs:
            self.extension_hdrs.append(ext)
            self.common_hdr.total_len += len(ext)
        self._set_next_hdrs()

    def _set_next_hdrs(self):
        """
        Set correct next_hdr fields.
        """
        # Set the first and the last next_hdr.
        if self.extension_hdrs:
            self.common_hdr.next_hdr = self.extension_hdrs[0].EXT_CLASS
            self.extension_hdrs[-1].next_hdr = self.l4_proto
        else:
            self.common_hdr.next_hdr = self.l4_proto
        # Set next_hdr fields according to the extension chain
        l = 0
        while l < len(self.extension_hdrs) - 1:
            self.extension_hdrs[l].next_hdr = self.extension_hdrs[l+1].EXT_CLASS
            l += 1

    def remove_extensions(self):
        """
        Removes all extensions and updates necessary fields.
        """
        for ext in self.extension_hdrs:
            self.common_hdr.total_len -= len(ext)
        self.extension_hdrs = []
        self.common_hdr.next_hdr = self.l4_proto

    def get_path(self):
        """
        Returns the path in the header.
        """
        return self._path

    def set_path(self, path):
        """
        Sets path to 'path' and updates necessary fields..
        """
        if self._path is not None:
            path_len = len(self._path.pack())
            self.common_hdr.hdr_len -= path_len
            self.common_hdr.total_len -= path_len
        self._path = path
        if path is not None:
            path_len = len(path.pack())
            self.common_hdr.hdr_len += path_len
            self.common_hdr.total_len += path_len
        self.set_first_of_pointers()

    def parse(self, raw):
        """
        Parses the raw data and populates the fields accordingly.
        """
        data = Raw(raw, "SCIONHeader", self.MIN_LEN, min_=True)
        self._parse_common_hdr(data)
        self._parse_opaque_fields(data)
        self._parse_extension_hdrs(data)
        self.parsed = True
        return data.offset()

    def _parse_common_hdr(self, data):
        """
        Parses the raw data and populates the common header fields accordingly.
        """
        self.common_hdr = SCIONCommonHdr(data.pop(SCIONCommonHdr.LEN))
        self.src_addr = SCIONAddr((self.common_hdr.src_addr_type,
                                   data.pop(self.common_hdr.src_addr_len)))
        self.dst_addr = SCIONAddr((self.common_hdr.dst_addr_type,
                                   data.pop(self.common_hdr.dst_addr_len)))

    def _parse_opaque_fields(self, data):
        """
        Parses the raw data to opaque fields and populates the path field
        accordingly.
        """
        # PSz: UpPath-only case missing, quick fix:
        if data.offset() == self.common_hdr.hdr_len:
            self._path = EmptyPath()
            return
        info = InfoOpaqueField(data.get(InfoOpaqueField.LEN))
        path_data = data.pop(self.common_hdr.hdr_len - data.offset())
        if info.info == OFT.CORE:
            self._path = CorePath(path_data)
        elif info.info == OFT.SHORTCUT:
            self._path = CrossOverPath(path_data)
        elif info.info in (OFT.INTRA_ISD_PEER, OFT.INTER_ISD_PEER):
            self._path = PeerPath(path_data)
        else:
            raise SCIONParseError("SCIONHeader: Can not parse path in "
                                  "packet: Unknown type %x", info.info)

    def _parse_extension_hdrs(self, data):
        """
        Parses the raw data and populates the extension header fields
        accordingly.
        """
        cur_hdr_type = self.common_hdr.next_hdr
        while cur_hdr_type not in L4_PROTO:
            (next_hdr_type, hdr_len, ext_no) = \
                struct.unpack("!BBB", data.get(3))
            # Calculate correct hdr_len in bytes
            hdr_len = (hdr_len + 1) * ExtensionHeader.LINE_LEN
            logging.info("Found extension hdr of type (%d, %d) with len %db",
                         cur_hdr_type, ext_no, hdr_len)
            hdr_data = data.pop(hdr_len)
            if (cur_hdr_type, ext_no) in EXTENSIONS:
                constr = EXTENSIONS[(cur_hdr_type, ext_no)]
                self.extension_hdrs.append(constr(hdr_data))
            else:
                # TODO(PSz): fail here?
                logging.warning("Extension (%d, %d) unsupported." %
                                (cur_hdr_type, ext_no))
            cur_hdr_type = next_hdr_type
        self.l4_proto = cur_hdr_type

    def pack(self):
        """
        Packs the header and returns a byte array.
        """
        data = []
        data.append(self.common_hdr.pack())
        data.append(self.src_addr.pack())
        data.append(self.dst_addr.pack())
        if self._path is not None:
            data.append(self._path.pack())
        # Pack extensions
        for ext_hdr in self.extension_hdrs:
            data.append(ext_hdr.pack())
        return b"".join(data)

    def get_iof(self):
        """
        Get the current :any:`InfoOpaqueField`.
        """
        return self._path.get_of(self.common_hdr.curr_iof_idx)

    def set_iof_idx_rel(self, n):
        """
        Set the current :any:`InfoOpaqueField` relative to the current
        OF pointer.

        :param int n: Offset from the current OF.
        """
        self.common_hdr.curr_iof_idx = self.common_hdr.curr_of_idx + n
        if self.common_hdr.curr_iof_idx < 0:
            raise SCIONIndexError("IOF index set to negative value (%d)" %
                                  self.common_hdr.curr_iof_idx)
        max_ = self._path.of_count()
        if self.common_hdr.curr_iof_idx >= max_:
            logging.warning("Current IOF index (%d) is beyond "
                            "the max index (%d)",
                            self.common_hdr.curr_iof_idx, max_)

    def get_of_rel(self, relative=0):
        """
        Get an :any:`OpaqueField` relative to the current OF pointer.

        :param int relative: Offset from the current OF.
        """
        return self._path.get_of(self.common_hdr.curr_of_idx + relative)

    def inc_of_idx(self, n):
        """
        Increment the current OF pointer by `n`.

        :param int n: The amount to increment by.
        """
        self.common_hdr.curr_of_idx += n
        if self.common_hdr.curr_of_idx < 0:
            raise SCIONIndexError("OF index set to negative value (%d)" %
                                  self.common_hdr.curr_of_idx)
        max_ = self._path.of_count()
        if self.common_hdr.curr_of_idx >= max_:
            logging.warning("Current OF index (%d) is beyond "
                            "the max index (%d)",
                            self.common_hdr.curr_of_idx, max_)

    def set_downpath(self):  # FIXME probably not needed
        """
        Sets down path flag.
        """
        iof = self.get_iof()
        if iof is not None:
            iof.up_flag = False

    def is_on_up_path(self):
        """
        Returns 'True' if the current opaque field should be interpreted as an
        up-path opaque field and 'False' otherwise.

        Currently this is indicated by a bit in the LSB of the 'type' field in
        the common header.
        """
        iof = self.get_iof()
        if iof is not None:
            return iof.up_flag
        else:
            return True  # FIXME for now True for EmptyPath.

    def is_last_path_of(self):
        """
        Return ``True`` if the current opaque field is the last opaque field,
        ``False`` otherwise.
        """
        return self.common_hdr.curr_of_idx == self._path.of_count() - 1

    def reverse(self):
        """
        Reverses the header.
        """
        (self.src_addr, self.dst_addr) = (self.dst_addr, self.src_addr)
        self._path.reverse()
        self.set_first_of_pointers()

    def set_first_of_pointers(self):
        """
        Sets pointers of current info and hop opaque fields to initial values.
        """
        if self._path:
            self.common_hdr.curr_iof_idx = self._path.get_first_iof_idx()
            self.common_hdr.curr_of_idx = self._path.get_first_hof_idx()
            logging.debug(
                "curr_iof_idx: %d curr_of_idx: %d",
                self.common_hdr.curr_iof_idx, self.common_hdr.curr_of_idx)

    def __len__(self):
        length = self.common_hdr.hdr_len
        for ext_hdr in self.extension_hdrs:
            length += len(ext_hdr)
        return length

    def __str__(self):
        sh_list = []
        sh_list.append(str(self.common_hdr))
        sh_list.append("%s >> %s" % (self.src_addr, self.dst_addr))
        sh_list.append(str(self._path))
        for ext_hdr in self.extension_hdrs:
            sh_list.append(str(ext_hdr))
        return "\n".join(sh_list)


class SCIONPacket(PacketBase):
    """
    Class for creating and manipulation SCION packets.
    """
    MIN_LEN = 8

    def __init__(self, raw=None):
        """
        Initialize an instance of the class SCIONPacket.

        :param raw:
        :type raw:
        """
        super().__init__()
        self.payload_len = 0
        if raw is not None:
            self.parse(raw)

    @classmethod
    def from_values(cls, src, dst, payload, path=None,
                    ext_hdrs=None, next_hdr=1, pkt_type=PacketType.DATA):
        """
        Returns a SCIONPacket with the values specified.

        :param src: Source address (must be a 'SCIONAddr' object)
        :param dst: Destination address (must be a 'SCIONAddr' object)
        :param payload: Payload of the packet (either 'bytes' or 'PacketBase')
        :param path: The path for this packet.
        :param ext_hdrs: A list of extension headers.
        :param next_hdr: If 'ext_hdrs' is not None then this must be the type
                         of the first extension header in the list.
        :param pkt_type: The type of the packet.
        """
        pkt = SCIONPacket()
        pkt.hdr = SCIONHeader.from_values(src, dst, path, ext_hdrs, next_hdr)
        pkt.set_payload(payload)
        return pkt

    def set_payload(self, payload):
        PacketBase.set_payload(self, payload)
        # Update payload_len and total len of the packet.
        self.hdr.common_hdr.total_len -= self.payload_len
        self.payload_len = len(payload)
        self.hdr.common_hdr.total_len += self.payload_len

    def parse(self, raw):
        """
        Parses the raw data and populates the fields accordingly.
        """
        self.raw = raw
        data = Raw(raw, "SCIONPacket", self.MIN_LEN, min_=True)
        self.hdr = SCIONHeader(data.get())
        data.pop(len(self.hdr))
        self.payload_len = len(data)
        self.set_payload(data.pop(self.payload_len))
        self.parsed = True

    def pack(self):
        """
        Packs the header and the payload and returns a byte array.
        """
        data = []
        data.append(self.hdr.pack())
        if isinstance(self._payload, PacketBase):
            data.append(self._payload.pack())
        else:
            data.append(self._payload)

        return b"".join(data)


class IFIDPacket(SCIONPacket):
    """
    IFID packet.
    """
    def __init__(self, raw=None):
        """
        Initialize an instance of the class IFIDPacket.

        :param raw:
        :type raw:
        """
        SCIONPacket.__init__(self)
        self.reply_id = 0  # Always 0 for initial request.
        self.request_id = None
        if raw:
            self.parse(raw)

    def parse(self, raw):
        SCIONPacket.parse(self, raw)
        self.reply_id, self.request_id = struct.unpack("!HH", self._payload)

    @classmethod
    def from_values(cls, src, dst_isd_ad, request_id):
        """
        Returns a IFIDPacket with the values specified.

        @param src: Source address (must be a 'SCIONAddr' object)
        @param dst_isd_ad: Destination's 'ISD_AD' namedtuple.
        @param request_id: interface number of src (neighboring router).
        """
        req = IFIDPacket()
        req.request_id = request_id
        dst = SCIONAddr.from_values(dst_isd_ad.isd, dst_isd_ad.ad,
                                    PacketType.IFID_PKT)
        req.hdr = SCIONHeader.from_values(src, dst)
        req.set_payload(struct.pack("!HH", req.reply_id, request_id))
        return req

    def pack(self):
        self.set_payload(struct.pack("!HH", self.reply_id, self.request_id))
        return SCIONPacket.pack(self)


class CertChainRequest(SCIONPacket):
    """
    Certificate Chain Request packet.

    :ivar ingress_if: ingress interface where the beacon comes from.
    :type ingress_if: int
    :ivar src_isd: ISD identifier of the requester.
    :type src_isd: int
    :ivar src_ad: AD identifier of the requester.
    :type src_ad: int
    :ivar isd_id: Target certificate chain's ISD identifier.
    :type isd_id: int
    :ivar ad_id, ad: Target certificate chain's AD identifier.
    :type ad_id: int
    :ivar version: Target certificate chain's version.
    :type version: int
    """
    LEN = 2 + ISD_AD.LEN * 2 + 4

    def __init__(self, raw=None):
        """
        Initialize an instance of the class CertChainRequest.

        :param raw: packed packet.
        :type raw: bytes
        """
        SCIONPacket.__init__(self)
        self.ingress_if = 0
        self.src_isd = 0
        self.src_ad = 0
        self.isd_id = 0
        self.ad_id = 0
        self.version = 0
        if raw:
            self.parse(raw)

    def parse(self, raw):
        """
        Parse a string of bytes and populate the instance variables.

        :param raw: packed packet.
        :type raw: bytes
        """
        SCIONPacket.parse(self, raw)
        data = Raw(self._payload, "CertChainRequest", self.LEN)
        self.ingress_if = struct.unpack("!H", data.pop(2))[0]
        self.src_isd, self.src_ad = ISD_AD.from_raw(data.pop(ISD_AD.LEN))
        self.isd_id, self.ad_id = ISD_AD.from_raw(data.pop(ISD_AD.LEN))
        self.version = struct.unpack("!I", data.pop(4))[0]

    @classmethod
    def from_values(cls, req_type, src, ingress_if, src_isd, src_ad, isd_id,
                    ad_id, version):
        """
        Return a Certificate Chain Request with the values specified.

        :param req_type: Either CERT_CHAIN_REQ_LOCAL (request comes from BS or
                         user) or CERT_CHAIN_REQ.
        :type req_type: int
        :param src: Source address.
        :type src: :class:`SCIONAddr`
        :param ingress_if: ingress interface where the beacon comes from.
        :type ingress_if: int
        :param src_isd: ISD identifier of the requester.
        :type src_isd: int
        :param src_ad: AD identifier of the requester.
        :type src_ad: int
        :param isd_id: Target certificate chain's ISD identifier.
        :type isd_id: int
        :param ad_id, ad: Target certificate chain's AD identifier.
        :type ad_id: int
        :param version: Target certificate chain's version.
        :type version: int
        :returns: the newly created CertChainRequest instance.
        :rtype: :class:`CertChainRequest`
        """
        req = CertChainRequest()
        dst = SCIONAddr.from_values(isd_id, src_ad, req_type)
        req.hdr = SCIONHeader.from_values(src, dst)
        req.ingress_if = ingress_if
        req.src_isd = src_isd
        req.src_ad = src_ad
        req.isd_id = isd_id
        req.ad_id = ad_id
        req.version = version
        req.set_payload(
            struct.pack("!H", ingress_if) + ISD_AD(src_isd, src_ad).pack() +
            ISD_AD(isd_id, ad_id).pack() + struct.pack("!I", version))
        return req


class CertChainReply(SCIONPacket):
    """
    Certificate Chain Reply packet.

    :cvar MIN_LEN: minimum length of the packet.
    :type MIN_LEN: int
    :ivar isd_id: Target certificate chain's ISD identifier.
    :type isd_id: int
    :ivar ad_id: Target certificate chain's AD identifier.
    :type ad_id: int
    :ivar version: Target certificate chain's version.
    :type version: int
    :ivar cert_chain: requested certificate chain's content.
    :type cert_chain: bytes
    """
    MIN_LEN = ISD_AD.LEN + 4

    def __init__(self, raw=None):
        """
        Initialize an instance of the class CertChainReply.

        :param raw: packed packet.
        :type raw: bytes
        """
        SCIONPacket.__init__(self)
        self.isd_id = 0
        self.ad_id = 0
        self.version = 0
        self.cert_chain = b''
        if raw:
            self.parse(raw)

    def parse(self, raw):
        """
        Parse a string of bytes and populate the instance variables.

        :param raw: packed packet.
        :type raw: bytes
        """
        SCIONPacket.parse(self, raw)
        data = Raw(self._payload, "CertChainReply", self.MIN_LEN, min_=True)
        self.isd_id, self.ad_id = ISD_AD.from_raw(data.pop(ISD_AD.LEN))
        self.version = struct.unpack("!I", data.pop(4))[0]
        self.cert_chain = data.pop()

    @classmethod
    def from_values(cls, dst, isd_id, ad_id, version, cert_chain):
        """
        Return a Certificate Chain Reply with the values specified.

        :param dst: Destination address.
        :type dst: :class:`SCIONAddr`
        :param isd_id: Target certificate chain's ISD identifier.
        :type isd_id: int
        :param ad_id, ad: Target certificate chain's AD identifier.
        :type ad_id: int
        :param version: Target certificate chain's version.
        :type version: int
        :param cert_chain: requested certificate chain's content.
        :type cert_chain: bytes
        :returns: the newly created CertChainReply instance.
        :rtype: :class:`CertChainReply`
        """
        rep = CertChainReply()
        src = SCIONAddr.from_values(isd_id, ad_id, PacketType.CERT_CHAIN_REP)
        rep.hdr = SCIONHeader.from_values(src, dst)
        rep.isd_id = isd_id
        rep.ad_id = ad_id
        rep.version = version
        rep.cert_chain = cert_chain
        rep.set_payload(ISD_AD(isd_id, ad_id).pack() +
                        struct.pack("!I", version) + cert_chain)
        return rep


class TRCRequest(SCIONPacket):
    """
    TRC Request packet.

    :ivar ingress_if: ingress interface where the beacon comes from.
    :type ingress_if: int
    :ivar src_isd: ISD identifier of the requester.
    :type src_isd: int
    :ivar src_ad: AD identifier of the requester.
    :type src_ad: int
    :ivar isd_id: Target TRC's ISD identifier.
    :type isd_id: int
    :ivar version: Target TRC's version.
    :type version: int
    """
    LEN = 2 + ISD_AD.LEN + 2 + 4

    def __init__(self, raw=None):
        """
        Initialize an instance of the class TRCRequest.

        :param raw: packed packet.
        :type raw: bytes
        """
        SCIONPacket.__init__(self)
        self.ingress_if = 0
        self.src_isd = 0
        self.src_ad = 0
        self.isd_id = 0
        self.version = 0
        if raw:
            self.parse(raw)

    def parse(self, raw):
        """
        Parse a string of bytes and populate the instance variables.

        :param raw: packed packet.
        :type raw: bytes
        """
        SCIONPacket.parse(self, raw)
        data = Raw(self._payload, "TRCRequest", self.LEN)
        self.ingress_if = struct.unpack("!H", data.pop(2))[0]
        self.src_isd, self.src_ad = ISD_AD.from_raw(data.pop(ISD_AD.LEN))
        self.isd_id = struct.unpack("!H", data.pop(2))[0]
        self.version = struct.unpack("!I", data.pop(4))[0]

    @classmethod
    def from_values(cls, req_type, src, ingress_if, src_isd, src_ad, isd_id,
                    version):
        """
        Return a TRC Request with the values specified.

        :param req_type: Either TRC_REQ_LOCAL (request comes from BS or user)
                         or TRC_REQ.
        :type req_type: int
        :param src: Source address.
        :type src: :class:`SCIONAddr`
        :param ingress_if: ingress interface where the beacon comes from.
        :type ingress_if: int
        :param src_isd: ISD identifier of the requester.
        :type src_isd: int
        :param src_ad: AD identifier of the requester.
        :type src_ad: int
        :param isd_id: Target TRC's ISD identifier.
        :type isd_id: int
        :param version: Target TRC's version.
        :type version: int
        :returns: the newly created TRCRequest instance.
        :rtype: :class:`TRCRequest`
        """
        req = TRCRequest()
        dst = SCIONAddr.from_values(isd_id, src_ad, req_type)
        req.hdr = SCIONHeader.from_values(src, dst)
        req.ingress_if = ingress_if
        req.src_isd = src_isd
        req.src_ad = src_ad
        req.isd_id = isd_id
        req.version = version
        req.set_payload(struct.pack("!H", ingress_if) +
                        ISD_AD(src_isd, src_ad).pack() +
                        struct.pack("!HI", isd_id, version))
        return req


class TRCReply(SCIONPacket):
    """
    TRC Reply packet.

    :cvar MIN_LEN: minimum length of the packet.
    :type MIN_LEN: int
    :ivar isd_id: Target TRC's ISD identifier.
    :type isd_id: int
    :ivar version: Target TRC's version.
    :type version: int
    :ivar trc: requested TRC's content.
    :type trc: bytes
    """
    MIN_LEN = 6

    def __init__(self, raw=None):
        """
        Initialize an instance of the class TRCReply.

        :param raw: packed packet.
        :type raw: bytes
        """
        SCIONPacket.__init__(self)
        self.isd_id = 0
        self.version = 0
        self.trc = b''
        if raw:
            self.parse(raw)

    def parse(self, raw):
        """
        Parse a string of bytes and populate the instance variables.

        :param raw: packed packet.
        :type raw: bytes
        """
        SCIONPacket.parse(self, raw)
        data = Raw(self._payload, "TRCReply", self.MIN_LEN, min_=True)
        self.isd_id, self.version = struct.unpack("!HI", data.pop(self.MIN_LEN))
        self.trc = data.pop()

    @classmethod
    def from_values(cls, dst, isd_id, version, trc):
        """
        Return a TRC Reply with the values specified.

        :param dst: Destination address.
        :type dst: :class:`SCIONAddr`
        :param isd_id: Target TRC's ISD identifier.
        :type isd_id: int
        :param version: Target TRC's version.
        :type version: int
        :param trc: requested TRC's content.
        :type trc: bytes
        :returns: the newly created TRCReply instance.
        :rtype: :class:`TRCReply`
        """
        rep = TRCReply()
        # TODO: revise TRC/Cert request/replies
        src = SCIONAddr.from_values(dst.isd_id, dst.ad_id, PacketType.TRC_REP)
        rep.hdr = SCIONHeader.from_values(src, dst)
        rep.isd_id = isd_id
        rep.version = version
        rep.trc = trc
        rep.set_payload(struct.pack("!HI", isd_id, version) + trc)
        return rep
