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
from ipaddress import IPv4Address

# SCION
from lib.packet.ext_hdr import ExtensionHeader, ICNExtHdr
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


class PacketType(object):
    """
    Defines constants for the SCION packet types.
    """
    DATA = -1  # Data packet
    # Path Construction Beacon
    BEACON = IPv4Address("10.224.0.1")
    # Path management packet from/to PS
    PATH_MGMT = IPv4Address("10.224.0.2")
    # TRC file request to parent AD
    TRC_REQ = IPv4Address("10.224.0.3")
    # TRC file request to lCS
    TRC_REQ_LOCAL = IPv4Address("10.224.0.4")
    # TRC file reply from parent AD
    TRC_REP = IPv4Address("10.224.0.5")
    # cert chain request to parent AD
    CERT_CHAIN_REQ = IPv4Address("10.224.0.6")
    # local cert chain request
    CERT_CHAIN_REQ_LOCAL = IPv4Address("10.224.0.7")
    # cert chain reply from lCS
    CERT_CHAIN_REP = IPv4Address("10.224.0.8")
    # IF ID packet to the peer router
    IFID_PKT = IPv4Address("10.224.0.9")
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
        HeaderBase.__init__(self)
        self.version = 0  # Version of SCION packet.
        self.src_addr_len = 0  # Length of the src address.
        self.dst_addr_len = 0  # Length of the dst address.
        self.total_len = 0  # Total length of the packet.
        self.curr_iof_p = 0  # Pointer inside the packet to the current IOF.
        self.curr_of_p = 0  # Pointer to the current opaque field.
        self.next_hdr = 0  # Type of the next hdr field (IP protocol numbers).
        self.hdr_len = 0  # Header length including the path.

        if raw is not None:
            self.parse(raw)

    @classmethod
    def from_values(cls, src_addr_len, dst_addr_len, next_hdr):
        """
        Returns a SCIONCommonHdr with the values specified.
        """
        chdr = SCIONCommonHdr()
        chdr.src_addr_len = src_addr_len
        chdr.dst_addr_len = dst_addr_len
        chdr.next_hdr = next_hdr
        chdr.curr_of_p = chdr.src_addr_len + chdr.dst_addr_len
        chdr.curr_iof_p = chdr.curr_of_p
        chdr.hdr_len = SCIONCommonHdr.LEN + src_addr_len + dst_addr_len
        chdr.total_len = chdr.hdr_len

        return chdr

    def parse(self, raw):
        """
        Parses the raw data and populates the fields accordingly.
        """
        assert isinstance(raw, bytes)
        dlen = len(raw)
        if dlen < self.LEN:
            logging.warning("Data too short to parse SCION common header: "
                            "data len %u", dlen)
            return
        (types, self.total_len, self.curr_iof_p, self.curr_of_p,
         self.next_hdr, self.hdr_len) = struct.unpack("!HHBBBB", raw)
        self.version = (types & 0xf000) >> 12
        self.src_addr_len = (types & 0x0fc0) >> 6
        self.dst_addr_len = types & 0x003f
        self.parsed = True
        return

    def pack(self):
        """
        Returns the common header as 8 byte binary string.
        """
        types = ((self.version << 12) | (self.src_addr_len << 6) |
                 self.dst_addr_len)
        return struct.pack("!HHBBBB", types, self.total_len,
                           self.curr_iof_p, self.curr_of_p,
                           self.next_hdr, self.hdr_len)

    def __str__(self):
        res = ("[CH ver: %u, src len: %u, dst len: %u, total len: %u bytes, "
               "TS: %u, current OF: %u, next hdr: %u, hdr len: %u]") % (
                   self.version, self.src_addr_len, self.dst_addr_len,
                   self.total_len, self.curr_iof_p, self.curr_of_p,
                   self.next_hdr, self.hdr_len)
        return res


class SCIONHeader(HeaderBase):
    """
    The SCION packet header.
    """

    MIN_LEN = 16  # Update when values are fixed.

    def __init__(self, raw=None):
        """
        Initialize an instance of the class SCIONHeader.

        :param raw:
        :type raw:
        """
        HeaderBase.__init__(self)
        self.common_hdr = None
        self.src_addr = None
        self.dst_addr = None
        self._path = None
        self._extension_hdrs = []

        if raw is not None:
            self.parse(raw)

    @classmethod
    def from_values(cls, src, dst, path=None, ext_hdrs=None, next_hdr=0):
        """
        Returns a SCIONHeader with the values specified.
        """
        assert isinstance(src, SCIONAddr)
        assert isinstance(dst, SCIONAddr)
        assert path is None or isinstance(path, PathBase)
        if ext_hdrs is None:
            ext_hdrs = []
        hdr = SCIONHeader()
        hdr.common_hdr = SCIONCommonHdr.from_values(src.addr_len, dst.addr_len,
                                                    next_hdr)
        hdr.src_addr = src
        hdr.dst_addr = dst
        hdr.path = path
        hdr.extension_hdrs = ext_hdrs

        return hdr

    @property
    def path(self):
        """
        Returns the path in the header.
        """
        return self._path

    @path.setter
    def path(self, path):
        """
        Sets path to 'path'.
        """
        self.set_path(path)

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

    @property
    def extension_hdrs(self):
        """
        Returns the extension headers.
        """
        return self._extension_hdrs

    @extension_hdrs.setter
    def extension_hdrs(self, ext_hdrs):
        """
        Sets extension headers.
        """
        self.set_ext_hdrs(ext_hdrs)

    def set_ext_hdrs(self, ext_hdrs):
        """
        Sets extension headers and updates necessary fields.
        """
        assert isinstance(ext_hdrs, list)
        while self._extension_hdrs:
            self.pop_ext_hdr()
        for ext_hdr in ext_hdrs:
            self.append_ext_hdr(ext_hdr)

    def append_ext_hdr(self, ext_hdr):
        """
        Appends an extension header and updates necessary fields.
        """
        assert isinstance(ext_hdr, ExtensionHeader)
        self._extension_hdrs.append(ext_hdr)
        self.common_hdr.total_len += len(ext_hdr)

    def pop_ext_hdr(self):
        """
        Pops and returns the last extension header and updates necessary fields.
        """
        if not self._extension_hdrs:
            return
        ext_hdr = self._extension_hdrs.pop()
        self.common_hdr.total_len -= len(ext_hdr)
        return ext_hdr

    def parse(self, raw):
        """
        Parses the raw data and populates the fields accordingly.
        """
        assert isinstance(raw, bytes)
        dlen = len(raw)
        if dlen < SCIONHeader.MIN_LEN:
            logging.warning("Data too short to parse SCION header: "
                            "data len %u", dlen)
            return
        offset = self._parse_common_hdr(raw, 0)
        # Parse opaque fields.
        offset = self._parse_opaque_fields(raw, offset)
        # Parse extensions headers.
        offset = self._parse_extension_hdrs(raw, offset)
        self.parsed = True
        return offset

    def _parse_common_hdr(self, raw, offset):
        """
        Parses the raw data and populates the common header fields accordingly.
        :return: offset in the raw data till which it has been parsed
        """
        self.common_hdr = \
            SCIONCommonHdr(raw[offset:offset + SCIONCommonHdr.LEN])
        assert self.common_hdr.parsed
        offset += SCIONCommonHdr.LEN
        # Create appropriate SCIONAddr objects.
        src_addr_len = self.common_hdr.src_addr_len
        self.src_addr = SCIONAddr(raw[offset:offset + src_addr_len])
        offset += src_addr_len
        dst_addr_len = self.common_hdr.dst_addr_len
        self.dst_addr = SCIONAddr(raw[offset:offset + dst_addr_len])
        offset += dst_addr_len
        return offset

    def _parse_opaque_fields(self, raw, offset):
        """
        Parses the raw data to opaque fields and populates the path field
        accordingly.
        :return: offset in the raw data till which it has been parsed
        """
        # PSz: UpPath-only case missing, quick fix:
        if offset == self.common_hdr.hdr_len:
            self._path = EmptyPath()
        else:
            info = InfoOpaqueField(raw[offset:offset + InfoOpaqueField.LEN])
            if info.info == OFT.TDC_XOVR:
                self._path = CorePath(raw[offset:self.common_hdr.hdr_len])
            elif info.info == OFT.NON_TDC_XOVR:
                self._path = CrossOverPath(raw[offset:self.common_hdr.hdr_len])
            elif info.info == OFT.INTRATD_PEER or info.info == OFT.INTERTD_PEER:
                self._path = PeerPath(raw[offset:self.common_hdr.hdr_len])
            else:
                logging.info("Can not parse path in packet: Unknown type %x",
                             info.info)
        return self.common_hdr.hdr_len

    def _parse_extension_hdrs(self, raw, offset):
        """
        Parses the raw data and populates the extension header fields
        accordingly.
        :return: offset in the raw data till which it has been parsed
        """
        # FIXME: The last extension header should be a layer 4 protocol header.
        # At the moment this is not support and we just indicate the end of the
        # extension headers by a 0 in the type field.
        cur_hdr_type = self.common_hdr.next_hdr
        while cur_hdr_type != 0:
            (next_hdr_type, hdr_len) = \
                struct.unpack("!BB", raw[offset:offset + 2])
            logging.info("Found extension hdr of type %u with len %u",
                         cur_hdr_type, hdr_len)
            if cur_hdr_type == ICNExtHdr.TYPE:
                self.extension_hdrs.append(
                    ICNExtHdr(raw[offset:offset + hdr_len]))
            else:
                self.extension_hdrs.append(
                    ExtensionHeader(raw[offset:offset + hdr_len]))
            cur_hdr_type = next_hdr_type
            offset += hdr_len
        return offset

    def pack(self):
        """
        Packs the header and returns a byte array.
        """
        data = []
        data.append(self.common_hdr.pack())
        data.append(self.src_addr.pack())
        data.append(self.dst_addr.pack())
        if self.path is not None:
            data.append(self.path.pack())
        for ext_hdr in self.extension_hdrs:
            data.append(ext_hdr.pack())
        return b"".join(data)

    def get_current_of(self):
        """
        Returns the current opaque field as pointed by the current_of field in
        the common_hdr.
        """
        if self.path is None:
            return None
        offset = (self.common_hdr.curr_of_p - (self.common_hdr.src_addr_len +
                  self.common_hdr.dst_addr_len))
        return self.path.get_of(offset // OpaqueField.LEN)

    def get_current_iof(self):
        """
        Returns the Info Opaque Field as pointed by the current_iof_p field in
        the common_hdr.
        """
        if self.path is None:
            return None
        offset = (self.common_hdr.curr_iof_p -
                  (self.common_hdr.src_addr_len + self.common_hdr.dst_addr_len))
        return self.path.get_of(offset // OpaqueField.LEN)

    def get_relative_of(self, n):
        """
        Returns (number_of_current_of + n)th opaque field. n may be negative.
        """
        if self.path is None:
            return None
        offset = (self.common_hdr.curr_of_p - (self.common_hdr.src_addr_len +
                  self.common_hdr.dst_addr_len))
        return self.path.get_of(offset // OpaqueField.LEN + n)

    def get_next_of(self):
        """
        Returns the opaque field after the one pointed by the current_of field
        in the common hdr or 'None' if there exists no next opaque field.
        """
        if self.path is None:
            return None
        offset = (self.common_hdr.curr_of_p - (self.common_hdr.src_addr_len +
                  self.common_hdr.dst_addr_len))
        return self.path.get_of(offset // OpaqueField.LEN + 1)

    def increase_of(self, number):
        """
        Increases pointer of current opaque field by number of opaque fields.
        """
        self.common_hdr.curr_of_p += number * OpaqueField.LEN

    def set_downpath(self):  # FIXME probably not needed
        """
        Sets down path flag.
        """
        iof = self.get_current_iof()
        if iof is not None:
            iof.up_flag = False

    def is_on_up_path(self):
        """
        Returns 'True' if the current opaque field should be interpreted as an
        up-path opaque field and 'False' otherwise.

        Currently this is indicated by a bit in the LSB of the 'type' field in
        the common header.
        """
        iof = self.get_current_iof()
        if iof is not None:
            return iof.up_flag
        else:
            return True  # FIXME for now True for EmptyPath.

    def is_last_path_of(self):
        """
        Returs 'True' if the current opaque field is the last opaque field,
        'False' otherwise.
        """
        offset = (SCIONCommonHdr.LEN + OpaqueField.LEN)
        return self.common_hdr.curr_of_p + offset == self.common_hdr.hdr_len

    def reverse(self):
        """
        Reverses the header.
        """
        (self.src_addr, self.dst_addr) = (self.dst_addr, self.src_addr)
        self.path.reverse()
        self.set_first_of_pointers()

    def set_first_of_pointers(self):
        """
        Sets pointers of current info and hop opaque fields to initial values.
        """
        tmp = self.common_hdr.src_addr_len + self.common_hdr.dst_addr_len
        if self.path:
            self.common_hdr.curr_of_p = tmp + self.path.get_first_hop_offset()
            self.common_hdr.curr_iof_p = tmp + self.path.get_first_info_offset()

    def __len__(self):
        length = self.common_hdr.hdr_len
        for ext_hdr in self.extension_hdrs:
            length += len(ext_hdr)
        return length

    def __str__(self):
        sh_list = []
        sh_list.append(str(self.common_hdr) + "\n")
        sh_list.append(str(self.src_addr) + " >> " + str(self.dst_addr) + "\n")
        sh_list.append(str(self.path) + "\n")
        for ext_hdr in self.extension_hdrs:
            sh_list.append(str(ext_hdr) + "\n")
        return "".join(sh_list)


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
        PacketBase.__init__(self)
        self.payload_len = 0
        if raw is not None:
            self.parse(raw)

    @classmethod
    def from_values(cls, src, dst, payload, path=None,
                    ext_hdrs=None, next_hdr=0, pkt_type=PacketType.DATA):
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
        pkt.payload = payload
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
        assert isinstance(raw, bytes)
        dlen = len(raw)
        self.raw = raw
        if dlen < SCIONPacket.MIN_LEN:
            logging.warning("Data too short to parse SCION packet: "
                            "data len %u", dlen)
            return
        self.hdr = SCIONHeader(raw)
        hdr_len = len(self.hdr)
        self.payload_len = dlen - hdr_len
        self.payload = raw[len(self.hdr):]
        self.parsed = True

    def pack(self):
        """
        Packs the header and the payload and returns a byte array.
        """
        data = []
        data.append(self.hdr.pack())
        if isinstance(self.payload, PacketBase):
            data.append(self.payload.pack())
        else:
            data.append(self.payload)

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
        self.reply_id, self.request_id = struct.unpack("!HH", self.payload)

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
        req.payload = struct.pack("!HH", req.reply_id, request_id)
        return req

    def pack(self):
        self.payload = struct.pack("!HH", self.reply_id, self.request_id)
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
        raw = self.payload
        (self.ingress_if, ) = struct.unpack("!H", raw[:2])
        raw = raw[2:]
        (self.src_isd, self.src_ad) = ISD_AD.from_raw(raw[:ISD_AD.LEN])
        raw = raw[ISD_AD.LEN:]
        (self.isd_id, self.ad_id) = ISD_AD.from_raw(raw[:ISD_AD.LEN])
        raw = raw[ISD_AD.LEN:]
        (self.version, ) = struct.unpack("!I", raw)

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
        req.payload = (struct.pack("!H", ingress_if) +
                       ISD_AD(src_isd, src_ad).pack() +
                       ISD_AD(isd_id, ad_id).pack() +
                       struct.pack("!I", version))
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
        (self.isd_id, self.ad_id) = ISD_AD.from_raw(self.payload[:ISD_AD.LEN])
        (self.version, ) = \
            struct.unpack("!I", self.payload[ISD_AD.LEN:ISD_AD.LEN + 4])
        self.cert_chain = self.payload[self.MIN_LEN:]

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
        rep.payload = (ISD_AD(isd_id, ad_id).pack() +
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
        raw = self.payload
        (self.ingress_if, ) = struct.unpack("!H", raw[:2])
        raw = raw[2:]
        (self.src_isd, self.src_ad) = ISD_AD.from_raw(raw[:ISD_AD.LEN])
        raw = raw[ISD_AD.LEN:]
        (self.isd_id, ) = struct.unpack("!H", raw[:2])
        raw = raw[2:]
        (self.version, ) = struct.unpack("!I", raw[:4])

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
        req.payload = (struct.pack("!H", ingress_if) +
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
        (self.isd_id, self.version) = \
            struct.unpack("!HI", self.payload[:self.MIN_LEN])
        self.trc = self.payload[self.MIN_LEN:]

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
        rep.payload = struct.pack("!HI", isd_id, version) + trc
        return rep
