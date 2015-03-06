"""
scion.py

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

from lib.packet.ext_hdr import ExtensionHeader, ICNExtHdr
from lib.packet.host_addr import (AddressLengths, IPv4HostAddr,
                                  IPv6HostAddr, SCIONHostAddr, HostAddr)
from lib.packet.opaque_field import InfoOpaqueField, OpaqueField
from lib.packet.packet_base import HeaderBase, PacketBase
from lib.packet.path import PathType, CorePath, PeerPath, CrossOverPath, \
    EmptyPath, PathBase
import struct, logging, bitstring
from bitstring import BitArray


class PacketType(object):
    """
    Defines constants for the SCION packet types.
    """
    DATA = 0  # data packet
    AID_REQ = 1  # Address request to local elements (from SCIONSwitch)
    AID_REP = 2  # AID reply to switch
    TO_LOCAL_ADDR = 100  # Threshold to distinguish local control packets
    BEACON = 101  # PathSegment type
    CERT_REQ_LOCAL = 102  # local certificate request (to certificate server)
    CERT_REP_LOCAL = 103  # local certificate reply (from certificate server)
    CERT_REQ = 104  # Certificate Request to parent AD
    CERT_REP = 105  # Certificate Reply from parent AD
    PATH_REQ = 108  # Path request to TDC/lPS
    PATH_REC = 109  # Path record (downpath reg. reply from TDC/lPS)
    ROT_REQ_LOCAL = 112  # ROT file reply to local certificate server
    ROT_REP_LOCAL = 113  # ROT file reply from local certificate server
    OFG_KEY_REQ = 114  # opaque field generation key request to CS
    OFG_KEY_REP = 115  # opaque field generation key reply from CS
    IFID_REQ = 116  # IF ID request to the peer router (of the neighbor AD)
    IFID_REP = 117  # IF ID reply from the peer router
    ROT_REQ = 118  # Root of Trust file request to parent AD
    ROT_REP = 119  # Root of Trust file reply from parent AD


class SignatureType(object):
    """
    Defines constants for the possible sizes of signatures.
    """
    SIZE_128 = 0
    SIZE_256 = 1
    SIZE_384 = 2


class IDSize(object):
    """
    Defines constants for the lengths of AIDs and TIDs.
    """
    SIZE_TID = 4
    SIZE_AID = 8

TYPES_SRC = {
        PacketType.BEACON: 16834570,
        PacketType.CERT_REP: 33611786,
        PacketType.PATH_REC: 67166218,
        PacketType.ROT_REP_LOCAL:100720650,
        PacketType.OFG_KEY_REP: 117497866,
        PacketType.ROT_REP: 134275082,
        PacketType.CERT_REP_LOCAL:151052298,
        PacketType.IFID_REP: 167829514,
        }
TYPES_SRC_INV = {v: k for k, v in TYPES_SRC.items()}
TYPES_DST = {
        PacketType.CERT_REQ: 33611786,
        PacketType.PATH_REQ: 67166218,
        PacketType.ROT_REQ_LOCAL: 100720650,
        PacketType.OFG_KEY_REQ: 117497866,
        PacketType.ROT_REQ: 134275082,
        PacketType.CERT_REQ_LOCAL: 151052298,
        PacketType.IFID_REQ: 167829514,
    }
TYPES_DST_INV = {v: k for k, v in TYPES_DST.items()}

def get_addr_from_type(ptype):
    """
    TODO
    """
    if ptype in TYPES_SRC:
        return IPv4HostAddr(TYPES_SRC[ptype])
    else:
        return IPv4HostAddr(TYPES_DST[ptype])

def get_type(pkt):
    """
    returns type of the packet, used for dispatching
    """
    isrc_addr = pkt.hdr.src_addr.to_int(endianness='little')
    idst_addr = pkt.hdr.dst_addr.to_int(endianness='little')
    if isrc_addr in TYPES_SRC_INV:
        return TYPES_SRC_INV[isrc_addr]
    if idst_addr in TYPES_DST_INV:
        return TYPES_DST_INV[idst_addr]
    return PacketType.DATA


class SCIONCommonHdr(HeaderBase):
    """
    Encapsulates the common header for SCION packets.
    """

    LEN = 8

    def __init__(self, raw=None):
        HeaderBase.__init__(self)
        self.type = PacketType.DATA  # Type of the packet.
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
    def from_values(cls, pkt_type, src_addr_len, dst_addr_len, next_hdr):
        """
        Returns a SCIONCommonHdr with the values specified.
        """
        chdr = SCIONCommonHdr()
        chdr.type = pkt_type
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
        if dlen < SCIONCommonHdr.LEN:
            logging.warning("Data too short to parse SCION common header: "
                            "data len %u", dlen)
            return
        bits = BitArray(bytes=raw)
        (types, self.total_len, self.curr_iof_p, self.curr_of_p,
         self.next_hdr, self.hdr_len) = \
            bits.unpack("uintbe:16, uintbe:16, uintbe:8, "
                        "uintbe:8, uintbe:8, uintbe:8")
        self.type = (types & 0xf000) >> 12
        self.src_addr_len = (types & 0x0fc0) >> 6
        self.dst_addr_len = types & 0x003f
        self.parsed = True
        return

    def pack(self):
        """
        Returns the common header as 8 byte binary string.
        """
        types = (self.type << 12) | (self.dst_addr_len << 6) | self.src_addr_len
        return bitstring.pack("uintbe:16, uintbe:16, uintbe:8, "
                              "uintbe:8, uintbe:8, uintbe:8",
                              types, self.total_len, self.curr_iof_p,
                              self.curr_of_p, self.next_hdr,
                              self.hdr_len).bytes

    def __str__(self):
        res = ("[CH type: %u, src len: %u, dst len: %u, total len: %u bytes, "
               "TS: %u, current OF: %u, next hdr: %u, hdr len: %u]") % (
               self.type, self.src_addr_len, self.dst_addr_len, self.total_len,
               self.curr_iof_p, self.curr_of_p, self.next_hdr, self.hdr_len)
        return res


class SCIONHeader(HeaderBase):
    """
    The SCION packet header.
    """

    MIN_LEN = 16

    def __init__(self, raw=None):
        HeaderBase.__init__(self)
        self.common_hdr = None
        self.src_addr = None
        self.dst_addr = None
        self.path = None
        self.extension_hdrs = []

        if raw is not None:
            self.parse(raw)

    @classmethod
    def from_values(cls, src, dst, pkt_type, path=None,
                    ext_hdrs=None, next_hdr=0):
        """
        Returns a SCIONHeader with the values specified.
        """
        assert isinstance(src, HostAddr)
        assert isinstance(dst, HostAddr)
        assert path is None or isinstance(path, PathBase)
        if ext_hdrs is None:
            ext_hdrs = []
        hdr = SCIONHeader()
        hdr.src_addr = src
        hdr.dst_addr = dst
        hdr.path = path
        hdr.extension_hdrs = ext_hdrs
        hdr.common_hdr = SCIONCommonHdr.from_values(pkt_type, src.addr_len,
                                                    dst.addr_len, next_hdr)
        if path is not None:
            path_len = len(path.pack())
            hdr.common_hdr.hdr_len += path_len
            hdr.common_hdr.total_len += path_len
        for ext_hdr in ext_hdrs:
            hdr.common_hdr.total_len += len(ext_hdr)
        return hdr

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
        offset = 0
        self.common_hdr = \
            SCIONCommonHdr(raw[offset:offset + SCIONCommonHdr.LEN])
        offset += SCIONCommonHdr.LEN
        assert self.common_hdr.parsed
        # Create appropriate HostAddr objects.
        host_types = {AddressLengths.HOST_ADDR_IPV4: IPv4HostAddr,
                      AddressLengths.HOST_ADDR_IPV6: IPv6HostAddr,
                      AddressLengths.HOST_ADDR_SCION: SCIONHostAddr}
        src_addr_len = self.common_hdr.src_addr_len
        self.src_addr = \
            host_types[src_addr_len](raw[offset:offset + src_addr_len])
        offset += src_addr_len
        dst_addr_len = self.common_hdr.dst_addr_len
        self.dst_addr = \
            host_types[dst_addr_len](raw[offset:offset + dst_addr_len])
        offset += dst_addr_len
        # Parse opaque fields.
        # PSz: UpPath-only case missing, quick fix:
        if offset == self.common_hdr.hdr_len:
            info = InfoOpaqueField()
        else:
            info = InfoOpaqueField(raw[offset:offset + InfoOpaqueField.LEN])
        if info.info == PathType.CORE:
            self.path = CorePath(raw[offset:self.common_hdr.hdr_len])
        elif info.info == PathType.CROSS_OVER:
            self.path = CrossOverPath(raw[offset:self.common_hdr.hdr_len])
        elif info.info == PathType.PEER_LINK:
            self.path = PeerPath(raw[offset:self.common_hdr.hdr_len])
        elif info.info == PathType.EMPTY:
            self.path = EmptyPath()  # PSz raw[offset:self.common_hdr.hdr_len])
        else:
            logging.info("Can not parse path in packet: Unknown type %x",
                         info.info)
        offset = self.common_hdr.hdr_len
        # Parse extensions headers.
        # FIXME: The last extension header should be a layer 4 protocol header.
        # At the moment this is not support and we just indicate the end of the
        # extension headers by a 0 in the type field.
        cur_hdr_type = self.common_hdr.next_hdr
        while cur_hdr_type != 0:
            bits = BitArray(raw[offset: offset + 2])
            (next_hdr_type, hdr_len) = bits.unpack("uintbe:8, uintbe:8")
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
        self.parsed = True

    def pack(self):
        """
        Packs the header and returns a byte array.
        """
        data = []
        data.append(self.common_hdr.pack())
        data.append(self.src_addr.addr)
        data.append(self.dst_addr.addr)
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

    def set_downpath(self): #FIXME probably not needed
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
            True  # FIXME for now True for EmptyPath.

    def is_last_path_of(self):
        """
        Returs 'True' if the current opaque field is the last opaque field,
        'False' otherwise.
        """
        offset = (SCIONCommonHdr.LEN + self.common_hdr.src_addr_len +
                  self.common_hdr.dst_addr_len)
        return self.common_hdr.curr_of_p + offset == self.common_hdr.hdr_len

    def reverse(self):
        """
        Reverses the header.
        """
        (self.src_addr, self.dst_addr) = (self.dst_addr, self.src_addr)
        self.path.reverse()
        self.common_hdr.curr_of_p = (self.common_hdr.src_addr_len +
                                     self.common_hdr.dst_addr_len)
        self.common_hdr.curr_iof_p = self.common_hdr.curr_of_p

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
        PacketBase.__init__(self)
        self.payload_len = 0
        if raw is not None:
            self.parse(raw)

    @classmethod
    def from_values(cls, src, dst, payload, path=None,
                    ext_hdrs=None, next_hdr=0, pkt_type=PacketType.DATA):
        """
        Returns a SCIONPacket with the values specified.

        @param src: Source address (must be a 'HostAddr' object)
        @param dst: Destination address (must be a 'HostAddr' object)
        @param payload: Payload of the packet (either 'bytes' or 'PacketBase')
        @param path: The path for this packet.
        @param ext_hdrs: A list of extension headers.
        @param next_hdr: If 'ext_hdrs' is not None then this must be the type
                         of the first extension header in the list.
        @param pkt_type: The type of the packet.
        """
        pkt = SCIONPacket()
        pkt.hdr = SCIONHeader.from_values(src, dst, pkt_type, path,
                                          ext_hdrs, next_hdr)
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


class IFIDRequest(SCIONPacket):
    """
    IFID Request packet.
    """
    def __init__(self, raw=None):
        SCIONPacket.__init__(self)
        self.request_id = None
        if raw:
            self.parse(raw)

    def parse(self, raw):
        SCIONPacket.parse(self, raw)
        _, self.request_id = struct.unpack("HH", self.payload)

    @classmethod
    def from_values(cls, src, request_id):
        """
        Returns a IFIDRequest with the values specified.

        @param src: Source address (must be a 'HostAddr' object)
        @param request_id: interface number of src (neighboring router).
        """
        req = IFIDRequest()
        req.request_id = request_id
        dst = get_addr_from_type(PacketType.IFID_REQ)
        req.hdr = SCIONHeader.from_values(src, dst, PacketType.DATA)
        req.payload = struct.pack("HH", 0, request_id)
        return req

    def pack(self):
        self.payload = struct.pack("HH", 0, self.request_id)
        return SCIONPacket.pack(self)


class IFIDReply(SCIONPacket):
    """
    IFID Reply packet.
    """
    def __init__(self, raw=None):
        SCIONPacket.__init__(self)
        self.reply_id = None
        self.request_id = None
        if raw:
            self.parse(raw)

    def parse(self, raw):
        SCIONPacket.parse(self, raw)
        self.reply_id, self.request_id = struct.unpack("HH", self.payload)

    @classmethod
    def from_values(cls, dst, reply_id, request_id):
        """
        Returns a IFIDReply with the values specified.

        @param dst: Destination address (must be a 'HostAddr' object)
        @param reply_id: interface number of dst (local router).
        @param request_id: interface number of src (neighboring router).
        """
        rep = IFIDReply()
        rep.reply_id = reply_id
        rep.request_id = request_id
        src = get_addr_from_type(PacketType.IFID_REP)
        rep.hdr = SCIONHeader.from_values(src, dst, PacketType.DATA)
        return rep

    def pack(self):
        self.payload = struct.pack("HH", self.reply_id, self.request_id)
        return SCIONPacket.pack(self)


class CertRequest(SCIONPacket):
    """
    Certificate Request packet.
    """
    LEN = 14

    def __init__(self, raw=None):
        SCIONPacket.__init__(self)
        self.path = None
        self.cert_isd = 0
        self.cert_ad = 0
        self.cert_version = 0
        if raw:
            self.parse(raw)

    def parse(self, raw):
        SCIONPacket.parse(self, raw)
        bits = BitArray(bytes=self.payload)
        (self.cert_isd, self.cert_version, self.cert_ad) = \
            bits.unpack("uintbe:16, uintbe:32, uintbe:64")
        if len(self.payload) - CertRequest.LEN > 0:
            self.path = PathBase(self.payload[CertRequest.LEN:])
        else:
            self.path = self.hdr.path

    @classmethod
    def from_values(cls, req_type, src, dst, path, cert_isd, cert_ad,
        cert_version):
        """
        Returns a Certificate Request with the values specified.

        @param req_type: Either CERT_REQ_LOCAL (request comes from BS or user)
            or CERT_REQ.
        @param src: Source address (must be a 'HostAddr' object).
        @param dst: Destination address (must be a 'HostAddr' object).
        @param path: Path to a core or empty (when request comes from user).
        @param cert_isd: Target certificate ISD ID.
        @param cert_ad:, ad: Target certificate AD ID.
        @param cert_version: Target certificate version.
        """
        req = CertRequest()
        if req_type == PacketType.CERT_REQ:
            req.hdr = SCIONHeader.from_values(src, dst, req_type, path=path)
        else:
            req.hdr = SCIONHeader.from_values(src, dst, req_type, path=None)
        req.path = path
        req.cert_isd = cert_isd
        req.cert_ad = cert_ad
        req.cert_version = cert_version
        return req

    def pack(self):
        self.payload = bitstring.pack("uintbe:16, uintbe:32, uintbe:64",
            self.cert_isd, self.cert_version, self.cert_ad).bytes
        if self.hdr.common_hdr.type != PacketType.CERT_REQ:
            self.payload += self.path.pack()
        return SCIONPacket.pack(self)


class CertReply(SCIONPacket):
    """
    Certificate Reply packet.
    """
    MIN_LEN = 14

    def __init__(self, raw=None):
        SCIONPacket.__init__(self)
        self.cert_isd = 0
        self.cert_ad = 0
        self.cert_version = 0
        self.cert = ''
        self.cert_len = 0
        if raw:
            self.parse(raw)

    def parse(self, raw):
        SCIONPacket.parse(self, raw)
        bits = BitArray(bytes=self.payload)
        (self.cert_isd, self.cert_version, self.cert_ad) = \
            bits.unpack("uintbe:16, uintbe:32, uintbe:64")
        self.cert_len = len(self.payload) - CertReply.MIN_LEN
        if self.cert_len > 0:
            bits = BitArray(bytes=self.payload[CertReply.MIN_LEN:])
            self.cert = bits.unpack("uintbe:" + str(self.cert_len * 8))[0]
        else:
            self.cert = None

    @classmethod
    def from_values(cls, src, dst, path, cert_isd, cert_ad, cert_version, cert):
        """
        Returns a Certificate Reply with the values specified.

        @param src: Source address (must be a 'HostAddr' object).
        @param dst: Destination address (must be a 'HostAddr' object).
        @param path: Path to a core or empty (when request comes from user).
        @param cert_isd: Target certificate ISD ID.
        @param cert_ad:, ad: Target certificate AD ID.
        @param cert_version: Target certificate version.
        @param cert: Target certificate.
        """
        rep = CertReply()
        rep.hdr = SCIONHeader.from_values(src, dst, PacketType.CERT_REP,
            path=path)
        rep.cert_isd = cert_isd
        rep.cert_ad = cert_ad
        rep.cert_version = cert_version
        rep.cert = cert
        rep.cert_len = len(cert)
        return rep

    def pack(self):
        self.payload = bitstring.pack("uintbe:16, uintbe:32, uintbe:64, " +
            "uintbe:" + str(self.cert_len * 8), self.cert_isd,
            self.cert_version, self.cert_ad, self.cert).bytes
        return SCIONPacket.pack(self)


class RotRequest(SCIONPacket):
    """
    ROT Request packet.
    """
    LEN = 6

    def __init__(self, raw=None):
        SCIONPacket.__init__(self)
        self.path = None
        self.rot_isd = 0
        self.rot_version = 0
        if raw:
            self.parse(raw)

    def parse(self, raw):
        SCIONPacket.parse(self, raw)
        bits = BitArray(bytes=self.payload)
        (self.rot_isd, self.rot_version) = bits.unpack("uintbe:16, uintbe:32")
        if len(self.payload) - RotRequest.LEN > 0:
            self.path = PathBase(self.payload[RotRequest.LEN:])
        else:
            self.path = self.hdr.path

    @classmethod
    def from_values(cls, req_type, src, dst, path, rot_isd, rot_version):
        """
        Returns a ROT Request with the values specified.

        @param type: Either ROT_REQ_LOCAL (request comes from BS or user)
            or ROT_REQ.
        @param src: Source address (must be a 'HostAddr' object).
        @param dst: Destination address (must be a 'HostAddr' object).
        @param path: Path to a core or empty (when request comes from user).
        @param rot_isd: Target ROT ISD ID.
        @param rot_version: Target ROT version.
        """
        req = RotRequest()
        if req_type == PacketType.ROT_REQ:
            req.hdr = SCIONHeader.from_values(src, dst, req_type, path=path)
        else:
            req.hdr = SCIONHeader.from_values(src, dst, req_type, path=None)
        req.path = path
        req.rot_isd = rot_isd
        req.rot_version = rot_version
        return req

    def pack(self):
        self.payload = bitstring.pack("uintbe:16, uintbe:32", self.rot_isd,
            self.rot_version).bytes
        if self.hdr.common_hdr.type != PacketType.ROT_REQ:
            self.payload += self.path.pack()
        return SCIONPacket.pack(self)


class RotReply(SCIONPacket):
    """
    ROT Reply packet.
    """
    MIN_LEN = 6

    def __init__(self, raw=None):
        SCIONPacket.__init__(self)
        self.rot_isd = 0
        self.rot_version = 0
        self.rot = b''
        self.rot_len = 0
        if raw:
            self.parse(raw)

    def parse(self, raw):
        SCIONPacket.parse(self, raw)
        bits = BitArray(bytes=self.payload)
        (self.rot_isd, self.rot_version) = bits.unpack("uintbe:16, uintbe:32")
        self.rot_len = len(self.payload) - RotReply.MIN_LEN
        if self.rot_len > 0:
            bits = BitArray(bytes=self.payload[RotReply.MIN_LEN:])
            self.rot = bits.unpack("uintbe:" + str(self.rot_len * 8))[0]
        else:
            self.rot = None

    @classmethod
    def from_values(cls, src, dst, path, rot_isd, rot_version, rot):
        """
        Returns a ROT Reply with the values specified.

        @param src: Source address (must be a 'HostAddr' object).
        @param dst: Destination address (must be a 'HostAddr' object).
        @param path: Path to a core or empty (when request comes from user).
        @param rot_isd: Target ROT ISD ID.
        @param rot_version: Target ROT version.
        @param rot: Target ROT.
        """
        rep = RotReply()
        rep.hdr = SCIONHeader.from_values(src, dst, PacketType.ROT_REP,
            path=path)
        rep.rot_isd = rot_isd
        rep.rot_version = rot_version
        rep.rot = rot
        rep.rot_len = len(rot)
        return rep

    def pack(self):
        self.payload = bitstring.pack("uintbe:16, uintbe:32, uintbe:" +
            str(self.rot_len * 8), self.rot_isd, self.rot_version,
            self.rot).bytes
        return SCIONPacket.pack(self)
