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
:mod:`scion_icmp` --- SCION ICMP header class
========================================
"""
# stdlib
import struct

# SCION
from lib.packet.packet_base import HeaderBase, PayloadBase, PacketBase
from lib.packet.scion import SCIONHeader

class SCIONICMPType(object):
    """
    Define ICMP type for SCION packets
    """
    ICMP_ECHOREPLY = 0 # Echo Reply
    ICMP_DEST_UNREACH = 3 # Destination Unreachable
    ICMP_SOURCE_QUENCH = 4 # Source Quench
    ICMP_REDIRECT = 5 # Redirect (change route)
    ICMP_ECHO = 8 # Echo Request
    ICMP_TIME_EXCEEDED = 11 # Time Exceeded
    ICMP_PARAMETERPROB = 12 # Parameter Problem
    ICMP_TIMESTAMP = 13 # Timestamp Request
    ICMP_TIMESTAMPREPLY = 14 # Timestamp Reply
    ICMP_INFO_REQUEST = 15 # Information Request
    ICMP_INFO_REPLY = 16 # Information Reply
    ICMP_ADDRESS = 17 # Address Mask Request
    ICMP_ADDRESSREPLY = 18 # Address Mask Reply
    NR_ICMP_TYPES = 18 # total number of ICMP Type


class SCIONICMPCodeUnreach(object):
    """
    Define ICMP code for packet type of Destination Unreachable
    """

    ICMP_NET_UNREACH = 0 # Network Unreachable
    ICMP_HOST_UNREACH = 1 # Host Unreachable
    ICMP_PROT_UNREACH = 2 # Protocol Unreachable
    ICMP_PORT_UNREACH = 3 # Port Unreachable
    ICMP_FRAG_NEEDED = 4 # Fragmentation Needed/DF set
    ICMP_SR_FAILED = 5 # Source Route failed
    ICMP_NET_UNKNOWN = 6
    ICMP_HOST_UNKNOWN = 7
    ICMP_HOST_ISOLATED = 8
    ICMP_NET_ANO = 9
    ICMP_HOST_ANO = 10 
    ICMP_NET_UNR_TOS = 11
    ICMP_HOST_UNR_TOS = 12
    ICMP_PKT_FILTERED = 13 # Packet filtered 
    ICMP_PREC_VIOLATION = 14 # Precedence violation
    ICMP_PREC_CUTOFF = 15 # Precedence cut off 
    NR_ICMP_UNREACH = 15 # instead of hardcoding immediate value 

class SCIONICMPCodeRedirect(object):
    """
    Define ICMP code for packet type of Redirection
    """
    ICMP_REDIR_NET = 0 # Redirect Net
    ICMP_REDIR_HOST = 1 # Redirect Host
    ICMP_REDIR_NETTOS = 2 # Redirect Net for TOS
    ICMP_REDIR_HOSTTOS = 3 # Redirect Host for TOS


class SCIONICMPCodeTimeExceed(object):
    """
    Define ICMP code for packet type of Time Exceed
    """
    ICMP_EXC_TTL = 0  # TTL count exceeded
    ICMP_EXC_FRAGTIME = 1 # Fragment Reass time exceeded




class SCIONICMPHdr(HeaderBase):

    """
    Encapsulate the common header of ICMP packets
    """
    LEN = 8
    
    def __init__ (self, raw = None):
        """
        Init an instance of the class SCIONICMPCmnHdr
        :param raw:
        :type raw:
        """
        HeaderBase.__init__(self)
        self.icmp_type = None # icmp type
        self.icmp_code = None # icmp code
        self.chksum = None # icmp checksum
        self.rest = None # 4 byte rest of header field
        if raw is not None:
            self.parse(raw)


    @classmethod
    def from_values(cls, type, code, rest=0):
        """
        Returns a SCIONICMPCmnHdr with the values specified
        """
        hdr = SCIONICMPHdr()
        hdr.icmp_type = type
        hdr.icmp_code = code
        hdr.rest = rest
        hdr.compute_chksum()
        return hdr


    def compute_chksum(self):
        self.chksum = 0

    def verify_chksum(self):
        return True


    def parse(self, raw):
        """
        Parses the raw data and populates the fields accordingly.
        """
        assert isinstance(raw, bytes)
        dlen = len(raw)
        if dlen < self.LEN:
            logging.warning("Data too short to parse SCION ICMP header: "
                            "data len %u", dlen)
            return
        
        (self.icmp_type, self.icmp_code, self.chksum, 
         self.rest) = struct.unpack("!BBHI", raw)
        
        return

    def pack(self):
        return struct.pack("!BBHI", self.icmp_type, self.icmp_code, self.chksum, self.rest)
    
    def __str__(self):
        res = ("[ICMP type: %u, code: %u, rest: %u, chksum: %u]") % (
            self.icmp_type, self.icmp_code, self.rest, self.chksum
        )
        return res


class SCIONICMPPacket(PacketBase):
    MIN_LEN = SCIONHeader.MIN_LEN + SCIONICMPHdr.LEN
    """
    class for creating and manipulating SCION ICMP packets
    """
    def __init__(self, raw=None):
        PacketBase.__init__(self)
        self.scion_hdr = None
        self.scion_icmp_hdr = None
        self.data = None
        if raw is not None:
            self.parse(raw)


    def from_values(cls, scion_hdr, type, code, rest=0, data=None):
        """
        Return a SCIONICMPPacket with the values specified
        :param scion_hdr SCION header in the ICMP packet
        :param type icmp type 
        :param code icmp code
        :param rest rest of header field
        :param data icmp data
        """

        pkt = SCIONICMPPacket()
        pkt.scion_hdr = scion_hdr
        pkt.scion_icmp_hdr = SCIONICMPHdr.from_values(type, code, rest)
        pkt.data = data
        pkt.compute_chksum()
        return pkt



    def compute_chksum(self):
        """
        Compute the checksum in icmp packet
        """
        #TODO: compute the chksum for the packet
        self.scion_icmp_hdr.compute_chksum()
        
        
    def verify_chksum(self):
        """
        Verify the checksum in the icmp pkt
        """
        #TODO: verify the chksum in the packet
        return True
        
    
    def parse(self, raw):
        """
        Parses the raw data and populates the fields accordingly.
        """
        assert isinstance(raw, bytes)
        dlen = len(raw)
        self.raw = raw
        if dlen < SCIONICMPPacket.MIN_LEN:
            logging.warning("Data too short to parse SCION packet: "
                            "data len %u", dlen)
            return

        self.scion_hdr = SCIONHeader(raw)
        icmp_hdr_start = len(self.scion_hdr)
        data_start = icmp_hdr_start + SCIONICMPHdr.LEN
        self.scion_icmp_hdr = SCIONICMPHdr(raw[icmp_hdr_start:data_start])
        self.data = raw[data_start:]

    def pack(self):
        """
        Packs the header and the payload and returns a byte array.
        """
        raw_list = []
        raw_list.append(self.scion_hdr.pack())
        raw_list.append(self.scion_icmp_hdr.pack())
        if isinstance(self.data, PayloadBase):
            raw_list.append(self.data.pack())
        elif self.data:
            raw_list.append(self.data)
        else:
           pass
        return b"".join(raw_list)
            
