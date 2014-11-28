"""
pcb.py

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

from lib.packet.opaque_field import SupportSignatureField, HopOpaqueField, \
    SupportPCBField, SupportPeerField, ROTField, InfoOpaqueField, \
    OpaqueFieldType
from lib.packet.path import CorePath
import bitstring, logging
from bitstring import BitArray


class PCBMarking(object):
    """
    Packs all fields for a specific PCB marking
    """
    LEN = 32

    def __init__(self, raw=None):
        self.parsed = False
        self.raw = None
        self.ad_id = 0
        self.ssf = SupportSignatureField()
        self.hof = HopOpaqueField()
        self.spcbf = SupportPCBField()
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < self.LEN:
            logging.warning("PCBM: Data too short for parsing, len: %u", dlen)
            return
        bits = BitArray(bytes=raw[:8])
        self.ad_id = bits.unpack("uintbe:64")[0]
        self.ssf.parse(raw[8:16])
        self.hof.parse(raw[16:24])
        self.spcbf.parse(raw[24:32])
        self.parsed = True

    @classmethod
    def from_values(cls, ad_id, ssf, hof, spcbf):
        """
        Returns PCBMarking with fields populated from values.
        """
        pcbm = PCBMarking()
        pcbm.ad_id = ad_id
        pcbm.ssf = ssf
        pcbm.hof = hof
        pcbm.spcbf = spcbf
        return pcbm

    def pack(self):
        """
        Returns PCBMarking as a binary string.
        """
        return bitstring.pack("uintbe:64", self.ad_id).bytes + \
               self.ssf.pack() + self.hof.pack() + self.spcbf.pack()

    def __str__(self):
        pcbm_str = "[PCB Marking ad_id: %x]\n" % (self.ad_id)
        pcbm_str += str(self.ssf)
        pcbm_str += str(self.hof) + '\n'
        pcbm_str += str(self.spcbf)
        return pcbm_str


class PeerMarking(object):
    """
    Packs all fields for a specific peer marking
    """
    LEN = 24

    def __init__(self, raw=None):
        self.parsed = False
        self.raw = None
        self.ad_id = 0
        self.hof = HopOpaqueField()
        self.spf = SupportPeerField()
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < self.LEN:
            logging.warning("PM: Data too short for parsing, len: %u", dlen)
            return
        bits = BitArray(bytes=raw[0:8])
        self.ad_id = bits.unpack("uintbe:64")[0]
        self.hof.parse(raw[8:16])
        self.spf.parse(raw[16:24])
        self.parsed = True

    @classmethod
    def from_values(cls, ad_id, hof, spf):
        """
        Returns PeerMarking with fields populated from values.
        """
        peer_marking = PeerMarking()
        peer_marking.ad_id = ad_id
        peer_marking.hof = hof
        peer_marking.spf = spf
        return peer_marking

    def pack(self):
        """
        Returns PeerMarking as a binary string.
        """
        return bitstring.pack("uintbe:64", self.ad_id).bytes + \
               self.hof.pack() + self.spf.pack()

    def __str__(self):
        pm_str = "[Peer Marking ad_id: %x]\n" % (self.ad_id)
        pm_str += str(self.hof) + '\n'
        pm_str += str(self.spf)
        return pm_str


class AutonomousDomain(object):
    """
    Packs all fields for a specific Autonomous Domain
    """
    def __init__(self, raw=None):
        self.parsed = False
        self.raw = None
        self.pcbm = PCBMarking()
        self.pms = []
        self.sig = b''
        self.LEN = self.pcbm.LEN
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < self.LEN:
            logging.warning("AD: Data too short for parsing, len: %u", dlen)
            return
        self.pcbm.parse(raw[:self.pcbm.LEN])
        raw = raw[self.pcbm.LEN:]
        while len(raw) > (self.pcbm.ssf.sig_len):
            peer_marking = PeerMarking()
            peer_marking.parse(raw[:peer_marking.LEN])
            self.pms.append(peer_marking)
            raw = raw[peer_marking.LEN:]
        self.sig = raw
        self.parsed = True

    @classmethod
    def from_values(cls, pcbm, pms, sig):
        """
        Returns AutonomousDomain with fields populated from values.
        """
        autonomous_domain = AutonomousDomain()
        autonomous_domain.pcbm = pcbm
        autonomous_domain.pms = pms
        autonomous_domain.sig = sig
        return autonomous_domain

    def pack(self):
        """
        Returns AutonomousDomain as a binary string.
        """
        ad_bytes = self.pcbm.pack()
        for peer_marking in self.pms:
            ad_bytes += peer_marking.pack()
        ad_bytes += self.sig
        return ad_bytes

    def remove_sig(self):
        """
        Removes the signature from the AD block.
        """
        self.sig = b''
        self.pcbm.ssf.sig_len = 0

    def __str__(self):
        ad_str = "[Autonomous Domain]\n"
        ad_str += str(self.pcbm)
        for peer_marking in self.pms:
            ad_str += str(peer_marking)
        ad_str += str(self.sig) + "\n"
        return ad_str


class PCB(object):
    """
        Packs all PCB fields for a specific beacon
    """
    LEN = 16

    def __init__(self, raw=None):
        self.parsed = False
        self.raw = None
        self.iof = InfoOpaqueField()
        self.iof.info = OpaqueFieldType.SPECIAL_OF
        self.rotf = ROTField()
        self.ads = []
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < self.LEN:
            logging.warning("PCB: Data too short for parsing, len: %u", dlen)
            return
        self.iof.parse(raw[0:8])
        self.rotf.parse(raw[8:16])
        raw = raw[16:]
        while len(raw) > 0:
            pcbm = PCBMarking()
            pcbm.parse(raw[:pcbm.LEN])
            autonomous_domain = AutonomousDomain(raw[:pcbm.ssf.sig_len + \
                                                    pcbm.ssf.block_size])
            self.ads.append(autonomous_domain)
            raw = raw[pcbm.ssf.sig_len+pcbm.ssf.block_size:]
        self.parsed = True

    def pack(self):
        """
        Returns PCB as a binary string.
        """
        pcb_bytes = self.iof.pack() + self.rotf.pack()
        for autonomous_domain in self.ads:
            pcb_bytes += autonomous_domain.pack()
        return pcb_bytes

    def add_ad(self, autonomous_domain):
        """
        Appends a new AD block.
        """
        self.iof.hops = self.iof.hops + 1
        self.ads.append(autonomous_domain)

    def remove_sig(self):
        """
        Removes the signature from each AD block.
        """
        for autonomous_domain in self.ads:
            autonomous_domain.remove_sig()

    def get_core_path(self):
        """
        Returns the list of HopOpaqueFields in the path.
        """
        hofs = []
        for autonomous_domain in reversed(self.ads):
            hofs.append(autonomous_domain.pcbm.hof)
        core_path = CorePath.from_values(self.iof, hofs)
        return core_path

    def get_isd(self):
        """
        Returns the ISD ID.
        """
        return self.iof.isd_id

    def get_last_ad(self):
        """
        Returns the previous AD ID.
        """
        return self.ads[-1].pcbm.ad_id

    @staticmethod
    def deserialize(raw):
        """
        Deserializes a bytes string into a list of PCBs.
        """
        assert isinstance(raw, bytes)
        dlen = len(raw)
        if dlen < PCB.LEN:
            logging.warning("Data too short for parsing, len: %u", dlen)
            return
        pcbs = []
        while len(raw) > 0:
            pcb = PCB()
            pcb.iof.parse(raw[0:8])
            pcb.rotf.parse(raw[8:16])
            raw = raw[16:]
            for i in range(0, pcb.iof.hops):
                pcbm = PCBMarking()
                pcbm.parse(raw[:pcbm.LEN])
                autonomous_domain = AutonomousDomain(raw[:pcbm.ssf.sig_len + \
                                                        pcbm.ssf.block_size])
                pcb.ads.append(autonomous_domain)
                raw = raw[pcbm.ssf.sig_len + pcbm.ssf.block_size:]
            pcbs.append(pcb)
        return pcbs

    @staticmethod
    def serialize(pcbs):
        """
        Serializes a list of PCBs into a bytes string.
        """
        pcbs_list = []
        for pcb in pcbs:
            pcbs_list.append(pcb.pack())
        return b"".join(pcbs_list)

    def __str__(self):
        pcb_str = "[PCB]\n"
        pcb_str += str(self.iof) + str(self.rotf)
        for autonomous_domain in self.ads:
            pcb_str += str(autonomous_domain)
        return pcb_str
