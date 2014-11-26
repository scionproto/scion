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

import logging
import bitstring
from bitstring import BitArray
from lib.packet.opaque_field import *
from lib.packet.path import CorePath


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
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < self.LEN:
            logging.warning("PCBM: Data too short to parse the field, len: %u", dlen)
            return
        bits = BitArray(bytes=raw[:8])
        self.ad_id = bits.unpack("uintle:64")[0]
        self.ssf.parse(raw[8:16])
        self.hof.parse(raw[16:24])
        self.spcbf.parse(raw[24:32])
        self.parsed = True
        
    @classmethod
    def from_values(cls, ad_id, ssf, hof, spcbf):
        pcbm = PCBMarking()
        pcbm.ad_id = ad_id
        pcbm.ssf = ssf
        pcbm.hof = hof
        pcbm.spcbf = spcbf
        return pcbm

    def pack(self):
        return bitstring.pack("uintle:64", self.ad_id).bytes + \
               self.ssf.pack() + self.hof.pack() + self.spcbf.pack()

    def __str__(self):
        s = "[PCB Marking ad_id: %x]\n" % (self.ad_id)
        s += str(self.ssf)
        s += str(self.hof) +'\n'
        s += str(self.spcbf)
        return s
        
        
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
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < self.LEN:
            logging.warning("PM: Data too short to parse the field, len: %u", dlen)
            return
        bits = BitArray(bytes=raw[0:8])
        self.ad_id = bits.unpack("uintle:64")[0]
        self.hof.parse(raw[8:16])
        self.spf.parse(raw[16:24])
        self.parsed = True
        
    @classmethod
    def from_values(cls, ad_id, hof, spf):
        pm = PeerMarking()
        pm.ad_id = ad_id
        pm.hof = hof
        pm.spf = spf
        return pm

    def pack(self):
        return bitstring.pack("uintle:64", self.ad_id).bytes + \
               self.hof.pack() + self.spf.pack()

    def __str__(self):
        s = "[Peer Marking ad_id: %x]\n" % (self.ad_id)
        s += str(self.hof) + '\n'
        s += str(self.spf)
        return s
        

class AutonomousDomain(object):
    """
    Packs all fields for a specific Autonomous Domain
    """
    def __init__(self, raw=None):
        self.parsed = False
        self.raw = None
        self.pcbm = PCBMarking()
        self.pms = []
        self.sig = ''
        self.LEN = self.pcbm.LEN
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < self.LEN:
            logging.warning("AD: Data too short to parse the field, len: %u", dlen)
            return
        self.pcbm.parse(raw[:self.pcbm.LEN])
        raw = raw[self.pcbm.LEN:]
        while len(raw) > (self.pcbm.ssf.sig_len):
            pm = PeerMarking()
            pm.parse(raw[:pm.LEN])
            self.pms.append(pm)
            raw = raw[pm.LEN:]
        bits = BitArray(bytes=raw)
        self.sig = raw
        self.parsed = True
    
    @classmethod
    def from_values(cls, pcbm, pms, sig):
        ad = AutonomousDomain()
        ad.pcbm = pcbm
        ad.pms = pms
        ad.sig = sig
        return ad

    def pack(self):
        p = self.pcbm.pack()
        for pm in self.pms:
            p += pm.pack()
        p += self.sig
        return p
        
    def remove_sig(self):
        self.sig = b''
        self.pcbm.ssf.sig_len = 0

    def __str__(self):
        s = "[Autonomous Domain]\n"
        s += str(self.pcbm)
        for pm in self.pms:
            s += str(pm)
        s += str(self.sig) + "\n"
        return s


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
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < self.LEN:
            logging.warning("PCB: Data too short to parse the field, len: %u", dlen)
            return
        self.iof.parse(raw[0:8])
        self.rotf.parse(raw[8:16])
        raw = raw[16:]
        while len(raw) > 0:
            pcbm = PCBMarking()
            pcbm.parse(raw[:pcbm.LEN])
            ad = AutonomousDomain(raw[:pcbm.ssf.sig_len+pcbm.ssf.block_size])
            self.ads.append(ad)
            raw = raw[pcbm.ssf.sig_len+pcbm.ssf.block_size:]
        self.parsed = True

    def pack(self):
        p = self.iof.pack() + self.rotf.pack()
        for ad in self.ads:
            p += ad.pack()
        return p
        
    def add_ad(self, ad):
        self.iof.hops = self.iof.hops + 1
        self.ads.append(ad)
        
    def remove_sig(self):
        for ad in self.ads:
            ad.remove_sig()

    def get_core_path(self):
        hofs = []
        for ad in reversed(self.ads):
            hofs.append(ad.pcbm.hof)
        cp = CorePath.from_values(self.iof, hofs)
        return cp

    def get_isd(self):
        return self.iof.isd_id

    def get_last_ad(self):
        return self.ads[-1].pcbm.ad_id

    def deserialize(raw):
        assert isinstance(raw, bytes)
        dlen = len(raw)
        if dlen < PCB.LEN:
            logging.warning("Data too short to parse the field, len: %u", dlen)
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
                ad = AutonomousDomain(raw[:pcbm.ssf.sig_len+pcbm.ssf.block_size])
                pcb.ads.append(ad)
                raw = raw[pcbm.ssf.sig_len+pcbm.ssf.block_size:]
            pcbs.append(pcb)
        return pcbs

    def serialize(pcbs):
        l = []
        for pcb in pcbs:
            l.append(pcb.pack())
        return b"".join(l)

    def __str__(self):
        s = "[PCB]\n"
        s += str(self.iof) + str(self.rotf)
        for ad in self.ads:
            s += str(ad)
        return s
