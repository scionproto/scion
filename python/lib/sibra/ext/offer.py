# Copyright 2016 ETH Zurich
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
:mod:`offer` --- Offer block
============================
"""
# Stdlib
import struct

# SCION
from lib.sibra.ext.info import (
    ResvInfoBase,
    ResvInfoEphemeral,
    ResvInfoSteady,
)
from lib.packet.ext_hdr import HopByHopExtension
from lib.packet.packet_base import Serializable
from lib.sibra.util import BWClass
from lib.util import Raw, calc_padding


class OfferBlockBase(Serializable):
    """
    Base class for a SIBRA offer block. This carries the bandwidth suggestions
    from all hops a rejected request passes through, starting with the first hop
    that rejected it. As the block gets padded to a multiple of LINE_LEN, there
    can be a number of empty offers at the end. These are handled by calculating
    the number of offer hops there should be, and ignoring the rest.

    An offer block is made up of a reservation info field, and a list of
    bandwidth suggestions.

     0B       1        2        3        4        5        6        7
     +--------+--------+--------+--------+--------+--------+--------+--------+
     | Reservation Info                                                      |
     +--------+--------+--------+--------+--------+--------+--------+--------+
     |Fwd bw 1|Rev bw 1|Fwd bw 2|Rev bw 2|Fwd bw 3|Rev bw 3|...              |
     +--------+--------+--------+--------+--------+--------+--------+--------+
     |...                                                                    |
     +--------+--------+--------+--------+--------+--------+--------+--------+
    """
    OFFER_LEN = 2
    LINE_LEN = HopByHopExtension.LINE_LEN
    OFFERS_PER_LINE = LINE_LEN // OFFER_LEN
    MIN_LEN = ResvInfoBase.LEN

    def __init__(self, raw=None):  # pragma: no cover
        self.info = None
        self.offers = []
        self.offer_hops = None
        super().__init__(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.MIN_LEN, min_=True)
        self.info = self.RESVINFO(data.pop(ResvInfoBase.LEN))
        self.offer_hops = len(data) // self.OFFER_LEN
        for _ in range(self.offer_hops):
            self.offers.append(BWClass(data.pop(1), data.pop(1)))

    @classmethod
    def from_values(cls, info, offer_hops):
        inst = cls()
        inst.info = info
        inst.offer_hops = offer_hops
        # Pad number of offer hops to a full line
        inst.offer_hops += calc_padding(offer_hops, cls.OFFERS_PER_LINE)
        for _ in range(inst.offer_hops):
            inst.offers.append(BWClass())
        return inst

    def pack(self):
        raw = []
        raw.append(self.info.pack())
        for offer in self.offers:
            raw.append(struct.pack("!BB", offer.fwd, offer.rev))
        result = b"".join(raw)
        assert len(result) % self.LINE_LEN == 0
        assert len(result) == len(self)
        return result

    def add(self, curr_hop, bw_cls):  # pragma: no cover
        """
        Add a suggested bandwidth for the current hop
        """
        offer_hop = curr_hop - self.info.fail_hop
        assert offer_hop < self.offer_hops
        self.offers[offer_hop] = bw_cls

    def get_min(self, total_hops):
        """
        Find the minimum suggested bandwidth in both directions. The total hop
        count is passed in so that padding offer entries can be ignored.
        """
        actual_offers = total_hops - self.info.fail_hop
        # FIXME(kormat): Needs to be exception
        assert len(self.offers) >= actual_offers
        bw_cls = self.offers[0]
        for offer in self.offers[:actual_offers]:
            bw_cls.min(offer)
        return bw_cls

    def __len__(self):  # pragma: no cover
        return ResvInfoBase.LEN + self.offer_hops * self.OFFER_LEN

    def __str__(self):
        tmp = ["%s(%dB): Offer hops: %s" %
               (self.NAME, len(self), self.offer_hops)]
        tmp.append("  %s" % self.info)
        for i, offer in enumerate(self.offers):
            tmp.append("  Offer %d: Fwd:%s Rev:%s" % (
                i, offer.fwd_str(), offer.rev_str()))
        return "\n".join(tmp)


class OfferBlockSteady(OfferBlockBase):
    NAME = "OfferBlockSteady"
    STEADY = True
    RESVINFO = ResvInfoSteady


class OfferBlockEphemeral(OfferBlockBase):
    NAME = "OfferBlockEphemeral"
    STEADY = False
    RESVINFO = ResvInfoEphemeral
