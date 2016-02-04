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
:mod:`info` --- Reservation info
================================
"""
# Stdlib
import struct

# SCION
from lib.defines import SIBRA_MAX_IDX
from lib.packet.ext_hdr import HopByHopExtension
from lib.sibra.util import (
    BWClass,
    tick_to_time,
    time_to_tick,
)
from lib.types import SIBRAPathType
from lib.util import Raw, iso_timestamp


class ResvInfoBase(object):
    """
    Base class for SIBRA reservation info fields. This stores information about
    a (requested or active) reservation.

     0B       1        2        3        4        5        6        7
     +--------+--------+--------+--------+--------+--------+--------+--------+
     | Expiration time (4B)              | BW fwd | BW rev |Idx|pad |Fail hop|
     +--------+--------+--------+--------+--------+--------+--------+--------+

    The reservation index (Idx) is used to allow for multiple overlapping
    reservations within a single path, which enables renewal and changing the
    bandwidth requested.

    The fail hop field is normally set to 0, and ignored unless this reservation
    info is part of a denied request, in which case it is set to the number of
    the first hop to reject the reservation.
    """
    LEN = HopByHopExtension.LINE_LEN

    def __init__(self, raw=None):  # pragma: no cover
        self.exp_tick = None  # SIBRA tick when the reservation expires
        self.bw = None  # Bandwidth reserved (in both directions)
        self.index = None  # Reservation index
        self.fail_hop = None  # Which hop rejected a request, if any.
        if raw:
            self._parse(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.LEN)
        self.exp_tick = struct.unpack("!I", data.pop(4))[0]
        self.bw = BWClass(data.pop(1), data.pop(1))
        self.index = data.pop(1) >> 4
        # FIXME(kormat): needs error handling
        assert self.index < SIBRA_MAX_IDX
        self.fail_hop = data.pop(1)

    @classmethod
    def from_values(cls, exp, bwsnap, index=0):  # pragma: no cover
        """
        :param float exp: Expiry time, in seconds since unix epoch.
        :param BWSnapshot bwsnap:
            Bandwidth to reserve in forward/reverse directions.
        """
        inst = cls()
        inst.exp_tick = time_to_tick(exp)
        inst.bw = bwsnap.to_classes().ceil()
        inst.index = index
        inst.fail_hop = 0
        assert inst.index < SIBRA_MAX_IDX
        return inst

    def pack(self):
        raw = []
        bw_ceil = self.bw.ceil()
        raw.append(struct.pack("!I", self.exp_tick))
        raw.append(struct.pack("!BB", bw_ceil.fwd, bw_ceil.rev))
        raw.append(struct.pack("!BB", self.index << 4, self.fail_hop))
        return b"".join(raw)

    def exp_ts(self):  # pragma: no cover
        """
        Convert the expiration time from a SIBRA tick to a unix timestamp.
        """
        return tick_to_time(self.exp_tick)

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __str__(self):
        tmp = ["%s(%dB):" % (self.NAME, len(self))]
        tmp.append("Resv idx: %2s" % self.index)
        tmp.append("Fwd: %s" % self.bw.fwd_str())
        tmp.append("Rev: %s" % self.bw.rev_str())
        tmp.append("Failhop: %s" % self.fail_hop)
        tmp.append("Expiry: %s" % iso_timestamp(tick_to_time(self.exp_tick)))
        return " ".join(tmp)


class ResvInfoSteady(ResvInfoBase):
    NAME = "ResvInfoSteady"
    PATH_TYPE = SIBRAPathType.STEADY


class ResvInfoEphemeral(ResvInfoBase):
    NAME = "ResvInfoEphemeral"
    PATH_TYPE = SIBRAPathType.EPHEMERAL
