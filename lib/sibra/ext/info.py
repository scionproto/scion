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
from lib.packet.packet_base import Serializable
from lib.sibra.util import (
    BWClass,
    tick_to_time,
    time_to_tick,
)
from lib.types import SIBRAPathType
from lib.util import Raw, iso_timestamp


class ResvInfoBase(Serializable):
    """
    Base class for SIBRA reservation info fields. This stores information about
    a (requested or active) reservation.

     0B       1        2        3        4        5        6        7
     +--------+--------+--------+--------+--------+--------+--------+--------+
     | Expiration time (4B)              | BW fwd | BW rev |Idx|F|xx|Fail hop|
     +--------+--------+--------+--------+--------+--------+--------+--------+

    The reservation index (Idx) is used to allow for multiple overlapping
    reservations within a single path, which enables renewal and changing the
    bandwidth requested.

    The F(orward) flag is used when registering a steady path, to indicate which
    direction it will traverse the path. E.g. a steady path registered with a
    local path server will have the forward flag set, as anything using that
    path will traverse it in the direction it was created. A steady path
    registered with a core path server will have the forward flag unset, as
    anything using the path from that direction will traverse the path in the
    opposite direction to creation.

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
        self.fwd_dir = None  # Which direction is the reservation traversed in
        super().__init__(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.LEN)
        self.exp_tick = struct.unpack("!I", data.pop(4))[0]
        self.bw = BWClass(data.pop(1), data.pop(1))
        index_flags = data.pop(1)
        self.fwd_dir = bool((index_flags >> 3) & 1)
        self.index = index_flags >> 4
        # FIXME(kormat): needs error handling
        assert self.index < SIBRA_MAX_IDX
        self.fail_hop = data.pop(1)

    @classmethod
    def from_values(cls, exp, bwsnap=None,
                    bw_cls=None, index=0, fwd_dir=True):  # pragma: no cover
        """
        :param float exp: Expiry time, in seconds since unix epoch.
        :param BWSnapshot bwsnap:
            Bandwidth to reserve in forward/reverse directions.
        :param BWClass bw_cls:
            SIBRA bandwidth class to reserve in forward/reverse directions.
        """
        assert bwsnap or bw_cls
        inst = cls()
        inst.exp_tick = time_to_tick(exp)
        if bwsnap is not None:
            inst.bw = bwsnap.to_classes().ceil()
        else:
            inst.bw = bw_cls
        inst.index = index
        inst.fwd_dir = fwd_dir
        inst.fail_hop = 0
        assert inst.index < SIBRA_MAX_IDX
        return inst

    def pack(self, mac=False):
        raw = []
        bw_ceil = self.bw.ceil()
        raw.append(struct.pack("!I", self.exp_tick))
        raw.append(struct.pack("!BB", bw_ceil.fwd, bw_ceil.rev))
        index_flags = self.index << 4
        if not mac:
            index_flags |= self.fwd_dir << 3
        raw.append(struct.pack("!B", index_flags))
        raw.append(struct.pack("!B", 0 if mac else self.fail_hop))
        return b"".join(raw)

    def exp_ts(self):  # pragma: no cover
        """
        Convert the expiration time from a SIBRA tick to a unix timestamp.
        """
        return tick_to_time(self.exp_tick)

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __str__(self):
        tmp = []
        tmp.append("%s(%dB): Resv idx: %2s Fwd: %s Rev: %s" %
                   (self.NAME, len(self), self.index, self.bw.fwd_str(),
                    self.bw.rev_str()))
        tmp.append("Failhop: %s Dir fwd: %s Expiry: %s" %
                   (self.fail_hop, self.fwd_dir,
                    iso_timestamp(tick_to_time(self.exp_tick))))
        return "\n  ".join(tmp)


class ResvInfoSteady(ResvInfoBase):
    NAME = "ResvInfoSteady"
    PATH_TYPE = SIBRAPathType.STEADY


class ResvInfoEphemeral(ResvInfoBase):
    NAME = "ResvInfoEphemeral"
    PATH_TYPE = SIBRAPathType.EPHEMERAL
