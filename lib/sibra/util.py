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
:mod:`sibra` --- SIBRA utilities
================================
"""
# Stdlib
import math

# SCION
from lib.defines import SIBRA_BW_FACTOR, SIBRA_TICK
from lib.util import SCIONTime


class BWSnapshot(object):  # pragma: no cover
    """
    A class to represent bi-directional bandwidth, in bits/s
    """
    def __init__(self, fwd=0, rev=0):
        self.fwd = fwd
        self.rev = rev

    def __add__(self, other):
        return BWSnapshot(self.fwd + other.fwd, self.rev + other.rev)

    def __sub__(self, other):
        return BWSnapshot(self.fwd - other.fwd, self.rev - other.rev)

    def __neg__(self):
        return BWSnapshot(-self.fwd, -self.rev)

    def __eq__(self, other):
        return self.fwd == other.fwd and self.rev == other.rev

    def min(self, other):
        self.fwd = min(self.fwd, other.fwd)
        self.rev = min(self.rev, other.rev)
        return self

    def max(self, other):
        self.fwd = max(self.fwd, other.fwd)
        self.rev = max(self.rev, other.rev)
        return self

    def slte(self, other):
        """
        "Strictly Less Than Equal". Only returns true if this object's forward
        AND reverse bandwidth are <= other.fwd and other.rev
        """
        return (self.fwd <= other.fwd) and (self.rev <= other.rev)

    def lte(self, other):
        """
        "Less Than Equal". Only returns true if this object's forward
        OR reverse bandwidth are <= other.fwd and other.rev
        """
        return (self.fwd <= other.fwd) or (self.rev <= other.rev)

    def reverse(self):
        self.fwd, self.rev = self.rev, self.fwd
        return self

    def copy(self):
        return BWSnapshot(self.fwd, self.rev)

    def to_classes(self, floor=False):
        """
        Convert to a bandwidth class
        """
        return BWClass(bps_to_class(self.fwd, floor),
                       bps_to_class(self.rev, floor))

    def fwd_str(self):
        return "%.1fKibit/s[%.1f]" % (self.fwd/1024, bps_to_class(self.fwd))

    def rev_str(self):
        return "%.1fKibit/s[%.1f]" % (self.rev/1024, bps_to_class(self.rev))

    def __str__(self):
        return "<BWSnapshot fwd:%s rev:%s>" % (self.fwd_str(), self.rev_str())

    def __repr__(self):
        return str(self)


class BWClass(object):  # pragma: no cover
    """
    A class to represent bi-direction SIBRA bandwidth classes. A class of 0 is a
    special case, and represents 0 bandwidth. Any other class x maps to Kibit/s
    via SIBRA_BW_FACTOR * sqrt(2 ** x-1). These classes are used to encode
    bandwidths in the extension header fields.
    """
    def __init__(self, fwd=0, rev=0):
        self.fwd = fwd
        self.rev = rev

    def __eq__(self, other):
        return self.fwd == other.fwd and self.rev == other.rev

    def min(self, other):
        self.fwd = min(self.fwd, other.fwd)
        self.rev = min(self.rev, other.rev)
        return self

    def copy(self):
        return BWClass(self.fwd, self.rev)

    def to_snap(self):
        return BWSnapshot(class_to_bps(self.fwd), class_to_bps(self.rev))

    def reverse(self):
        self.fwd, self.rev = self.rev, self.fwd
        return self

    def ceil(self):
        return BWClass(math.ceil(self.fwd), math.ceil(self.rev))

    def floor(self):
        return BWClass(math.floor(self.fwd), math.floor(self.rev))

    def fwd_str(self):
        return "%.1f(%.1fKibit/s)" % (self.fwd, class_to_bps(self.fwd)/1024)

    def rev_str(self):
        return "%.1f(%.1fKibit/s)" % (self.rev, class_to_bps(self.rev)/1024)

    def __str__(self):
        return "<BWClass fwd:%s rev:%s>" % (self.fwd_str(), self.rev_str())


def class_to_bps(bw_cls):
    """
    Convert a SIBRA bandwidth class to bps (Bits Per Second). Class 0 is a
    special case, and is mapped to 0bps.

    :param float bw_cls: SIBRA bandwidth class.
    :returns: Kbps of bandwidth class
    :rtype: float
    """
    if bw_cls == 0:
        return 0
    bw_base = math.sqrt(pow(2, bw_cls - 1))
    return SIBRA_BW_FACTOR * bw_base


def bps_to_class(bps, floor=False):
    """
    Convert bps (Bits Per Second) to a SIBRA bandwidth class. bps 0 is a
    special case, and is mapped to Class 0.

    :param float bps: bits per second
    :returns: SIBRA bandwidth class
    :rtype: float
    """
    if bps == 0 or (floor and bps < SIBRA_BW_FACTOR):
        return 0
    bw_base = max(1, bps / SIBRA_BW_FACTOR)
    bw_cls = math.log2(pow(bw_base, 2)) + 1
    if floor:
        return math.floor(bw_cls)
    return bw_cls


def tick_to_time(tick):  # pragma: no cover
    """
    Converts from SIBRA tick to unix timestamp
    """
    return tick * SIBRA_TICK


def time_to_tick(ts, ceil=True):  # pragma: no cover
    """
    Converts from unix timestamp to SIBRA tick

    :param float ts: Seconds since the unix epoch.
    :param bool ceil: Round up the value to the next SIBRA tick
    """
    if ceil:
        return math.ceil(ts / SIBRA_TICK)
    return math.floor(ts / SIBRA_TICK)


def current_tick():  # pragma: no cover
    """
    Returns the current SIBRA tick
    """
    return time_to_tick(SCIONTime.get_time())
