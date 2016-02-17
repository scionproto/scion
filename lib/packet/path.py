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
:mod:`path` --- SCION Path packets
==================================
"""
# Stdlib
import copy
from abc import ABCMeta, abstractmethod

# SCION
from lib.defines import SCION_MIN_MTU
from lib.errors import SCIONParseError
from lib.packet.opaque_field import (
    HopOpaqueField,
    InfoOpaqueField,
    OpaqueField,
    OpaqueFieldList,
)
from lib.packet.packet_base import HeaderBase
from lib.packet.pcb_ext.mtu import MtuPcbExt
from lib.types import OpaqueFieldType as OFT
from lib.util import Raw

UP_IOF = "up_segment_iof"
UP_HOFS = "up_segment_hofs"
DOWN_IOF = "down_segment_iof"
DOWN_HOFS = "down_segment_hofs"
CORE_IOF = "core_segment_iof"
CORE_HOFS = "core_segment_hofs"
UP_UPSTREAM_HOF = "up_segment_upstream_ad"
DOWN_UPSTREAM_HOF = "down_segment_upstream_ad"
UP_PEERING_HOF = "up_segment_peering_link"
DOWN_PEERING_HOF = "down_segment_peering_link"


class PathBase(HeaderBase, metaclass=ABCMeta):
    """
    Base class for paths in SCION.

    A path is a sequence of path segments dependent on the type of path. Path
    segments themselves are a sequence of :any:`OpaqueField`\s
    containing routing information for each AS-level hop.
    """
    OF_ORDER = None
    REVERSE_IOF_MAP = {UP_IOF: DOWN_IOF, DOWN_IOF: UP_IOF}

    def __init__(self, raw=None):
        """
        :param bytes raw: Raw path to parse.
        """
        self._iof_idx = None
        self._hof_idx = None
        self._ofs = OpaqueFieldList(self.OF_ORDER)
        self.interfaces = []
        self.mtu = 0
        if raw is not None:
            self._parse(raw)

    @abstractmethod
    def from_values(self, *args, **kwargs):
        raise NotImplementedError

    def _set_ofs(self, label, value):
        """
        Set an OF label to the given value.

        :param str label: The OF label.
        :param value:
            Can be ``None``, a single :any:`OpaqueField`, or a list of
            :any:`OpaqueField`\s.
        """
        if value is None:
            data = []
        elif isinstance(value, list):
            data = value
        else:
            data = [value]
        self._ofs.set(label, data)

    def _parse_iof(self, data, label):
        """
        Parse a raw :any:`InfoOpaqueField`.

        :param Raw data: Raw instance.
        :param str label: OF label.
        :returns: Number of hops in the path segment.
        :rtype: int
        """
        iof = InfoOpaqueField(data.pop(InfoOpaqueField.LEN))
        self._ofs.set(label, [iof])
        return iof.hops

    def _parse_hofs(self, data, label, count=1):
        """
        Parse raw :any:`HopOpaqueFields`\s.

        :param Raw data: Raw instance.
        :param str label: OF label.
        :param int count: Number of HOFs to parse.
        """
        hofs = []
        for _ in range(count):
            hofs.append(HopOpaqueField(data.pop(HopOpaqueField.LEN)))
        self._ofs.set(label, hofs)

    def pack(self):
        raw = self._ofs.pack()
        assert len(raw) == len(self)
        return raw

    def reverse(self):
        """
        Reverse the direction of the path.
        """
        iof_label = self._ofs.get_label_by_idx(self._iof_idx)
        # Swap down segment and up segment.
        self._ofs.swap(UP_HOFS, DOWN_HOFS)
        self._ofs.swap(UP_IOF, DOWN_IOF)
        # Reverse IOF flags.
        self._ofs.reverse_up_flag(UP_IOF)
        self._ofs.reverse_up_flag(DOWN_IOF)
        # Reverse HOF lists.
        self._ofs.reverse_label(UP_HOFS)
        self._ofs.reverse_label(DOWN_HOFS)
        # Update indices.
        # iof_idx needs to be updated depending on the current path-segment.
        # If in up-segment -> the reversed IOF must be in down-segment.
        # If in core-segment -> the reversed IOF must be in core-segment.
        # If in down-segment -> the reversed IOF must be in up-segment.
        self.set_of_idxs(
            self._ofs.get_idx_by_label(self.REVERSE_IOF_MAP[iof_label]),
            len(self._ofs) - self._hof_idx)

    def get_of_idxs(self):
        """
        Get current :any:`InfoOpaqueField` and :any:`HopOpaqueField` indexes.

        :return: Tuple (int, int) of IOF index and HOF index, respectively.
        """
        return self._iof_idx, self._hof_idx

    def set_of_idxs(self, iof_idx=None, hof_idx=None):
        """
        Set current :any:`InfoOpaqueField` and :any:`HopOpaqueField` indexes.

        :param int iof_idx:
            IOF index to set, or ``None`` to use the first IOF index in the
            path.
        :param int hof_idx:
            HOF index to set, or ``None`` to use the first HOF index in the
            path.
        """
        self._iof_idx = iof_idx or self._get_first_iof_idx()
        self._hof_idx = hof_idx or self._get_first_hof_idx()

    def get_iof(self):
        """
        Get current :any:`InfoOpaqueField`.
        """
        if self._iof_idx is None:
            return None
        return self._get_of(self._iof_idx)

    def get_hof(self):
        """
        Get current :any:`HopOpaqueField`.
        """
        if self._hof_idx is None:
            return None
        return self._get_of(self._hof_idx)

    def inc_hof_idx(self):
        """
        Increment the current HOF index by 1.
        """
        self._hof_idx += 1

    def next_segment(self):
        """
        Advance the IOF and HOF indexes to the next path segment.
        """
        iof_offset, hof_offset = self.SEGMENT_OFFSETS
        self._iof_idx = self._hof_idx + iof_offset
        self._hof_idx += hof_offset

    def _get_of(self, idx):
        """
        Returns the :any:`OpaqueField` at the given index.
        """
        return self._ofs.get_by_idx(idx)

    def _get_first_iof_idx(self):
        """
        Returns index of the first :any:`InfoOpaqueField` in the path.
        """
        if len(self._ofs):
            return 0
        return None

    def _get_first_hof_idx(self):  # pragma: no cover
        """
        Returns index of the first :any:`HopOpaqueField` in the path.
        """
        for l in UP_HOFS, CORE_HOFS, DOWN_HOFS:
            if self._ofs.get_by_label(l):
                return 1
        return None

    def get_ofs_by_label(self, label):
        """
        Return all :any:`OpaqueField`\s for a given label.

        :param str label: OF label.
        """
        return self._ofs.get_by_label(label)

    def get_hof_ver(self):
        """
        Return the :any:`HopOpaqueField` needed to verify the current HOF.
        """
        iof = self.get_iof()
        if iof.up_flag:
            return self._get_of(self._hof_idx + 1)
        return self._get_of(self._hof_idx - 1)

    def get_fwd_if(self):
        """
        Return the interface to forward the current packet to.
        """
        iof = self.get_iof()
        hof = self.get_hof()
        if iof.up_flag:
            return hof.ingress_if
        return hof.egress_if

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

    def is_last_path_hof(self):
        """
        Return ``True`` if the current opaque field is the last opaque field,
        ``False`` otherwise.
        """
        return self._hof_idx == len(self._ofs) - 1

    @abstractmethod
    def get_as_hops(self):
        """
        Return path length in AS hops.
        """
        raise NotImplementedError

    def __len__(self):
        """
        Return the path length in bytes.
        """
        return len(self._ofs) * OpaqueField.LEN

    @abstractmethod
    def __str__(self):
        raise NotImplementedError


class CorePath(PathBase):
    """
    A (non-shortcut) path through the ISD core.

    The sequence of :any:`OpaqueField`\s for such a path is:

    | info OF up-segment | hop OF 1 | ... | hop OF N
    | info OF core-segment | hop OF 1 | ... | hop OF N
    | info OF down-segment | hop OF 1 | ... | hop OF N
    """
    NAME = "CorePath"
    OF_ORDER = UP_IOF, UP_HOFS, CORE_IOF, CORE_HOFS, DOWN_IOF, DOWN_HOFS
    REVERSE_IOF_MAP = {UP_IOF: DOWN_IOF, DOWN_IOF: UP_IOF, CORE_IOF: CORE_IOF}
    SEGMENT_OFFSETS = 1, 2

    @classmethod
    def from_values(cls, up_iof=None, up_hofs=None, core_iof=None,
                    core_hofs=None, down_iof=None, down_hofs=None):
        """
        Constructs a :any:`CorePath` with the values specified.

        :param up_iof: :any:`InfoOpaqueField` of up_segment
        :param up_hofs: list of :any:`HopOpaqueField`\s of up_segment
        :param core_iof: :any:`InfoOpaqueField` for core_segment
        :param core_hofs: list of :any:`HopOpaqueField`\s of core_segment
        :param down_iof: :any:`InfoOpaqueField` of down_segment
        :param down_hofs: list of :any:`HopOpaqueField`\s of down_segment
        """
        cp = cls()
        cp._set_ofs(UP_IOF, up_iof)
        cp._set_ofs(UP_HOFS, up_hofs)
        cp._set_ofs(CORE_IOF, core_iof)
        cp._set_ofs(CORE_HOFS, core_hofs)
        cp._set_ofs(DOWN_IOF, down_iof)
        cp._set_ofs(DOWN_HOFS, down_hofs)
        cp.set_of_idxs()
        return cp

    def _parse(self, raw):
        """
        Parse a raw :any:`CorePath`.
        """
        data = Raw(raw, self.NAME)
        # Parse up-segment
        count = self._parse_iof(data, UP_IOF)
        self._parse_hofs(data, UP_HOFS, count)
        # Parse core-segment
        if len(data) > 0:
            count = self._parse_iof(data, CORE_IOF)
            self._parse_hofs(data, CORE_HOFS, count)
        # Parse down-segment
        if len(data) > 0:
            count = self._parse_iof(data, DOWN_IOF)
            self._parse_hofs(data, DOWN_HOFS, count)
        self.set_of_idxs()

    def reverse(self):
        """
        Reverse the direction of the path.
        """
        super().reverse()
        self._ofs.reverse_up_flag(CORE_IOF)
        self._ofs.reverse_label(CORE_HOFS)
        # Handle the case when reverse happens at cross-over point.
        if ((self._ofs.count(UP_HOFS) and
                self.get_hof() == self._ofs.get_by_label(UP_HOFS, -1)) or
            (self._ofs.count(CORE_HOFS) and
                self.get_hof() == self._ofs.get_by_label(CORE_HOFS, -1))):
            self.next_segment()

    def get_hof_ver(self, ingress=True):
        """
        Return the :any:`HopOpaqueField` needed to verify the current HOF.
        """
        hof = self.get_hof()
        if hof.info == OFT.NORMAL_OF:
            return super().get_hof_ver()
        iof = self.get_iof()
        if not (ingress ^ iof.up_flag):
            # Ingress and up, or egress and down
            return None
        elif ingress:
            # Ingress and down
            return self._get_of(self._hof_idx - 1)
        else:
            # Egress and up
            return self._get_of(self._hof_idx + 1)

    def get_as_hops(self):
        """
        Get the path length in AS hops.
        """
        total = 0
        active_segments = 0
        for i in UP_HOFS, CORE_HOFS, DOWN_HOFS:
            count = self._ofs.count(i)
            total += count
            if count:
                active_segments += 1
        if active_segments:
            total -= active_segments - 1
        return total

    def __str__(self):
        s = []
        s.append("<Core-Path>")

        for name, iof_label, hofs_label in (
            ("Up", UP_IOF, UP_HOFS),
            ("Core", CORE_IOF, CORE_HOFS),
            ("Down", DOWN_IOF, DOWN_HOFS),
        ):
            iof = self._ofs.get_by_label(iof_label)
            if not iof:
                continue
            s.append("  <%s-Segment>" % name)
            s.append("    %s" % iof[0])
            for of in self._ofs.get_by_label(hofs_label):
                s.append("    %s" % of)
            s.append("  </%s-Segment>" % name)
        s.append("</Core-Path>")
        return "\n".join(s)


class CrossOverPath(PathBase):
    """
    A shortcut path using a cross-over link.

    The sequence of opaque fields for such a path is:

    | info OF up-segment |  hop OF 1 | ... | hop OF N | upstream AS OF
    | info OF down-segment | upstream AS OF | hop OF 1 | ... | hop OF N

    The upstream AS OF is needed to verify the last hop of the up-segment /
    first hop of the down-segment respectively.

    On-path case (e.g., destination is on up/down-segment) is a special case
    handled by this class. Then one segment (down- or up-segment depending
    whether destination is upstream or downstream AS) is used only for MAC
    verification and for determination whether path can terminate at destination
    AS (i.e., its last egress interface has to equal 0).
    """
    NAME = "CrossOverPath"
    OF_ORDER = (UP_IOF, UP_HOFS, UP_UPSTREAM_HOF,
                DOWN_IOF, DOWN_UPSTREAM_HOF, DOWN_HOFS)
    SEGMENT_OFFSETS = 2, 4

    @classmethod
    def from_values(cls, up_iof=None, up_hofs=None, up_upstream_hof=None,
                    down_iof=None, down_upstream_hof=None, down_hofs=None):
        """
        Constructs a :any:`CrossOverPath` with the values specified.

        :param up_iof: :any:`InfoOpaqueField` of up_segment
        :param up_hofs: list of :any:`HopOpaqueField`\s of up_segment
        :param up_upstream_hof: Upstream :any:`HopOpaqueField` of up_segment
        :param down_iof: :any:`InfoOpaqueField` of down_segment
        :param down_upstream_hof: Upstream :any:`HopOpaqueField` of down_segment
        :param down_hofs: list of :any:`HopOpaqueField` of down_segment
        """
        cp = cls()
        cp._set_ofs(UP_IOF, up_iof)
        cp._set_ofs(UP_HOFS, up_hofs)
        cp._set_ofs(UP_UPSTREAM_HOF, up_upstream_hof)
        cp._set_ofs(DOWN_IOF, down_iof)
        cp._set_ofs(DOWN_UPSTREAM_HOF, down_upstream_hof)
        cp._set_ofs(DOWN_HOFS, down_hofs)
        cp.set_of_idxs()
        return cp

    def _parse(self, raw):
        """
        Parses a raw :any:`CrossOverPath`.
        """
        data = Raw(raw, self.NAME)
        # Parse up-segment
        count = self._parse_iof(data, UP_IOF)
        self._parse_hofs(data, UP_HOFS, count)
        self._parse_hofs(data, UP_UPSTREAM_HOF)
        # Parse down-segment
        count = self._parse_iof(data, DOWN_IOF)
        self._parse_hofs(data, DOWN_UPSTREAM_HOF)
        self._parse_hofs(data, DOWN_HOFS, count)
        self.set_of_idxs()

    def reverse(self):
        """
        Reverse the direction of the path.
        """
        # Reverse hops and info fields.
        super().reverse()
        # Reverse upstream AS fields.
        self._ofs.swap(UP_UPSTREAM_HOF, DOWN_UPSTREAM_HOF)
        # Handle on-path case.
        if (self._ofs.count(UP_HOFS) == 1 and
                self._hof_idx == self._ofs.get_idx_by_label(UP_HOFS)):
            self._iof_idx = self._ofs.get_idx_by_label(DOWN_IOF)
            self._hof_idx = self._iof_idx + 2
            self.set_downpath()
            assert self._hof_idx == self._ofs.get_idx_by_label(DOWN_HOFS)

    def _get_first_hof_idx(self):
        """
        Returns index of the first :any:`HopOpaqueField` in the path that's used
        for routing.
        """
        up_hofs_len = self._ofs.count(UP_HOFS)
        if up_hofs_len:
            # Check whether this is on-path case.
            if up_hofs_len == 1:
                # Return index of the first HopOpaqueField in the down segment
                # that's used for routing (not for only MAC verification)
                # UP_IOF + 1 UP_HOFS + UP_UPSTREAM_HOF + DOWN_IOF +
                # DOWN_UPSTREAM_HOF = 5
                return 5
            return 1
        elif self._ofs.count(DOWN_HOFS):
            return 1
        return super()._get_first_hof_idx()

    def _get_first_iof_idx(self):
        """
        Returns index of the first :any:`InfoOpaqueField` in the path, handling
        the on-path case.
        """
        if self._ofs.count(UP_HOFS) == 1:
            # If up_segment is used only for MAC verification (on-path case),
            # then return index of first InfoOpaqueField of down_segment.
            # UP_IOF + 1 UP_HOFS + UP_UPSTREAM_HOF = 3
            return 3
        return super()._get_first_iof_idx()

    def get_hof_ver(self, ingress=True):
        hof = self.get_hof()
        if hof.info == OFT.NORMAL_OF:
            return super().get_hof_ver()
        iof = self.get_iof()
        ingress_up = {
            (True, True): 1, (True, False): -1,
            (False, False): -1,
        }
        return self._get_of(self._hof_idx + ingress_up[ingress, iof.up_flag])

    def get_as_hops(self):
        """
        Return path length in AS hops.
        """
        return self._ofs.count(UP_HOFS) + self._ofs.count(DOWN_HOFS) - 1

    def __str__(self):
        s = ["<CrossOver-Path>", "  <Up-Segment>"]
        s.append("    %s" % self._ofs.get_by_label(UP_IOF, 0))
        for hof in self._ofs.get_by_label(UP_HOFS):
            s.append("    %s" % str(hof))
        s.append("    Upstream AS: %s" %
                 self._ofs.get_by_label(UP_UPSTREAM_HOF, 0))
        s.extend(["  </Up-Segment>", "  <Down-Segment>"])
        s.append("    %s" % (self._ofs.get_by_label(DOWN_IOF, 0)))
        s.append("    Upstream AS: %s" %
                 self._ofs.get_by_label(DOWN_UPSTREAM_HOF, 0))
        for hof in self._ofs.get_by_label(DOWN_HOFS):
            s.append("    %s" % str(hof))
        s.extend(["  </Down-Segment>", "</CrossOver-Path>"])
        return "\n".join(s)


class PeerPath(PathBase):
    """
    A shortcut path using a peering link.

    The sequence of :any:`OpaqueField`\s for such a path is:

    | info OF up-segment |  hop OF 1 | ... | hop OF N | peering link OF
    | upstream AS OF | info OF down-segment | upstream AS OF
    | peering link OF | hop OF 1 | ... | hop OF N

    The upstream AS OF is needed to verify the last hop of the up-segment /
    first hop of the down-segment respectively.
    """
    NAME = "PeerPath"
    OF_ORDER = (UP_IOF, UP_HOFS, UP_PEERING_HOF, UP_UPSTREAM_HOF,
                DOWN_IOF, DOWN_UPSTREAM_HOF, DOWN_PEERING_HOF, DOWN_HOFS)
    SEGMENT_OFFSETS = 2, 4

    @classmethod
    def from_values(cls, up_iof=None, up_hofs=None, up_peering_hof=None,
                    up_upstream_hof=None, down_iof=None, down_upstream_hof=None,
                    down_peering_hof=None, down_hofs=None):
        """
        Constructs a :any:`PeerPath` with the values specified.

        :param up_iof: :any:`InfoOpaqueField` of up_segment
        :param up_hofs: list of :any:`HopOpaqueField`\s of up_segment
        :param up_peering_hof: Peering :any:`HopOpaqueField` of up_segment
        :param up_upstream_hof: Upstream :any:`HopOpaqueField` of up_segment
        :param down_iof: :any:`InfoOpaqueField` of down_segment
        :param down_upstream_hof: Upstream :any:`HopOpaqueField` of down_segment
        :param down_peering_hof: Peering :any:`HopOpaqueField` of down_segment
        :param down_hofs: list of :any:`HopOpaqueField` of down_segment
        """
        cp = cls()
        cp._set_ofs(UP_IOF, up_iof)
        cp._set_ofs(UP_HOFS, up_hofs)
        cp._set_ofs(UP_PEERING_HOF, up_peering_hof)
        cp._set_ofs(UP_UPSTREAM_HOF, up_upstream_hof)
        cp._set_ofs(DOWN_IOF, down_iof)
        cp._set_ofs(DOWN_UPSTREAM_HOF, down_upstream_hof)
        cp._set_ofs(DOWN_PEERING_HOF, down_peering_hof)
        cp._set_ofs(DOWN_HOFS, down_hofs)
        cp.set_of_idxs()
        return cp

    def _parse(self, raw):
        """
        Parse a raw :any:`PeerPath`.
        """
        data = Raw(raw, self.NAME)
        # Parse up-segment
        count = self._parse_iof(data, UP_IOF)
        self._parse_hofs(data, UP_HOFS, count)
        self._parse_hofs(data, UP_PEERING_HOF)
        self._parse_hofs(data, UP_UPSTREAM_HOF)
        # Parse down-segment
        count = self._parse_iof(data, DOWN_IOF)
        self._parse_hofs(data, DOWN_UPSTREAM_HOF)
        self._parse_hofs(data, DOWN_PEERING_HOF)
        self._parse_hofs(data, DOWN_HOFS, count)
        self.set_of_idxs()

    def reverse(self):
        """
        Reverse the direction of the path.
        """
        # Reverse hop and info fields.
        super().reverse()
        # Reverse upstream AS and peering link fields.
        self._ofs.swap(UP_UPSTREAM_HOF, DOWN_UPSTREAM_HOF)
        self._ofs.swap(UP_PEERING_HOF, DOWN_PEERING_HOF)
        # Handle case when reverse happens at peering point.
        if self.get_hof() == self._ofs.get_by_label(UP_HOFS, -1):
            self.inc_hof_idx()
            assert self._hof_idx == self._ofs.get_idx_by_label(UP_PEERING_HOF)

    def get_hof_ver(self, ingress=True):
        hof = self.get_hof()
        if hof.info == OFT.NORMAL_OF:
            return super().get_hof_ver()
        iof = self.get_iof()
        ingress_up = {
            (True, True): 2, (True, False): 1,
            (False, True): -1, (False, False): -2,
        }
        return self._get_of(self._hof_idx + ingress_up[ingress, iof.up_flag])

    def _get_first_hof_idx(self):
        """
        Returns index of the first :any:`HopOpaqueField` in the path that's used
        for routing.
        """
        hofs = self._ofs.get_by_label(UP_HOFS)
        if not hofs:
            hofs = self._ofs.get_by_label(DOWN_HOFS)
        if not hofs:
            return super()._get_first_hof_idx()
        if hofs[0].info == OFT.XOVR_POINT:
            # Skip to peering link hof
            return 2
        return 1

    def get_as_hops(self):
        """
        Return path length in AS hops.
        """
        return self._ofs.count(UP_HOFS) + self._ofs.count(DOWN_HOFS) - 1

    def __str__(self):
        s = ["<Peer-Path>", "  <Up-Segment>"]
        s.append("    %s" % self._ofs.get_by_label(UP_IOF, 0))
        for hof in self._ofs.get_by_label(UP_HOFS):
            s.append("    %s" % str(hof))
        s.append("    Peering link: %s" %
                 self._ofs.get_by_label(UP_PEERING_HOF, 0))
        s.append("    Upstream AS: %s" %
                 self._ofs.get_by_label(UP_UPSTREAM_HOF, 0))
        s.extend(["  </Up-Segment>", "  <Down-Segment>"])
        s.append("    %s" % self._ofs.get_by_label(DOWN_IOF, 0))
        s.append("    Upstream AS: %s" %
                 self._ofs.get_by_label(DOWN_UPSTREAM_HOF, 0))
        s.append("    Peering link: %s" %
                 self._ofs.get_by_label(DOWN_PEERING_HOF, 0))
        for hof in self._ofs.get_by_label(DOWN_HOFS):
            s.append("    %s" % str(hof))
        s.extend(["  </Down-Segment>", "</Peer-Path>"])
        return "\n".join(s)


class EmptyPath(PathBase):  # pragma: no cover
    """
    Represents an empty path.

    This is currently needed for intra AS communication, which doesn't need a
    SCION path but still uses SCION packets for communication.
    """
    OF_ORDER = []
    SEGMENT_OFFSETS = 0, 0

    def __init__(self):
        super().__init__()
        self._iof_idx = 0
        self._hof_idx = 0

    def from_values(self, *args, **kwargs):
        raise NotImplementedError

    def get_hof(self):
        return None

    def _parse(self, raw):
        raise NotImplementedError

    def reverse(self):
        pass

    def _get_first_iof_idx(self):
        return 0

    def _get_first_hof_idx(self):
        return 0

    def get_as_hops(self):
        return 0

    def get_fwd_if(self):
        return 0

    def __str__(self):
        return "<Empty-Path></Empty-Path>"


def valid_mtu(mtu):
    """
    Check validity of mtu value
    We assume any SCION AS supports at least the IPv6 min MTU
    """
    return mtu and mtu >= SCION_MIN_MTU


def min_mtu(*candidates):
    """
    Return minimum of n mtu values, checking for validity
    """
    return min(filter(valid_mtu, candidates), default=0)


class PathCombinator(object):
    """
    Class that contains functions required to build end-to-end SCION paths.
    """
    @classmethod
    def build_shortcut_paths(cls, up_segments, down_segments):
        """
        Returns a list of all shortcut paths (peering and crossover paths) that
        can be built using the provided up- and down-segments.

        :param list up_segments: List of `up` :any:`PathSegment`\s.
        :param list down_segments: List of `down` :any:`PathSegment`\s.
        :returns: List of :any:`PathBase`\s.
        """
        paths = []
        for up in up_segments:
            for down in down_segments:
                path = cls._build_shortcut_path(up, down)
                if path and path not in paths:
                    paths.append(path)
        return paths

    @classmethod
    def build_core_paths(cls, up_segment, down_segment, core_segments):
        """
        Returns list of all paths that can be built as combination of the
        supplied segments.

        :param list up_segments: List of `up` :any:`PathSegment`\s
        :param list core_segments: List of `core` :any:`PathSegment`\s
        :param list down_segments: List of `down` :any:`PathSegment`\s
        :returns: List of :any:`PathBase`\s.
        """
        paths = []
        path = cls._build_core_path(up_segment, [], down_segment)
        if path:
            paths.append(path)
        if core_segments:
            for core_segment in core_segments:
                path = cls._build_core_path(up_segment, core_segment,
                                            down_segment)
                if path and path not in paths:
                    paths.append(path)
        return paths

    @classmethod
    def _build_shortcut_path(cls, up_segment, down_segment):
        """
        Takes :any:`PathSegment`\s and tries to combine them into short path via
        any cross-over or peer links found.

        :param list up_segment: `up` :any:`PathSegment`.
        :param list down_segment: `down` :any:`PathSegment`.
        :returns:
            :any:`PathBase` if a shortcut path is found, otherwise ``None``.
        """
        # TODO check if stub ASs are the same...
        if (not up_segment or not down_segment or
                not up_segment.ases or not down_segment.ases):
            return None

        # looking for xovr and peer points
        xovr, peer = cls._get_xovr_peer(up_segment, down_segment)

        if not xovr and not peer:
            return None

        def _sum_pt(pt):
            if pt is None:
                return 0
            return sum(pt)

        if _sum_pt(peer) > _sum_pt(xovr):
            # Peer is best.
            return cls._join_shortcuts(up_segment, down_segment, peer, True)
        else:
            # Xovr is best
            return cls._join_shortcuts(up_segment, down_segment, xovr, False)

    @classmethod
    def _build_core_path(cls, up_segment, core_segment, down_segment):
        """
        Joins the supplied segments into a core fullpath.

        :param list up_segment: `up` :any:`PathSegment`.
        :param list core_segment:
            `core` :any:`PathSegment` (must have down-segment orientation), or
            ``None``.
        :param list down_segment: `down` :any:`PathSegment`.
        :returns:
            :any:`CorePath` if a core path is found, otherwise ``None``.
        """
        if (not up_segment or not down_segment or
                not up_segment.ases or not down_segment.ases):
            return None

        if not cls._check_connected(up_segment, core_segment, down_segment):
            return None

        up_iof, up_hofs, up_mtu = cls._copy_segment(up_segment, [-1])
        core_iof, core_hofs, core_mtu = cls._copy_segment(core_segment, [-1, 0])
        down_iof, down_hofs, down_mtu = cls._copy_segment(
            down_segment, [0], up=False)
        path = CorePath.from_values(up_iof, up_hofs, core_iof, core_hofs,
                                    down_iof, down_hofs)
        path.mtu = min_mtu(up_mtu, core_mtu, down_mtu)
        up_core = list(reversed(up_segment.ases))
        if core_segment:
            up_core += list(reversed(core_segment.ases))
        cls._add_interfaces(path, up_core)
        cls._add_interfaces(path, down_segment.ases, up=False)
        return path

    @classmethod
    def _add_interfaces(cls, path, segment_ases, up=True):
        """
        Add interface IDs of segment_ases to path. Order of IDs depends on up
        flag.
        """
        for block in segment_ases:
            isd_as = block.pcbm.isd_as
            egress = block.pcbm.hof.egress_if
            ingress = block.pcbm.hof.ingress_if
            if up:
                if egress:
                    path.interfaces.append((isd_as, egress))
                if ingress:
                    path.interfaces.append((isd_as, ingress))
            else:
                if ingress:
                    path.interfaces.append((isd_as, ingress))
                if egress:
                    path.interfaces.append((isd_as, egress))

    @classmethod
    def _copy_segment(cls, segment, xovrs, up=True):
        """
        Copy a :any:`PathSegment`, setting the up flag, the crossover point
        flag, and optionally reversing the hops.

        :param segment: :any:`PathSegment` to copy.
        :param list xovrs: List of OF indexes to set as cross-over points.
        :param bool up: Should the path direction be set to up?
        :returns:
            Tuple of the new :any:`InfoOpaqueField`, and a list of
            :any:`HopOpaqueField'\s.
        :rtype: tuple
        """
        if not segment:
            return None, None, None
        iof = copy.deepcopy(segment.iof)
        iof.up_flag = up
        hofs, mtu = cls._copy_hofs(segment.ases, reverse=up)
        for xovr in xovrs:
            hofs[xovr].info = OFT.XOVR_POINT
        return iof, hofs, mtu

    @classmethod
    def _get_xovr_peer(cls, up_segment, down_segment):
        """
        Find the shortest xovr (preferred) and peer points between the supplied
        segments.

        *Note*: 'shortest' is calculated by looking for the point that's
        furthest from the core.

        :param list up_segment: `up` :any:`PathSegment`.
        :param list down_segment: `down` :any:`PathSegment`.
        :returns:
            Tuple of the shortest xovr and peer points.
        """
        xovrs = []
        peers = []
        for up_i, up_as in enumerate(up_segment.ases[1:], 1):
            for down_i, down_as in enumerate(down_segment.ases[1:], 1):
                if up_as.pcbm.isd_as == down_as.pcbm.isd_as:
                    xovrs.append((up_i, down_i))
                    continue
                for up_peer in up_as.pms:
                    for down_peer in down_as.pms:
                        if (up_peer.isd_as == down_as.pcbm.isd_as and
                                down_peer.isd_as == up_as.pcbm.isd_as):
                            peers.append((up_i, down_i))
        xovr = peer = None
        if xovrs:
            xovr = max(xovrs, key=lambda tup: sum(tup))
        if peers:
            peer = max(peers, key=lambda tup: sum(tup))
        return xovr, peer

    @classmethod
    def _join_shortcuts(cls, up_segment, down_segment, point, peer=True):
        """
        Joins the supplied segments into a shortcut fullpath.

        :param list up_segment: `up` :any:`PathSegment`.
        :param list down_segment: `down` :any:`PathSegment`.
        :param tuple point: Indexes of peer/xovr point.
        :param bool peer:
            ``True`` if the shortcut uses a peering link, ``False`` if it uses a
            cross-over link
        :returns:
            :any:`PeerPath` if using a peering link, otherwise
            :any:`CrossOverPath`.
        """
        (up_index, down_index) = point

        up_iof, up_hofs, up_upstream_hof, up_mtu = \
            cls._copy_segment_shortcut(up_segment, up_index)
        down_iof, down_hofs, down_upstream_hof, down_mtu = \
            cls._copy_segment_shortcut(down_segment, down_index, up=False)

        up_peering_hof = None
        down_peering_hof = None
        path = None
        if not peer:
            # It's a cross-over path.
            up_iof.info = down_iof.info = OFT.SHORTCUT
            path = CrossOverPath.from_values(
                up_iof, up_hofs, up_upstream_hof, down_iof, down_upstream_hof,
                down_hofs)
        else:
            # It's a peer path.
            if up_segment.get_isd() == down_segment.get_isd():
                up_iof.info = down_iof.info = OFT.INTRA_ISD_PEER
            else:
                up_iof.info = down_iof.info = OFT.INTER_ISD_PEER

            up_peering_hof, down_peering_hof = cls._join_shortcuts_peer(
                up_segment.ases[up_index], down_segment.ases[down_index])
            path = PeerPath.from_values(
                up_iof, up_hofs, up_peering_hof, up_upstream_hof, down_iof,
                down_upstream_hof, down_peering_hof, down_hofs)
        for i in reversed(range(up_index, len(up_segment.ases))):
            pcbm = up_segment.ases[i].pcbm
            egress = pcbm.hof.egress_if
            ingress = pcbm.hof.ingress_if
            if egress:
                path.interfaces.append((pcbm.isd_as, egress))
            if i != up_index:
                path.interfaces.append((pcbm.isd_as, ingress))
        if peer:
            up_pcbm = up_segment.ases[up_index].pcbm
            down_pcbm = down_segment.ases[down_index].pcbm
            path.interfaces.append((up_pcbm.isd_as, up_peering_hof.ingress_if))
            path.interfaces.append((
                down_pcbm.isd_as, down_peering_hof.ingress_if))
        for i in range(down_index, len(down_segment.ases)):
            pcbm = down_segment.ases[i].pcbm
            egress = pcbm.hof.egress_if
            ingress = pcbm.hof.ingress_if
            if i != down_index:
                path.interfaces.append((pcbm.isd_as, ingress))
            if egress:
                path.interfaces.append((pcbm.isd_as, egress))
        path.mtu = min_mtu(up_mtu, down_mtu)
        return path

    @classmethod
    def _check_connected(cls, up_segment, core_segment, down_segment):
        """
        Check if the supplied segments are connected in sequence. If the `core`
        segment is not specified, it is ignored.
        """
        up_first_ia = up_segment.get_first_pcbm().isd_as
        down_first_ia = down_segment.get_first_pcbm().isd_as
        if core_segment:
            core_first_ia = core_segment.get_first_pcbm().isd_as
            core_last_ia = core_segment.get_last_pcbm().isd_as
            if (core_last_ia != up_first_ia or core_first_ia != down_first_ia):
                return False
        elif up_first_ia != down_first_ia:
            return False
        return True

    @classmethod
    def _copy_hofs(cls, ases, reverse=True):
        """
        Copy :any:`HopOpaqueField`\s, and optionally reverse the result.

        :param list ases: List of :any:`ASMarking` objects.
        :param bool reverse: If ``True``, reverse the list before returning it.
        :returns:
            List of copied :any:`HopOpaqueField`\s.
        """
        hofs = []
        mtu = None
        for block in ases:
            for ext in block.ext:
                if ext.EXT_TYPE == MtuPcbExt.EXT_TYPE:
                    mtu = min_mtu(mtu, ext.mtu)
            hofs.append(copy.deepcopy(block.pcbm.hof))
        if reverse:
            hofs.reverse()
        return hofs, mtu

    @classmethod
    def _copy_segment_shortcut(cls, segment, index, up=True):
        """
        Copy a segment for a path shortcut, extracting the upstream
        :any:`HopOpaqueField`, and setting the `up` flag and HOF types
        appropriately.

        :param PathSegment segment: Segment to copy.
        :param int index: Index at which to start the copy.
        :param bool up:
            ``True`` if the path direction is `up` (which will reverse the
            segment direction), ``False`` otherwise (which will leave the
            segment direction unchanged).
        :returns:
            The copied :any:`InfoOpaqueField`, path :any:`HopOpaqueField`\s and
            Upstream :any:`HopOpaqueField`.
        """
        iof = copy.deepcopy(segment.iof)
        iof.hops -= index
        iof.up_flag = up
        # Copy segment HOFs
        ases = segment.ases[index:]
        hofs, mtu = cls._copy_hofs(ases, reverse=up)
        xovr_idx = -1 if up else 0
        hofs[xovr_idx].info = OFT.XOVR_POINT
        # Extract upstream HOF
        upstream_hof = copy.deepcopy(segment.ases[index - 1].pcbm.hof)
        upstream_hof.info = OFT.NORMAL_OF
        return iof, hofs, upstream_hof, mtu

    @classmethod
    def _join_shortcuts_peer(cls, up_as, down_as):
        """
        Finds the peering :any:`HopOpaqueField` of the shortcut path.
        """
        # FIXME(kormat): Is it possible for there to be multiple matches? Could
        # 2 ASs have >1 peering link to the other?
        for up_peer in up_as.pms:
            for down_peer in down_as.pms:
                if (up_peer.isd_as == down_as.pcbm.isd_as and
                        down_peer.isd_as == up_as.pcbm.isd_as):
                    return up_peer.hof, down_peer.hof

    @classmethod
    def tuples_to_full_paths(cls, tuples):
        """
        For a set of tuples of possible end-to-end path [format is:
        (up_seg, core_seg, down_seg)], return a list of fullpaths.

        """
        # TODO(PSz): eventually this should replace _build_core_paths.
        res = []
        for up_segment, core_segment, down_segment in tuples:
            if not up_segment and not core_segment and not down_segment:
                continue

            up_iof, up_hofs, up_mtu = cls._copy_segment(up_segment, [-1])
            core_iof, core_hofs, core_mtu = cls._copy_segment(core_segment,
                                                              [-1, 0])
            down_iof, down_hofs, down_mtu = cls._copy_segment(down_segment,
                                                              [0], up=False)
            path = CorePath.from_values(up_iof, up_hofs, core_iof, core_hofs,
                                        down_iof, down_hofs)
            path.mtu = min_mtu(up_mtu, core_mtu, down_mtu)
            if up_segment:
                up_core = list(reversed(up_segment.ases))
            else:
                up_core = []
            if core_segment:
                up_core += list(reversed(core_segment.ases))
            cls._add_interfaces(path, up_core)
            if down_segment:
                down_core = down_segment.ases
            else:
                down_core = []
            cls._add_interfaces(path, down_core, up=False)
            res.append(path)
        return res


def parse_path(raw):
    if len(raw) == 0:
        return EmptyPath()
    info = InfoOpaqueField(raw[:InfoOpaqueField.LEN])
    if info.info == OFT.CORE:
        return CorePath(raw)
    elif info.info == OFT.SHORTCUT:
        return CrossOverPath(raw)
    elif info.info in (OFT.INTRA_ISD_PEER, OFT.INTER_ISD_PEER):
        return PeerPath(raw)
    else:
        raise SCIONParseError("Can not parse path in "
                              "packet: Unknown type %x", info.info)
