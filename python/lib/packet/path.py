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
# SCION
from lib.packet.opaque_field import (
    HopOpaqueField,
    InfoOpaqueField,
    OpaqueField,
    OpaqueFieldList,
)
from lib.packet.packet_base import Serializable
from lib.util import Raw


class SCIONPath(Serializable):
    NAME = "SCIONPath"
    A_IOF = "A_segment_iof"
    A_HOFS = "A_segment_hofs"
    B_IOF = "B_segment_iof"
    B_HOFS = "B_segment_hofs"
    C_IOF = "C_segment_iof"
    C_HOFS = "C_segment_hofs"
    OF_ORDER = A_IOF, A_HOFS, B_IOF, B_HOFS, C_IOF, C_HOFS
    IOF_LABELS = A_IOF, B_IOF, C_IOF
    HOF_LABELS = A_HOFS, B_HOFS, C_HOFS

    def __init__(self, raw=None):  # pragma: no cover
        self._ofs = OpaqueFieldList(self.OF_ORDER)
        self._iof_idx = None
        self._hof_idx = None
        super().__init__(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME)
        if data:
            # Parse first segment
            a_iof = self._parse_iof(data, self.A_IOF)
            self._parse_hofs(data, self.A_HOFS, a_iof.hops)
        if data:
            # Parse second segment
            b_iof = self._parse_iof(data, self.B_IOF)
            self._parse_hofs(data, self.B_HOFS, b_iof.hops)
        if data:
            # Parse third segment
            assert not a_iof.shortcut
            c_iof = self._parse_iof(data, self.C_IOF)
            self._parse_hofs(data, self.C_HOFS, c_iof.hops)
        self._init_of_idxs()

    def _parse_iof(self, data, label):
        """
        Parse a raw :any:`InfoOpaqueField`.

        :param Raw data: Raw instance.
        :param str label: OF label.
        """
        iof = InfoOpaqueField(data.pop(InfoOpaqueField.LEN))
        self._ofs.set(label, [iof])
        return iof

    def _parse_hofs(self, data, label, count):
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

    @classmethod
    def from_values(cls, a_iof=None, a_hofs=None, b_iof=None,
                    b_hofs=None, c_iof=None, c_hofs=None):  # pragma: no cover
        inst = cls()
        inst._set_ofs(inst.A_IOF, a_iof)
        inst._set_ofs(inst.A_HOFS, a_hofs)
        inst._set_ofs(inst.B_IOF, b_iof)
        inst._set_ofs(inst.B_HOFS, b_hofs)
        inst._set_ofs(inst.C_IOF, c_iof)
        inst._set_ofs(inst.C_HOFS, c_hofs)
        inst._init_of_idxs()
        return inst

    def pack(self):  # pragma: no cover
        raw = self._ofs.pack()
        assert len(raw) == len(self)
        return raw

    def _set_ofs(self, label, value):
        """
        Set an OF label to the given value.

        :param str label: The OF label.
        :param value:
            Can be ``None``, a single Opaque Field, or a list of Opaque Fields.
        """
        if value is None:
            data = []
        elif isinstance(value, list):
            data = value
        else:
            data = [value]
        self._ofs.set(label, data)

    def _init_of_idxs(self):
        self._iof_idx = 0
        self._hof_idx = 0
        if not len(self._ofs):
            return
        iof = self.get_iof()
        if iof.peer:
            hof = self._ofs.get_by_idx(1)
            if hof.xover:
                self._hof_idx += 1
        self.inc_hof_idx()

    def get_of_idxs(self):  # pragma: no cover
        """
        Get current InfoOpaqueField and HopOpaqueField indexes.

        :return: Tuple (int, int) of IOF index and HOF index, respectively.
        """
        return self._iof_idx, self._hof_idx

    def set_of_idxs(self, iof_idx, hof_idx):  # pragma: no cover
        """Set current InfoOpaqueField and HopOpaqueField indexes."""
        self._iof_idx = iof_idx
        self._hof_idx = hof_idx

    def reverse(self):
        """Reverse the direction of the path."""
        if not len(self._ofs):
            # Empty path doesn't need reversal.
            return
        iof_label = self._ofs.get_label_by_idx(self._iof_idx)
        swap_iof, swap_hof = None, None
        # Determine which IOF/HOFs need to be swapped, if any.
        if self._ofs.count(self.C_IOF):
            swap_iof, swap_hof = self.C_IOF, self.C_HOFS
        elif self._ofs.count(self.B_IOF):
            swap_iof, swap_hof = self.B_IOF, self.B_HOFS
        # Do the swap as needed.
        if swap_iof:
            self._ofs.swap(self.A_IOF, swap_iof)
            self._ofs.swap(self.A_HOFS, swap_hof)
        # Reverse IOF flags.
        for label in self.IOF_LABELS:
            self._ofs.reverse_cons_dir_flag(label)
        # Reverse HOF lists.
        for label in self.HOF_LABELS:
            self._ofs.reverse_label(label)
        # Update IOF index:
        # - (1) For paths with a single segment, just get the index of the
        #   original label.
        # - (2) For paths with 2 segments, get the index of the opposite label.
        # - (3) For paths with 3 segments, if the initial label was at either
        #   end, use (2), otherwise use (1), as the current label didn't get
        #   swapped.
        if swap_iof and iof_label == self.A_IOF:
            iof_idx = self._ofs.get_idx_by_label(swap_iof)
        elif swap_iof and iof_label == swap_iof:
            iof_idx = self._ofs.get_idx_by_label(self.A_IOF)
        else:
            iof_idx = self._ofs.get_idx_by_label(iof_label)
        # Update the HOF index by simply subtracting it from the total number of
        # OFs.
        self.set_of_idxs(iof_idx, len(self._ofs) - self._hof_idx)

    def get_hof_ver(self, ingress=True):
        """Return the :any:`HopOpaqueField` needed to verify the current HOF."""
        iof = self.get_iof()
        hof = self.get_hof()
        if not hof.xover or (iof.shortcut and not iof.peer):
            # For normal hops on any type of segment, or cross-over hops on
            # non-peer shortcut hops, just use next/prev HOF.
            return self._get_hof_ver_normal(iof)
        if iof.peer:
            # Peer shortcut paths have two extra HOFs; 1 for the peering
            # interface, and another from the upstream interface, used for
            # verification only.
            ingress_cons_dir = {(True, False): +2, (True, True): +1,
                                (False, False): -1, (False, True): -2}
        else:
            # Non-peer shortcut paths have an extra HOF above the last hop, used
            # for verification of the last hop in that segment.
            ingress_cons_dir = {(True, False): None, (True, True): -1,
                                (False, False): +1, (False, True): None}
        # Map the local direction of travel and the IOF consDir flag to the required
        # offset of the verification HOF (or None, if there's no relevant HOF).
        offset = ingress_cons_dir[ingress, iof.cons_dir_flag]
        if offset is None:
            return None
        return self._ofs.get_by_idx(self._hof_idx + offset)

    def _get_hof_ver_normal(self, iof):
        # If this is the last hop of an Up path, or the first hop of a Down
        # path, there's no previous HOF to verify against.
        if (not iof.cons_dir_flag and self._hof_idx == self._iof_idx + iof.hops) or (
                iof.cons_dir_flag and self._hof_idx == self._iof_idx + 1):
            return None
        # Otherwise use the next/prev HOF based on the consDir flag.
        offset = -1 if iof.cons_dir_flag else 1
        return self._ofs.get_by_idx(self._hof_idx + offset)

    def get_iof(self):  # pragma: no cover
        """Get current :any:`InfoOpaqueField`."""
        if self._iof_idx is None:
            return None
        return self._ofs.get_by_idx(self._iof_idx)

    def get_hof(self):  # pragma: no cover
        """Get current :any:`HopOpaqueField`."""
        if self._hof_idx is None:
            return None
        return self._ofs.get_by_idx(self._hof_idx)

    def inc_hof_idx(self):
        """
        Increment the HOF idx to next routing HOF.

        Skip VERIFY_ONLY HOFs, as they are not used for routing.
        Also detect when there are no HOFs left in the current segment, and
        switch to the next segment, before restarting.
        """
        iof = self.get_iof()
        skipped_verify_only = False
        while True:
            self._hof_idx += 1
            if (self._hof_idx - self._iof_idx) > iof.hops:
                # Switch to the next segment
                self._iof_idx = self._hof_idx
                iof = self.get_iof()
                # Continue looking for a routing HOF
                continue
            hof = self.get_hof()
            if not hof.verify_only:
                break
            skipped_verify_only = True
        return skipped_verify_only

    def get_fwd_if(self):  # pragma: no cover
        """Return the interface to forward the current packet to."""
        if not len(self._ofs):
            return 0
        iof = self.get_iof()
        hof = self.get_hof()
        if iof.cons_dir_flag:
            return hof.egress_if
        return hof.ingress_if

    def get_curr_if(self, ingress=True):  # pragma: no cover
        """
        Return the current interface, depending on the direction of the
        segment.
        """
        hof = self.get_hof()
        iof = self.get_iof()
        if ingress == iof.cons_dir_flag:
            return hof.ingress_if
        return hof.egress_if

    def get_as_hops(self):
        total = 0
        segs = 0
        peer = False
        for l in self.IOF_LABELS:
            res = self._ofs.get_by_label(l)
            if not res:
                break
            peer |= res[0].peer
            total += self._get_as_hops(res[0])
            segs += 1
        if not peer:
            total -= segs - 1
        return total

    def _get_as_hops(self, iof):  # pragma: no cover
        if not iof.shortcut:
            return iof.hops
        if not iof.peer:
            return iof.hops - 1
        return iof.hops - 2

    def is_on_last_segment(self):  # pragma: no cover
        label = self._ofs.get_label_by_idx(self._hof_idx)
        if label == self.A_HOFS:
            return self._ofs.count(self.B_HOFS) == 0
        elif label == self.B_HOFS:
            return self._ofs.count(self.C_HOFS) == 0
        else:
            return True

    def __len__(self):  # pragma: no cover
        """Return the path length in bytes."""
        return len(self._ofs) * OpaqueField.LEN

    def __str__(self):
        s = []
        s.append("<SCION-Path(%sB)>" % len(self))

        for name, iof_label, hofs_label in (
            ("A", self.A_IOF, self.A_HOFS), ("B", self.B_IOF, self.B_HOFS),
            ("C", self.C_IOF, self.C_HOFS),
        ):
            iof = self._ofs.get_by_label(iof_label)
            if not iof:
                break
            s.append("  <%s-Segment>" % name)
            s.append("    %s" % iof[0])
            for of in self._ofs.get_by_label(hofs_label):
                s.append("    %s" % of)
            s.append("  </%s-Segment>" % name)
        s.append("</SCION-Path>")
        return "\n".join(s)


def parse_path(raw):  # pragma: no cover
    return SCIONPath(raw)
