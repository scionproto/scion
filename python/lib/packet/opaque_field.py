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
:mod:`opaque_field` --- SCION Opaque fields
===========================================
"""
# Stdlib
import struct

# SCION
from lib.crypto.symcrypto import mac
from lib.defines import OPAQUE_FIELD_LEN
from lib.errors import SCIONIndexError, SCIONKeyError
from lib.flagtypes import HopOFFlags, InfoOFFlags
from lib.packet.packet_base import Serializable
from lib.util import Raw, hex_str, iso_timestamp


class OpaqueField(Serializable):
    LEN = OPAQUE_FIELD_LEN

    def __len__(self):  # pragma: no cover
        return self.LEN


class HopOpaqueField(OpaqueField):
    """
    Opaque field for a hop in a path of the SCION packet header.

    Each hop opaque field has a flag field (8 bits), expiration time (8 bits)
    ingress/egress interfaces (2 * 12 bits) and a MAC (24 bits) authenticating
    the opaque field.
    """
    NAME = "HopOpaqueField"
    MAC_LEN = 3  # MAC length in bytes.
    MAC_BLOCK_LEN = 16
    VERIFY_FLAGS = HopOFFlags.FORWARD_ONLY

    def __init__(self, raw=None):  # pragma: no cover
        self.xover = False
        self.verify_only = False
        self.forward_only = False
        self.recurse = False
        self.exp_time = 0
        self.ingress_if = 0
        self.egress_if = 0
        self.mac = bytes(self.MAC_LEN)
        super().__init__(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.LEN)
        flags, self.exp_time = struct.unpack("!BB", data.pop(2))
        self._parse_flags(flags)
        ifs = int.from_bytes(data.pop(3), byteorder="big")
        self.ingress_if = (ifs & 0xFFF000) >> 12
        self.egress_if = ifs & 0x000FFF
        self.mac = data.pop(3)

    def _parse_flags(self, flags):  # pragma: no cover
        self.xover = bool(flags & HopOFFlags.XOVER)
        self.verify_only = bool(flags & HopOFFlags.VERIFY_ONLY)
        self.forward_only = bool(flags & HopOFFlags.FORWARD_ONLY)
        self.recurse = bool(flags & HopOFFlags.RECURSE)

    @classmethod
    def from_values(cls, exp_time, ingress_if=0, egress_if=0,
                    mac=None, xover=False, verify_only=False,
                    forward_only=False, recurse=False):  # pragma: no cover
        inst = cls()
        inst.xover = xover
        inst.verify_only = verify_only
        inst.forward_only = forward_only
        inst.recurse = recurse
        inst.exp_time = exp_time
        inst.ingress_if = ingress_if
        inst.egress_if = egress_if
        inst.mac = mac or bytes(inst.MAC_LEN)
        return inst

    def pack(self, mac=False):
        packed = []
        flags = self._pack_flags()
        if mac:
            flags &= self.VERIFY_FLAGS
        packed.append(struct.pack("!B", flags))
        packed.append(struct.pack("!B", self.exp_time))
        ifs = (self.ingress_if << 12) | self.egress_if
        # Ingress and egress interfaces are packed into three bytes
        packed.append(ifs.to_bytes(3, "big"))
        if not mac:
            packed.append(self.mac)
        return b"".join(packed)

    def _pack_flags(self):  # pragma: no cover
        flags = 0
        if self.xover:
            flags |= HopOFFlags.XOVER
        if self.verify_only:
            flags |= HopOFFlags.VERIFY_ONLY
        if self.forward_only:
            flags |= HopOFFlags.FORWARD_ONLY
        if self.recurse:
            flags |= HopOFFlags.RECURSE
        return flags

    def calc_mac(self, key, ts, prev_hof=None):
        """Generates MAC for newly created OF."""
        raw = bytearray()
        raw += struct.pack("!I", ts)
        raw += self.pack(mac=True)
        if prev_hof:
            raw += prev_hof.pack()[1:]  # Ignore flag byte
        else:
            raw += bytes(self.LEN-1)
        return mac(key, bytes(raw))[:self.MAC_LEN]

    def verify_mac(self, *args, **kwargs):  # pragma: no cover
        return self.mac == self.calc_mac(*args, **kwargs)

    def set_mac(self, *args, **kwargs):  # pragma: no cover
        self.mac = self.calc_mac(*args, **kwargs)

    def __eq__(self, other):  # pragma: no cover
        return (self.exp_time == other.exp_time and
                self.ingress_if == other.ingress_if and
                self.egress_if == other.egress_if and
                self.mac == other.mac)

    def __str__(self):
        flags = self._pack_flags()
        return ("%s(%dB): flags: %s, exp_time: %s, "
                "ingress: %s, egress: %s, mac: %s" %
                (self.NAME, len(self), HopOFFlags.to_str(flags), self.exp_time,
                 self.ingress_if, self.egress_if, hex_str(self.mac)))


class InfoOpaqueField(OpaqueField):
    """
    Class for the info opaque field.

    The info opaque field contains flags of the path-segment (1 byte),
    a creation timestamp (4 bytes), the ISD ID (2 byte) and # hops for this
    segment (1 byte).
    """
    NAME = "InfoOpaqueField"

    def __init__(self, raw=None):  # pragma: no cover
        self.up_flag = False
        self.shortcut = False
        self.peer = False
        self.timestamp = 0
        self.isd = 0
        self.hops = 0
        super().__init__(raw)

    def _parse(self, raw):  # pragma: no cover
        data = Raw(raw, self.NAME, self.LEN)
        flags, self.timestamp, self.isd, self.hops = \
            struct.unpack("!BIHB", data.pop(self.LEN))
        self._parse_flags(flags)

    def _parse_flags(self, flags):  # pragma: no cover
        if flags & InfoOFFlags.UP:
            self.up_flag = True
        if flags & InfoOFFlags.SHORTCUT:
            self.shortcut = True
        if flags & InfoOFFlags.PEER_SHORTCUT:
            self.peer = True
        self._check_flags()

    def _check_flags(self):  # pragma: no cover
        # It's illegal to have the peer flag set without the shortcut flag.
        assert not(not self.shortcut and self.peer)

    @classmethod
    def from_values(cls, timestamp, isd, up_flag=False, shortcut=False,
                    peer=False, hops=0):  # pragma: no cover
        inst = cls()
        inst.up_flag = up_flag
        inst.shortcut = shortcut
        inst.peer = peer
        inst.timestamp = timestamp
        inst.isd = isd
        inst.hops = hops
        inst._check_flags()
        return inst

    def pack(self):  # pragma: no cover
        return struct.pack("!BIHB", self._pack_flags(), self.timestamp,
                           self.isd, self.hops)

    def _pack_flags(self):  # pragma: no cover
        self._check_flags()
        flags = 0
        if self.up_flag:
            flags |= InfoOFFlags.UP
        if self.shortcut:
            flags |= InfoOFFlags.SHORTCUT
        if self.peer:
            flags |= InfoOFFlags.PEER_SHORTCUT
        return flags

    def __str__(self):
        flags = self._pack_flags()
        return ("%s(%sB): flags: %s, TS: %s, ISD: %s, hops: %s" %
                (self.NAME, self.LEN, InfoOFFlags.to_str(flags),
                 iso_timestamp(self.timestamp), self.isd, self.hops))


class OpaqueFieldList(object):
    """
    Encapsulates lists of Opaque Fields (OFs).

    The lists are stored under labels, where each label describes the contents
    of the list. Some label will only ever have 1 entry, such as an up segment
    IOF. Others can have many, such as a down segment HOF list.
    """
    def __init__(self, order):  # pragma: no cover
        """
        :param list order:
            A list of tokens that define the order of the opaque field labels.
            E.g. ``[UP_IOF, UP_HOFS]`` defines that the up-segment info opaque
            field comes before the up-segment hop opaque fields.
        """
        self._order = order
        self._labels = {}
        for label in order:
            self._labels[label] = []

    def set(self, label, ofs):
        """
        Sets an OF label to the supplied value.

        :param str label: OF label to change. E.g. ``UP_IOF``.
        :param list ofs: List of opaque fields to store in the label.
        :raises:
            :any:`SCIONKeyError`: if the label is unknown.
        """
        assert isinstance(ofs, list), type(ofs)
        if label not in self._labels:
            raise SCIONKeyError("Opaque field label (%s) unknown" % label)
        self._labels[label] = ofs

    def get_by_idx(self, idx):
        """
        Get an OF by index. The index follows the order supplied when the
        :class:`OpaqueFieldList` object was created.

        :param int idx: The index to fetch.
        :returns: The OF at that index.
        :rtype: :class:`OpaqueField`
        :raises:
            SCIONIndexError: if the index is negative, or too large.
        """
        if idx < 0:
            raise SCIONIndexError("Requested OF index (%d) is negative" % idx)
        offset = idx
        for label in self._order:
            group = self._labels[label]
            if offset < len(group):
                return group[offset]
            offset -= len(group)
        raise SCIONIndexError("Requested OF index (%d) is out of range (max %d)"
                              % (idx, len(self) - 1))

    def get_by_label(self, label, label_idx=None):
        """
        Get an OF list by label. If a label index is supplied, use that to index
        into the label and return a single OF instead.

        :param str label: The label to fetch. E.g. ``UP_HOFS``.
        :param int label_idx:
            (Optional) an index of an OF in the specified label.
        :returns:
            A list of OFs (or if `label_idx` was specified, a single OF).
        :raises:
            :any:`SCIONKeyError`: if the label is unknown.
            :any:`SCIONIndexError`: if the specified label index is out of range
        """
        try:
            group = self._labels[label]
        except KeyError:
            raise SCIONKeyError("Opaque field label (%s) unknown"
                                % label) from None
        if label_idx is None:
            return group
        try:
            return group[label_idx]
        except IndexError:
            raise SCIONIndexError(
                "Opaque field label index (%d) for label %s out of range" %
                (label_idx, label)) from None

    def get_label_by_idx(self, idx):
        """
        Returns the label to which idx points to.

        :param int idx: The index for which we want to know the label.
        :returns: The label 'idx' points to.
        :raises:
            :any:`SCIONIndexError`: if the index is out of range.
        """
        if idx < 0:
            raise SCIONIndexError("Index for requested label is negative (%d)"
                                  % idx)
        offset = idx
        for label in self._order:
            group = self._labels[label]
            if offset < len(group):
                return label
            offset -= len(group)
        raise SCIONIndexError("Index (%d) for requested label is out of range "
                              "(max %d)" % (idx, len(self) - 1)) from None

    def get_idx_by_label(self, label):
        """
        Returns the index of the first element in the given label.

        :param str label: The label for which we want the start index.
        :raises:
            :any:`SCIONKeyError`: if the label is unknown.
        """
        idx = 0
        for l in self._order:
            if label == l:
                if self._labels[l]:
                    return idx
                else:
                    raise SCIONKeyError("Opaque field label (%s) is empty." %
                                        label) from None
            idx += len(self._labels[l])
        raise SCIONKeyError("Opaque field label (%s) unknown." %
                            label) from None

    def swap(self, label_a, label_b):
        """
        Swap the contents of two labels. The order of the parameters doesn't
        matter.

        :param str label_a: The first label.
        :param str label_b: The second label.
        :raises:
            :any:`SCIONKeyError`: if either label is unknown.
        """
        try:
            self._labels[label_a], self._labels[label_b] = \
                self._labels[label_b], self._labels[label_a]
        except KeyError as e:
            raise SCIONKeyError("Opaque field label (%s) unknown"
                                % e.args[0]) from None

    def reverse_label(self, label):
        """
        Reverse the contents of a label.

        :param str label: The label to reverse.
        :raises:
            :any:`SCIONKeyError`: if the label is unknown.
        """
        try:
            self._labels[label].reverse()
        except KeyError:
            raise SCIONKeyError("Opaque field label (%s) unknown"
                                % label) from None

    def reverse_up_flag(self, label):
        """
        Reverse the Up flag of the first OF in a label, assuming the label isn't
        empty. Used to change direction of IOFs.

        :param str label: The label to modify.
        :raises:
            :any:`SCIONKeyError`: if the label is unknown.
        """
        try:
            group = self._labels[label]
        except KeyError:
            raise SCIONKeyError("Opaque field label (%s) unknown"
                                % label) from None
        if len(group) > 0:
            group[0].up_flag ^= True

    def pack(self):
        """
        Pack all of the OFs into a single bytestring.

        :returns: A bytestring containing all the OFs, in order.
        :rtype: bytes
        """
        ret = []
        for label in self._order:
            for of in self._labels[label]:
                ret.append(of.pack())
        return b"".join(ret)

    def count(self, label):
        """
        Return the number of OFs in a label.

        :param str label: The label to count.
        :returns: The number of OFs in the label.
        :rtype: int
        :raises:
            :any:`SCIONKeyError`: if the label is unknown.
        """
        try:
            return len(self._labels[label])
        except KeyError:
            raise SCIONKeyError("Opaque field label (%s) unknown"
                                % label) from None

    def __len__(self):
        count = 0
        for values in self._labels.values():
            count += len(values)
        return count
