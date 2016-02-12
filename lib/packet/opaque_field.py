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
from abc import ABCMeta, abstractmethod

# SCION
from lib.types import OpaqueFieldType as OFT
from lib.errors import SCIONIndexError, SCIONKeyError
from lib.util import Raw, hex_str, iso_timestamp


class OpaqueField(object, metaclass=ABCMeta):
    """
    Base class for the different kinds of opaque fields in SCION.
    """
    LEN = 8

    def __init__(self):  # pragma: no cover
        """
        Initialize an instance of the class OpaqueField.
        """
        self.info = 0  # TODO verify path.PathType in that context
        self.raw = None

    @abstractmethod
    def parse(self, raw):
        """
        Populates fields from a raw byte block.
        """
        raise NotImplementedError

    @abstractmethod
    def pack(self):
        """
        Returns opaque field as 8 byte binary string.
        """
        raise NotImplementedError

    def is_regular(self):
        """
        Returns true if opaque field is regular, false otherwise.
        """
        return (self.info & (1 << 6) == 0)

    def is_continue(self):
        """
        Returns true if continue bit is set, false otherwise.
        """
        return not (self.info & (1 << 5) == 0)

    def is_xovr(self):
        """
        Returns true if crossover point bit is set, false otherwise.
        """
        return not (self.info & (1 << 4) == 0)

    def __len__(self):  # pragma: no cover
        return self.LEN

    @abstractmethod
    def __str__(self):
        raise NotImplementedError

    def __eq__(self, other):  # pragma: no cover
        if type(other) is not type(self):
            return False
        return self.raw == other.raw

    def __ne__(self, other):  # pragma: no cover
        return not self.__eq__(other)


class HopOpaqueField(OpaqueField):
    """
    Opaque field for a hop in a path of the SCION packet header.

    Each hop opaque field has a info (8 bits), expiration time (8 bits)
    ingress/egress interfaces (2 * 12 bits) and a MAC (24 bits) authenticating
    the opaque field.
    """
    NAME = "HopOpaqueField"
    MAC_LEN = 3  # MAC length in bytes.

    def __init__(self, raw=None):
        """
        Initialize an instance of the class HopOpaqueField.

        :param raw:
        :type raw:
        """
        super().__init__()
        self.exp_time = 0
        self.ingress_if = 0
        self.egress_if = 0
        self.mac = bytes(self.MAC_LEN)
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Populates fields from a raw byte block.
        """
        data = Raw(raw, self.NAME, self.LEN)
        self.raw = raw
        self.info, self.exp_time = struct.unpack("!BB", data.pop(2))
        # A byte added as length of three bytes can't be unpacked
        ifs = struct.unpack("!I", b'\0' + data.pop(3))[0]
        self.mac = data.pop(3)
        self.ingress_if = (ifs & 0xFFF000) >> 12
        self.egress_if = ifs & 0x000FFF

    @classmethod
    def from_values(cls, exp_time, ingress_if=0, egress_if=0, mac=None):
        """
        Returns HopOpaqueField with fields populated from values.

        @param exp_time: Expiry time. An integer in the range [0,255]
        @param ingress_if: Ingress interface.
        @param egress_if: Egress interface.
        @param mac: MAC of ingress/egress interfaces' ID and timestamp.
        """
        hof = cls()
        hof.exp_time = exp_time
        hof.ingress_if = ingress_if
        hof.egress_if = egress_if
        if mac is None:
            mac = b"\x00" * cls.MAC_LEN
        hof.mac = mac
        return hof

    def pack(self):
        """
        Returns HopOpaqueField as 8 byte binary string.
        """
        ifs = (self.ingress_if << 12) | self.egress_if
        data = struct.pack("!BB", self.info, self.exp_time)
        # Ingress and egress interface info is packed into three bytes
        data += struct.pack("!I", ifs)[1:]
        data += self.mac
        return data

    def __eq__(self, other):  # pragma: no cover
        if type(other) is not type(self):
            return False
        return (self.exp_time == other.exp_time and
                self.ingress_if == other.ingress_if and
                self.egress_if == other.egress_if and
                self.mac == other.mac)

    def __str__(self):
        return ("Hop OF info(%dB): %s, exp_time: %d, ingress if: %d, "
                "egress if: %d, mac: %s" %
                (len(self), OFT.to_str(self.info), self.exp_time,
                 self.ingress_if, self.egress_if, hex_str(self.mac)))


class InfoOpaqueField(OpaqueField):
    """
    Class for the info opaque field.

    The info opaque field contains type info of the path-segment (1 byte),
    a creation timestamp (4 bytes), the ISD ID (2 byte) and # hops for this
    segment (1 byte).
    """
    NAME = "InfoOpaqueField"

    def __init__(self, raw=None):  # pragma: no cover
        super().__init__()
        self.timestamp = 0
        self.isd = 0
        self.hops = 0
        self.up_flag = False
        self.raw = raw
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Populates fields from a raw byte block.
        """
        self.raw = raw
        data = Raw(raw, self.NAME, self.LEN)
        self.info, self.timestamp, self.isd, self.hops = \
            struct.unpack("!BIHB", data.pop(self.LEN))
        self.up_flag = bool(self.info & 0b00000001)
        self.info >>= 1

    @classmethod
    def from_values(cls, info=0, up_flag=False, timestamp=0, isd=0, hops=0):
        """
        Returns InfoOpaqueField with fields populated from values.

        @param info: Opaque field type.
        @param up_flag: up/down-flag.
        @param timestamp: Beacon's timestamp.
        @param isd: Isolation Domanin's ID.
        @param hops: Number of hops in the segment.
        """
        iof = InfoOpaqueField()
        iof.info = info
        iof.up_flag = up_flag
        iof.timestamp = timestamp
        iof.isd = isd
        iof.hops = hops
        return iof

    def pack(self):
        """
        Returns InfoOpaqueFIeld as 8 byte binary string.
        """
        info = (self.info << 1) + self.up_flag
        data = struct.pack("!BIHB", info, self.timestamp, self.isd, self.hops)
        return data

    def __eq__(self, other):  # pragma: no cover
        if type(other) is type(self):
            return (self.info == other.info and
                    self.up_flag == other.up_flag and
                    self.timestamp == other.timestamp and
                    self.isd == other.isd and
                    self.hops == other.hops)
        else:
            return False

    def __str__(self):
        return ("[Info OF info(%sB): %s, up: %s, TS: %s, ISD: %s, hops: %s]"
                % (len(self), OFT.to_str(self.info), self.up_flag,
                   iso_timestamp(self.timestamp), self.isd, self.hops))


class OpaqueFieldList(object):
    """
    Encapsulates lists of Opaque Fields (OFs).

    The lists are stored under labels, where each label describes the contents
    of the list. Some label will only ever have 1 entry, such as an up segment
    IOF. Others can have many, such as a down segment HOF list.
    """
    def __init__(self, order):
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
        assert isinstance(ofs, list)
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
