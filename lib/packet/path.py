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

# SCION
from lib.packet.opaque_field import (
    HopOpaqueField,
    InfoOpaqueField,
    OpaqueFieldType,
)


class PathBase(object):
    """
    Base class for paths in SCION.

    A path is a sequence of path segments dependent on the type of path. Path
    segments themselves are a sequence of opaque fields containing routing
    information for each AD-level hop.
    """
    def __init__(self):
        """
        Initialize an instance of the class PathBase.
        """
        self.up_segment_info = None
        self.up_segment_hops = []
        self.down_segment_info = None
        self.down_segment_hops = []

        self.parsed = False

    def parse(self, raw):
        pass

    def pack(self):
        pass

    def reverse(self):
        """
        Reverses the segment.
        """
        # Swap down segment and up segment.
        self.up_segment_hops, self.down_segment_hops = \
            self.down_segment_hops, self.up_segment_hops
        self.up_segment_info, self.down_segment_info = \
            self.down_segment_info, self.up_segment_info
        # Reverse flags.
        if self.up_segment_info is not None:
            self.up_segment_info.up_flag ^= True
        if self.down_segment_info is not None:
            self.down_segment_info.up_flag ^= True
        # Reverse hops.
        self.up_segment_hops.reverse()
        self.down_segment_hops.reverse()

    def get_first_hop_offset(self):
        """
        Returns offset to the first HopOpaqueField of the path.
        """
        if self.up_segment_hops or self.down_segment_hops:
            return InfoOpaqueField.LEN
        else:
            return 0

    def get_first_hop_of(self):
        """
        Returns the first HopOpaqueField of the path.
        """
        offset = self.get_first_hop_offset()
        if offset:
            offset -= InfoOpaqueField.LEN
            n = offset // HopOpaqueField.LEN
            return self.get_of(n + 1)
        else:
            return None

    def get_first_info_offset(self):
        """
        Returns offset to the first InfoOpaqueField of the path.
        """
        return 0

    def get_first_info_of(self):
        """
        Returns the first InfoOpaqueField of the path.
        """
        offset = self.get_first_info_offset()
        if offset:
            offset -= InfoOpaqueField.LEN
            n = offset // HopOpaqueField.LEN
            return self.get_of(n + 1)
        return self.get_of(0)

    def get_of(self, index):
        """
        Returns the opaque field for the given index.
        """
        # Build temporary flat list of opaque fields.
        tmp = []
        if self.up_segment_info:
            tmp.append(self.up_segment_info)
            tmp.extend(self.up_segment_hops)
        if self.down_segment_info:
            tmp.append(self.down_segment_info)
            tmp.extend(self.down_segment_hops)
        if index >= len(tmp):
            return None
        else:
            return tmp[index]

    def __str__(self):
        pass

    def __repr__(self):
        return self.__str__()


class CorePath(PathBase):
    """
    A (non-shortcut) path through the ISD core.

    The sequence of opaque fields for such a path is:
    | info OF up-segment | hop OF 1 | ... | hop OF N | info OF core-segment |
    | hop OF 1 \ ... | hop OF N | info OF down-segment |
    | hop OF 1 | ... | hop OF N |
    """
    def __init__(self, raw=None):
        """
        Initialize an instance of the class CorePath.

        :param raw:
        :type raw:
        """
        PathBase.__init__(self)
        self.core_segment_info = None
        self.core_segment_hops = []

        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Parses the raw data and populates the fields accordingly.
        """
        assert isinstance(raw, bytes)
        # Parse up-segment
        offset = self._parse_up_segment(raw)
        # Parse core-segment
        if len(raw) != offset:
            offset = self._parse_core_segment(raw, offset)
        # Parse down-segment
        if len(raw) != offset:
            self._parse_down_segment(raw, offset)

        self.parsed = True

    def _parse_up_segment(self, raw):
        """
        Parses the raw data and populates the up_segment fields.

        :param raw: bytes
        :return: offset in the raw data till which it has been parsed
        """
        self.up_segment_info = InfoOpaqueField(raw[:InfoOpaqueField.LEN])
        offset = InfoOpaqueField.LEN
        for _ in range(self.up_segment_info.hops):
            self.up_segment_hops.append(
                HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN]))
            offset += HopOpaqueField.LEN
        return offset

    def _parse_core_segment(self, raw, offset):
        """
        Parses the raw data and populates the core_segment fields.

        :param raw: bytes
        :param offset: int
        :return: offset in the raw data till which it has been parsed
        """
        self.core_segment_info = \
            InfoOpaqueField(raw[offset:offset + InfoOpaqueField.LEN])
        offset += InfoOpaqueField.LEN
        for _ in range(self.core_segment_info.hops):
            self.core_segment_hops.append(
                HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN]))
            offset += HopOpaqueField.LEN
        return offset

    def _parse_down_segment(self, raw, offset):
        """
        Parses the raw data and populates the down_segment fields.

        :param raw: bytes
        :param offset: int
        :return: offset in the raw data till which it has been parsed
        """
        self.down_segment_info = \
            InfoOpaqueField(raw[offset:offset + InfoOpaqueField.LEN])
        offset += InfoOpaqueField.LEN
        for _ in range(self.down_segment_info.hops):
            self.down_segment_hops.append(
                HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN]))
            offset += HopOpaqueField.LEN
        return offset

    def pack(self):
        """
        Packs the opaque fields and returns a byte array.
        """
        return self._pack_up_segment() + self._pack_core_segment() + \
            self._pack_down_segment()

    def _pack_up_segment(self):
        """
        Packs the up segment opaque fields and returns a byte array.
        """
        data = []
        if self.up_segment_info:
            data.append(self.up_segment_info.pack())
            for of in self.up_segment_hops:
                data.append(of.pack())
        return b"".join(data)

    def _pack_core_segment(self):
        """
        Packs the core segment opaque fields and returns a byte array.
        """
        data = []
        if self.core_segment_info:
            data.append(self.core_segment_info.pack())
            for of in self.core_segment_hops:
                data.append(of.pack())
        return b"".join(data)

    def _pack_down_segment(self):
        """
        Packs the down segment opaque fields and returns a byte array.
        """
        data = []
        if self.down_segment_info:
            data.append(self.down_segment_info.pack())
            for of in self.down_segment_hops:
                data.append(of.pack())
        return b"".join(data)

    def reverse(self):
        PathBase.reverse(self)
        self.core_segment_hops.reverse()
        if self.core_segment_info is not None:
            self.core_segment_info.up_flag ^= True

    def get_of(self, index):
        """
        Returns the opaque field for the given index.
        """
        # Build temporary flat list of opaque fields.
        tmp = []
        if self.up_segment_info:
            tmp.append(self.up_segment_info)
            tmp.extend(self.up_segment_hops)
        if self.core_segment_info:
            tmp.append(self.core_segment_info)
            tmp.extend(self.core_segment_hops)
        if self.down_segment_info:
            tmp.append(self.down_segment_info)
            tmp.extend(self.down_segment_hops)
        if index >= len(tmp):
            return None
        else:
            return tmp[index]

    @classmethod
    def from_values(cls, up_inf=None, up_hops=None,
                    core_inf=None, core_hops=None,
                    dw_inf=None, dw_hops=None):
        """
        Returns CorePath with the values specified.
        @param up_inf: InfoOpaqueField of up_segment
        @param up_hops: list of HopOpaqueField of up_segment
        @param core_inf: InfoOpaqueField for core_segment
        @param core_hops: list of HopOpaqueFields of core_segment
        @param dw_inf: InfoOpaqueField of down_segment
        @param dw_hops: list of HopOpaqueField of down_segment
        """
        if up_hops is None:
            up_hops = []
        if core_hops is None:
            core_hops = []
        if dw_hops is None:
            dw_hops = []

        cp = CorePath()
        cp.up_segment_info = up_inf
        cp.up_segment_hops = up_hops
        cp.core_segment_info = core_inf
        cp.core_segment_hops = core_hops
        cp.down_segment_info = dw_inf
        cp.down_segment_hops = dw_hops
        return cp

    def __str__(self):
        s = []
        s.append("<Core-Path>:\n")

        if self.up_segment_info:
            s.append("<Up-Segment>:\n")
            s.append(str(self.up_segment_info) + "\n")
            for of in self.up_segment_hops:
                s.append(str(of) + "\n")
            s.append("</Up-Segment>\n")

        if self.core_segment_info:
            s.append("<Core-Segment>\n")
            s.append(str(self.core_segment_info) + "\n")
            for of in self.core_segment_hops:
                s.append(str(of) + "\n")
            s.append("</Core-Segment>\n")

        if self.down_segment_info:
            s.append("<Down-Segment>\n")
            s.append(str(self.down_segment_info) + "\n")
            for of in self.down_segment_hops:
                s.append(str(of) + "\n")
            s.append("</Down-Segment>\n")

        s.append("</Core-Path>")
        return "".join(s)


class CrossOverPath(PathBase):
    """
    A shortcut path using a cross-over link.

    The sequence of opaque fields for such a path is:
    | info OF up-segment |  hop OF 1 | ... | hop OF N | upstream AD OF |
    | info OF down-segment | upstream AD OF | hop OF 1 | ... | hop OF N |
    The upstream AD OF is needed to verify the last hop of the up-segment /
    first hop of the down-segment respectively.

    On-path case (e.g., destination is on up/down-segment) is a special case
    handled by this class. Then one segment (down- or up-segment depending
    whether destination is upstream or downstream AD) is used only for MAC
    verification and for determination whether path can terminate at destination
    AD (i.e., its last egress interface has to equal 0).
    """

    def __init__(self, raw=None):
        """
        Initialize an instance of the class CrossOverPath.

        :param raw:
        :type raw:
        """
        PathBase.__init__(self)
        self.up_segment_upstream_ad = None
        self.down_segment_upstream_ad = None

        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Parses the raw data and populates the fields accordingly.
        """
        assert isinstance(raw, bytes)
        # Parse up-segment
        offset = self._parse_up_segment(raw)
        # Parse down-segment
        self._parse_down_segment(raw, offset)
        self.parsed = True

    def _parse_up_segment(self, raw):
        """
        Parses the raw data and populates the up_segment fields.

        :param raw: bytes
        :type raw:
        """
        self.up_segment_info = InfoOpaqueField(raw[:InfoOpaqueField.LEN])
        offset = InfoOpaqueField.LEN
        for _ in range(self.up_segment_info.hops):
            self.up_segment_hops.append(
                HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN]))
            offset += HopOpaqueField.LEN
        self.up_segment_upstream_ad = \
            HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN])
        offset += HopOpaqueField.LEN
        return offset

    def _parse_down_segment(self, raw, offset):
        """
        Parses the raw data and populates the down_segment fields.

        :param raw: bytes
        :type raw:
        """
        self.down_segment_info = \
            InfoOpaqueField(raw[offset:offset + InfoOpaqueField.LEN])
        offset += InfoOpaqueField.LEN
        self.down_segment_upstream_ad = \
            HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN])
        offset += HopOpaqueField.LEN
        for _ in range(self.down_segment_info.hops):
            self.down_segment_hops.append(
                HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN]))
            offset += HopOpaqueField.LEN

    def pack(self):
        """
        Packs the opaque fields and returns a byte array.
        """
        return self._pack_up_segment() + self._pack_down_segment()

    def _pack_up_segment(self):
        """
        Packs the up segment opaque fields and returns a byte array.
        """
        data = [self.up_segment_info.pack()]
        for of in self.up_segment_hops:
            data.append(of.pack())
        data.append(self.up_segment_upstream_ad.pack())
        return b"".join(data)

    def _pack_down_segment(self):
        """
        Packs the down segment opaque fields and returns a byte array.
        """
        data = [self.down_segment_info.pack(),
                self.down_segment_upstream_ad.pack()]
        for of in self.down_segment_hops:
            data.append(of.pack())
        return b"".join(data)

    def reverse(self):
        # Reverse hops and info fields.
        PathBase.reverse(self)
        # Reverse upstream AD fields.
        self.up_segment_upstream_ad, self.down_segment_upstream_ad = \
            self.down_segment_upstream_ad, self.up_segment_upstream_ad

    def get_of(self, index):
        # Build temporary flat list of opaque fields.
        tmp = [self.up_segment_info]
        tmp.extend(self.up_segment_hops)
        tmp.append(self.up_segment_upstream_ad)
        tmp.append(self.down_segment_info)
        tmp.append(self.down_segment_upstream_ad)
        tmp.extend(self.down_segment_hops)
        return tmp[index]

    def get_first_hop_offset(self):
        """
        Returns offset to the first HopOpaqueField of the path.
        """
        if self.up_segment_hops:
            # Check whether this is on-path case.
            if len(self.up_segment_hops) == 1:
                # Return offset to first HopOpaqueField used for routing (not
                # for only MAC verification) of down_segment.
                return 2 * InfoOpaqueField.LEN + 3 * HopOpaqueField.LEN
            return InfoOpaqueField.LEN
        elif self.down_segment_hops:
            return InfoOpaqueField.LEN
        else:
            return 0

    def get_first_info_offset(self):
        """
        Returns offset to the first InfoOpaqueField of the path.
        Handles on-path case.
        """
        if self.up_segment_hops and len(self.up_segment_hops) == 1:
            # If up_segment is used only for MAC verification (on-path case),
            # then return offset to first InfoOpaqueField of down_segment.
            return InfoOpaqueField.LEN + 2 * HopOpaqueField.LEN
        return 0

    def __str__(self):
        s = []
        s.append("<CrossOver-Path>:\n<Up-Segment>:\n")
        s.append(str(self.up_segment_info) + "\n")
        for of in self.up_segment_hops:
            s.append(str(of) + "\n")
        s.append("Upstream AD: " + str(self.up_segment_upstream_ad) + "\n")
        s.append("</Up-Segment>\n<Down-Segment>\n")
        s.append(str(self.down_segment_info) + "\n")
        s.append("Upstream AD: " + str(self.down_segment_upstream_ad) + "\n")
        for of in self.down_segment_hops:
            s.append(str(of) + "\n")
        s.append("</Down-Segment>\n</CrossOver-Path>")

        return "".join(s)


class PeerPath(PathBase):
    """
    A shortcut path using a crossover link.

    The sequence of opaque fields for such a path is:
    | info OF up-segment |  hop OF 1 | ... | hop OF N | peering link OF |
    | upstream AD OF | info OF down-segment | upstream AD OF | peering link OF |
    | hop OF 1 | ... | hop OF N |
    The upstream AD OF is needed to verify the last hop of the up-segment /
    first hop of the down-segment respectively.
    """

    def __init__(self, raw=None):
        """
        Initialize an instance of the class PeerPath.

        :param raw:
        :type raw:
        """
        PathBase.__init__(self)
        self.up_segment_peering_link = None
        self.up_segment_upstream_ad = None
        self.down_segment_peering_link = None
        self.down_segment_upstream_ad = None
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Parses the raw data and populates the fields accordingly.
        """
        assert isinstance(raw, bytes)
        # Parse up-segment
        offset = self._parse_up_segment(raw)
        # Parse down-segment
        self._parse_down_segment(raw, offset)
        self.parsed = True

    def _parse_up_segment(self, raw):
        """
        Parses the raw data and populates the down_segment fields.

        :param raw:
        :return
        """
        self.up_segment_info = InfoOpaqueField(raw[:InfoOpaqueField.LEN])
        offset = InfoOpaqueField.LEN
        for _ in range(self.up_segment_info.hops):
            self.up_segment_hops.append(
                HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN]))
            offset += HopOpaqueField.LEN
        self.up_segment_peering_link = \
            HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN])
        offset += HopOpaqueField.LEN
        self.up_segment_upstream_ad = \
            HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN])
        offset += HopOpaqueField.LEN
        return offset

    def _parse_down_segment(self, raw, offset):
        """
        Parses the raw data and populates the down_segment fields.

        :param raw:
        :param offset:
        """
        self.down_segment_info = \
            InfoOpaqueField(raw[offset:offset + InfoOpaqueField.LEN])
        offset += InfoOpaqueField.LEN
        self.down_segment_upstream_ad = \
            HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN])
        offset += HopOpaqueField.LEN
        self.down_segment_peering_link = \
            HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN])
        offset += HopOpaqueField.LEN
        for _ in range(self.down_segment_info.hops):
            self.down_segment_hops.append(
                HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN]))
            offset += HopOpaqueField.LEN

    def pack(self):
        """
        Packs the opaque fields and returns a byte array.
        """
        return self._pack_up_segment() + self._pack_down_segment()

    def _pack_up_segment(self):
        """
        Packs the up segment opaque fields and returns a byte array.
        """
        data = [self.up_segment_info.pack()]
        for of in self.up_segment_hops:
            data.append(of.pack())
        data.append(self.up_segment_peering_link.pack())
        data.append(self.up_segment_upstream_ad.pack())
        return b"".join(data)

    def _pack_down_segment(self):
        """
        Packs the down segment opaque fields and returns a byte array.
        """
        data = [self.down_segment_info.pack(),
                self.down_segment_upstream_ad.pack(),
                self.down_segment_peering_link.pack()]
        for of in self.down_segment_hops:
            data.append(of.pack())
        return b"".join(data)

    def reverse(self):
        # Reverse hop and info fields.
        PathBase.reverse(self)
        # Reverse upstream AD and peering link fields.
        self.up_segment_upstream_ad, self.down_segment_upstream_ad = \
            self.down_segment_upstream_ad, self.up_segment_upstream_ad
        self.up_segment_peering_link, self.down_segment_peering_link = \
            self.down_segment_peering_link, self.up_segment_peering_link

    def get_of(self, index):
        # Build temporary flat list of opaque fields.
        tmp = [self.up_segment_info]
        tmp.extend(self.up_segment_hops)
        tmp.append(self.up_segment_peering_link)
        tmp.append(self.up_segment_upstream_ad)
        tmp.append(self.down_segment_info)
        tmp.append(self.down_segment_upstream_ad)
        tmp.append(self.down_segment_peering_link)
        tmp.extend(self.down_segment_hops)
        return tmp[index]

    def __str__(self):
        s = []
        s.append("<Peer-Path>:\n<Up-Segment>:\n")
        s.append(str(self.up_segment_info) + "\n")
        for of in self.up_segment_hops:
            s.append(str(of) + "\n")
        s.append("Peering link: " + str(self.up_segment_peering_link) + "\n")
        s.append("Upstream AD: " + str(self.up_segment_upstream_ad) + "\n")
        s.append("</Up-Segment>\n<Down-Segment>\n")
        s.append(str(self.down_segment_info) + "\n")
        s.append("Upstream AD: " + str(self.down_segment_upstream_ad) + "\n")
        s.append("Peering link: " + str(self.down_segment_peering_link) + "\n")
        for of in self.down_segment_hops:
            s.append(str(of) + "\n")
        s.append("</Down-Segment>\n</Peer-Path>")

        return "".join(s)

    def get_first_hop_offset(self):
        """
        Depending on up_segment flag returns the first up- or down-segment hop.
        """
        if self.up_segment_hops:
            first_segment_hops = self.up_segment_hops
        elif self.down_segment_hops:
            first_segment_hops = self.down_segment_hops
        else:
            return 0

        if first_segment_hops[0].info == OpaqueFieldType.LAST_OF:
            return InfoOpaqueField.LEN + HopOpaqueField.LEN
        return InfoOpaqueField.LEN


class EmptyPath(PathBase):
    """
    Represents an empty path.

    This is currently needed for intra AD communication, which doesn't need a
    SCION path but still uses SCION packets for communication.
    """
    def __init__(self):
        """
        Initialize an instance of the class EmptyPath.

        :param raw:
        :type raw:
        """
        PathBase.__init__(self)

    def pack(self):
        return b''

    def get_of(self, index):
        return None

    def __str__(self):
        return "<Empty-Path></Empty-Path>"


class PathCombinator(object):
    """
    Class that contains functions required to build end-to-end SCION paths.
    """
    @staticmethod
    def build_shortcut_paths(up_segments, down_segments):
        """
        Returns a list of all shortcut paths (peering and crossover paths) that
        can be built using the provided up- and down-segments.
        """
        paths = []
        for up in up_segments:
            for down in down_segments:
                path = PathCombinator._build_shortcut_path(up, down)
                if path and path not in paths:
                    paths.append(path)

        return paths

    @staticmethod
    def build_core_paths(up_segment, down_segment, core_segments):
        """
        Returns list of all paths that can be built as combination of segments
        from up_segments, core_segments and down_segments.
        """
        paths = []
        if not core_segments:
            path = PathCombinator._build_core_path(up_segment, [],
                                                   down_segment)
            if path:
                paths.append(path)
        else:
            for core_segment in core_segments:
                path = PathCombinator._build_core_path(
                    up_segment, core_segment, down_segment)
                if path and path not in paths:
                    paths.append(path)
        return paths

    @staticmethod
    def _build_shortcut_path(up_segment, down_segment):
        """
        Takes PCB objects (up/down_segment) and tries to combine
        them as short path
        """
        # TODO check if stub ADs are the same...
        if (not up_segment or not down_segment or
                not up_segment.ads or not down_segment.ads):
            return None

        # looking for xovr and peer points
        (xovrs, peers) = PathCombinator._get_xovrs_peers(up_segment,
                                                         down_segment)

        if not xovrs and not peers:
            return None
        elif xovrs and peers:
            if sum(peers[-1]) > sum(xovrs[-1]):
                return PathCombinator._join_shortcuts(
                    up_segment, down_segment, peers[-1], True)
            else:
                return PathCombinator._join_shortcuts(
                    up_segment, down_segment, xovrs[-1], False)
        elif xovrs:
            return PathCombinator._join_shortcuts(
                up_segment, down_segment, xovrs[-1], False)
        else:  # peers only
            return PathCombinator._join_shortcuts(
                up_segment, down_segment, peers[-1], True)

    @staticmethod
    def _build_core_path(up_segment, core_segment, down_segment):
        """
        Joins up_, core_ and down_segment into core fullpath. core_segment can
        be 'None' in case of a intra-ISD core_segment of length 0.
        Returns object of CorePath class. core_segment (if exists) has to have
        down-segment orientation.
        """
        if (not up_segment or not down_segment or
                not up_segment.ads or not down_segment.ads):
            return None

        if not PathCombinator._check_connected(up_segment, core_segment,
                                               down_segment):
            return None

        full_path = CorePath()
        full_path = PathCombinator._join_up_segment(full_path, up_segment)
        full_path = PathCombinator._join_core_segment(full_path, core_segment)
        full_path = PathCombinator._join_down_segment(full_path, down_segment)
        return full_path

    @staticmethod
    def _get_xovrs_peers(up_segment, down_segment):
        """
        Collects the xovr and peer points from up_segment, down_segment.
        """
        xovrs = []
        peers = []
        for up_i in range(1, len(up_segment.ads)):
            for down_i in range(1, len(down_segment.ads)):
                up_ad = up_segment.ads[up_i]
                down_ad = down_segment.ads[down_i]
                if up_ad.pcbm.ad_id == down_ad.pcbm.ad_id:
                    xovrs.append((up_i, down_i))
                else:
                    for up_peer in up_ad.pms:
                        for down_peer in down_ad.pms:
                            if (up_peer.ad_id == down_ad.pcbm.ad_id and
                                    down_peer.ad_id == up_ad.pcbm.ad_id):
                                peers.append((up_i, down_i))
        # select shortest path xovrs (preferred) or peers
        xovrs.sort(key=lambda tup: sum(tup))
        peers.sort(key=lambda tup: sum(tup))
        return xovrs, peers

    @staticmethod
    def _join_shortcuts(up_segment, down_segment, point, peer=True):
        """
        Joins up_ and down_segment (objects of PCB class) into a shortcut
        fullpath.
        Depending on the scenario returns an object of type PeerPath or
        CrossOverPath class.
        point: tuple (up_segment_index, down_segment_index) position of
               peer/xovr link
        peer:  true for peer, false for xovr path
        """
        up_segment = copy.deepcopy(up_segment)
        down_segment = copy.deepcopy(down_segment)
        (up_index, dw_index) = point

        if peer:
            path = PeerPath()
            if up_segment.get_isd() == down_segment.get_isd():
                info = OpaqueFieldType.INTRATD_PEER
            else:
                info = OpaqueFieldType.INTERTD_PEER
        else:
            path = CrossOverPath()
            info = OpaqueFieldType.NON_TDC_XOVR

        path = PathCombinator._join_up_segment_shortcuts(path, up_segment,
                                                         info, up_index)
        if peer:
            path = PathCombinator._join_shortcuts_peer(
                path, up_segment.ads[up_index], down_segment.ads[dw_index])

        path = PathCombinator._join_down_segment_shortcuts(
            path, down_segment, info, dw_index)
        return path

    @staticmethod
    def _check_connected(up_segment, core_segment, down_segment):
        # If we have a core segment, check that the core_segment connects the
        # up_ and down_segment. Otherwise, check that up- and down-segment meet
        # at a single core AD.
        if core_segment:
            if ((core_segment.get_last_pcbm().ad_id !=
                    up_segment.get_first_pcbm().ad_id) or
                    (core_segment.get_first_pcbm().ad_id !=
                     down_segment.get_first_pcbm().ad_id)):
                return False
        else:
            if (up_segment.get_first_pcbm().ad_id !=
                    down_segment.get_first_pcbm().ad_id):
                return False
        return True

    @staticmethod
    def _join_up_segment(path, up_segment):
        """
        Takes a path and up_segment and populates the up_segment fields of
        the path.
        """
        path.up_segment_info = up_segment.iof
        path.up_segment_info.up_flag = True
        for block in reversed(up_segment.ads):
            path.up_segment_hops.append(copy.deepcopy(block.pcbm.hof))
        path.up_segment_hops[-1].info = OpaqueFieldType.LAST_OF
        return path

    @staticmethod
    def _join_core_segment(path, core_segment):
        """
        Takes a path and core_segment and populates the core_segment fields of
        the path.
        """
        if not core_segment:
            return path
        path.core_segment_info = core_segment.iof
        path.core_segment_info.up_flag = True
        for block in reversed(core_segment.ads):
            path.core_segment_hops.append(
                copy.deepcopy(block.pcbm.hof))
        path.core_segment_hops[-1].info = OpaqueFieldType.LAST_OF
        path.core_segment_hops[0].info = OpaqueFieldType.LAST_OF
        return path

    @staticmethod
    def _join_down_segment(path, down_segment):
        """
        Takes a path and down_segment and populates the down_segment fields of
        the path.
        """
        path.down_segment_info = down_segment.iof
        path.down_segment_info.up_flag = False
        for block in down_segment.ads:
            path.down_segment_hops.append(copy.deepcopy(block.pcbm.hof))
        path.down_segment_hops[0].info = OpaqueFieldType.LAST_OF
        return path

    @staticmethod
    def _join_up_segment_shortcuts(path, up_segment, info, up_index):
        """
        Populates the up_segment fields of a shortcut path.
        """
        path.up_segment_info = up_segment.iof
        path.up_segment_info.info = info
        path.up_segment_info.hops -= up_index
        path.up_segment_info.up_flag = True
        for i in reversed(range(up_index, len(up_segment.ads))):
            path.up_segment_hops.append(up_segment.ads[i].pcbm.hof)
        path.up_segment_hops[-1].info = OpaqueFieldType.LAST_OF
        path.up_segment_upstream_ad = up_segment.ads[up_index - 1].pcbm.hof
        path.up_segment_upstream_ad.info = OpaqueFieldType.NORMAL_OF
        return path

    @staticmethod
    def _join_down_segment_shortcuts(path, down_segment, info, dw_index):
        """
        Populates the down_segment fields of a shortcut path.
        """
        path.down_segment_info = down_segment.iof
        path.down_segment_info.info = info
        path.down_segment_info.hops -= dw_index
        path.down_segment_info.up_flag = False
        path.down_segment_upstream_ad = down_segment.ads[dw_index - 1].pcbm.hof
        path.down_segment_upstream_ad.info = OpaqueFieldType.NORMAL_OF
        for i in range(dw_index, len(down_segment.ads)):
            path.down_segment_hops.append(down_segment.ads[i].pcbm.hof)
        path.down_segment_hops[0].info = OpaqueFieldType.LAST_OF
        return path

    @staticmethod
    def _join_shortcuts_peer(path, up_ad, down_ad):
        """
        Populates the peering link fields of a shortcut path.
        """
        for up_peer in up_ad.pms:
            for down_peer in down_ad.pms:
                if (up_peer.ad_id == down_ad.pcbm.ad_id and
                        down_peer.ad_id == up_ad.pcbm.ad_id):
                    path.up_segment_peering_link = up_peer.hof
                    path.down_segment_peering_link = down_peer.hof
        return path
