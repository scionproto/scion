"""
path.py

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

import copy
from lib.packet.opaque_field import (InfoOpaqueField, HopOpaqueField,
    OpaqueFieldType)


class PathType(object):
    """
    Defines constants for the SCION path types.
    """
    # TODO Discuss and (probably) remove
    EMPTY = 0x00  # Empty path
    CORE = OpaqueFieldType.TDC_XOVR # Path to the core
    CROSS_OVER = OpaqueFieldType.NON_TDC_XOVR # Path with cross over
    PEER_LINK = OpaqueFieldType.INTRATD_PEER # Path with peer link


class PathBase(object):
    """
    Base class for paths in SCION.

    A path is a sequence of path segments dependent on the type of path. Path
    segments themselves are a sequence of opaque fields containing routing
    information for each AD-level hop.
    """
    def __init__(self):
        self.type = 0
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

    def is_last_hop(self, hop):
        """
        Returns true if 'hop' equals to the last down-segment hop.
        """
        return hop is None or hop == self.down_segment_hops[-1]

    def is_first_hop(self, hop):
        """
        Returns true if 'hop' equals to the first up-segment hop.
        """
        return hop is None or hop == self.up_segment_hops[0]

    def get_first_hop_of(self):
        """
        Depending on up_segment flag returns the first up- or down-segment hop.
        """
        if self.up_segment_hops:
            return self.up_segment_hops[0]
        elif self.down_segment_hops:
            return self.down_segment_hops[0]
        else:
            return None

    def get_of(self, index):
        """
        Returns the opaque field for the given index.
        """
        # Build temporary flat list of opaque fields.
        tmp = [self.up_segment_info]
        tmp.extend(self.up_segment_hops)
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
        PathBase.__init__(self)
        self.type = PathType.CORE
        self.core_segment_info = None
        self.core_segment_hops = []

        if raw is not None:
            self.parse(raw)

    # TODO PSz: a flag is needed to distinguish downPath-only case. I.e. if
    # SCIONPacket.up_path is false and path has only one special OF, then it
    # should parse only DownPath. It would be easier to put down/up flag to SOF.
    def parse(self, raw):
        """
        Parses the raw data and populates the fields accordingly.
        """
        assert isinstance(raw, bytes)
        # Parse up-segment
        self.up_segment_info = InfoOpaqueField(raw[:InfoOpaqueField.LEN])
        offset = InfoOpaqueField.LEN
        for _ in range(self.up_segment_info.hops):
            self.up_segment_hops.append(
                HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN]))
            offset += HopOpaqueField.LEN
        # Parse core-segment
        if len(raw) != offset:
            self.core_segment_info = \
                InfoOpaqueField(raw[offset:offset + InfoOpaqueField.LEN])
            offset += InfoOpaqueField.LEN
            for _ in range(self.core_segment_info.hops):
                self.core_segment_hops.append(
                    HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN]))
                offset += HopOpaqueField.LEN
        # Parse down-segment
        if len(raw) != offset:
            self.down_segment_info = \
                InfoOpaqueField(raw[offset:offset + InfoOpaqueField.LEN])
            offset += InfoOpaqueField.LEN
            for _ in range(self.down_segment_info.hops):
                self.down_segment_hops.append(
                    HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN]))
                offset += HopOpaqueField.LEN

        self.parsed = True

    def pack(self):
        """
        Packs the opaque fields and returns a byte array.
        """
        data = []
        if self.up_segment_info:
            data.append(self.up_segment_info.pack())
            for of in self.up_segment_hops:
                data.append(of.pack())
        if self.core_segment_info:
            data.append(self.core_segment_info.pack())
            for of in self.core_segment_hops:
                data.append(of.pack())
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
        tmp = [self.up_segment_info]
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
    """

    def __init__(self, raw=None):
        PathBase.__init__(self)
        self.type = PathType.PEER_LINK
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
        self.up_segment_info = InfoOpaqueField(raw[:InfoOpaqueField.LEN])
        offset = InfoOpaqueField.LEN
        for _ in range(self.up_segment_info.hops):
            self.up_segment_hops.append(
                HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN]))
            offset += HopOpaqueField.LEN
        self.up_segment_upstream_ad = \
            HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN])
        offset += HopOpaqueField.LEN

        # Parse down-segment
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

        self.parsed = True

    def pack(self):
        """
        Packs the opaque fields and returns a byte array.
        """
        data = []
        data.append(self.up_segment_info.pack())
        for of in self.up_segment_hops:
            data.append(of.pack())
        data.append(self.up_segment_upstream_ad.pack())
        data.append(self.down_segment_info.pack())
        data.append(self.down_segment_upstream_ad.pack())
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
        PathBase.__init__(self)
        self.type = PathType.PEER_LINK
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


        # Parse down-segment
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

        self.parsed = True

    def pack(self):
        """
        Packs the opaque fields and returns a byte array.
        """
        data = []
        data.append(self.up_segment_info.pack())
        for of in self.up_segment_hops:
            data.append(of.pack())
        data.append(self.up_segment_peering_link.pack())
        data.append(self.up_segment_upstream_ad.pack())
        data.append(self.down_segment_info.pack())
        data.append(self.down_segment_upstream_ad.pack())
        data.append(self.down_segment_peering_link.pack())
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
        s.append("Upstream AD: " + str(self.up_segment_upstream_ad) + "\n")
        s.append("Peering link: " + str(self.up_segment_peering_link) + "\n")
        s.append("</Up-Segment>\n<Down-Segment>\n")
        s.append(str(self.down_segment_info) + "\n")
        s.append("Peering link: " + str(self.down_segment_peering_link) + "\n")
        s.append("Upstream AD: " + str(self.down_segment_upstream_ad) + "\n")
        for of in self.down_segment_hops:
            s.append(str(of) + "\n")
        s.append("</Down-Segment>\n</Peer-Path>")

        return "".join(s)


class EmptyPath(PathBase):
    """
    Represents an empty path.

    This is currently needed for intra AD communication, which doesn't need a
    SCION path but still uses SCION packets for communication.
    """
    def __init__(self, raw=None):
        PathBase.__init__(self)
        self.type = PathType.EMPTY

        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.up_segment_info = InfoOpaqueField(raw[:InfoOpaqueField.LEN])
        # We do this so we can still reverse the segment.
        self.down_segment_info = self.up_segment_info

        self.parsed = True

    def pack(self):
        return b''

    def is_first_hop(self, hop):
        return True

    def is_last_hop(self, hop):
        return True

    def get_first_hop_of(self):
        return None

    def get_of(self, index):
        return self.up_segment_info

    def __str__(self):
        return "<Empty-Path></Empty-Path>"


class PathCombinator(object):
    """
    Class that contains functions required to build end-to-end SCION paths.
    """

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

        # If we have a core segment, check that the core_segment connects the
        # up_ and down_segment. Otherwise, check that up- and down-segment meet
        # at a single core AD.
        if ((core_segment and
             (core_segment.get_first_ad().ad_id !=
              up_segment.get_first_ad().ad_id) or
             (core_segment.get_last_ad().ad_id !=
              down_segment.get_first_ad().ad_id)) or
             (not core_segment and
              (up_segment.get_first_ad().ad_id !=
               down_segment.get_first_ad().ad_id))):
            return None

        full_path = CorePath()
        full_path.up_segment_info = up_segment.iof
        full_path.up_segment_info.up_flag = True
        for block in reversed(up_segment.ads):
            full_path.up_segment_hops.append(copy.deepcopy(block.pcbm.hof))
        full_path.up_segment_hops[-1].info = OpaqueFieldType.LAST_OF

        if core_segment:
            full_path.core_segment_info = core_segment.iof
            full_path.core_segment_info.up_flag = False
            for block in core_segment.ads:
                full_path.core_segment_hops.append(
                    copy.deepcopy(block.pcbm.hof))
            full_path.core_segment_hops[0].info = OpaqueFieldType.LAST_OF

        full_path.down_segment_info = down_segment.iof
        full_path.down_segment_info.up_flag = False
        for block in down_segment.ads:
            full_path.down_segment_hops.append(copy.deepcopy(block.pcbm.hof))
        full_path.down_segment_hops[0].info = OpaqueFieldType.LAST_OF
        return full_path

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
            info = OpaqueFieldType.INTRATD_PEER
        else:
            path = CrossOverPath()
            info = OpaqueFieldType.NON_TDC_XOVR

        path.up_segment_info = up_segment.iof
        path.up_segment_info.info = info
        path.up_segment_info.hops -= up_index
        path.up_segment_info.up_flag = True
        for i in reversed(range(up_index, len(up_segment.ads))):
            path.up_segment_hops.append(up_segment.ads[i].pcbm.hof)
        path.up_segment_hops[-1].info = OpaqueFieldType.LAST_OF
        path.up_segment_upstream_ad = up_segment.ads[up_index - 1].pcbm.hof

        if peer:
            up_ad = up_segment.ads[up_index]
            down_ad = down_segment.ads[dw_index]
            for up_peer in up_ad.pms:
                for down_peer in down_ad.pms:
                    if (up_peer.ad_id == down_ad.pcbm.ad_id and
                            down_peer.ad_id == up_ad.pcbm.ad_id):
                        path.up_segment_peering_link = up_peer.hof
                        path.down_segment_peering_link = down_peer.hof

        path.down_segment_info = down_segment.iof
        path.down_segment_info.info = info
        path.down_segment_info.hops -= dw_index
        path.down_segment_info.up_flag = False
        path.down_segment_upstream_ad = down_segment.ads[dw_index - 1].pcbm.hof
        for i in range(dw_index, len(down_segment.ads)):
            path.down_segment_hops.append(down_segment.ads[i].pcbm.hof)
        path.down_segment_hops[0].info = OpaqueFieldType.LAST_OF

        return path

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
        if not xovrs and not peers:
            return None
        elif xovrs and peers:
            if sum(peers[-1]) > sum(xovrs[-1]):
                return PathCombinator._join_shortcuts(up_segment, down_segment,
                                                      peers[-1], True)
            else:
                return PathCombinator._join_shortcuts(up_segment, down_segment,
                                                      xovrs[-1], False)
        elif xovrs:
            return PathCombinator._join_shortcuts(up_segment, down_segment,
                                                  xovrs[-1],
                                                  False)
        else:  # peers only
            return PathCombinator._join_shortcuts(up_segment, down_segment,
                                                  peers[-1],
                                                  True)

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
            path = PathCombinator._build_core_path(up_segment, [], down_segment)
            if path:
                paths.append(path)
        else:
            for core_segment in core_segments:
                path = PathCombinator._build_core_path(up_segment,
                                                       core_segment,
                                                       down_segment)
                if path and path not in paths:
                    paths.append(path)
        return paths

