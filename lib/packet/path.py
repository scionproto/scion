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
    # TODO merge it with OpaqueFieldType
    # Discuss and (probably) remove
    EMPTY = 0x00  # Empty path
    CORE = OpaqueFieldType.TDC_XOVR #0x80  # Path to the core
    CROSS_OVER = OpaqueFieldType.NON_TDC_XOVR #0xc0  # Path with cross over
    PEER_LINK =  OpaqueFieldType.INTRATD_PEER #0xf0  # Path with peer link


class PathBase(object):
    """
    Base class for paths in SCION.

    A path is a sequence of opaque fields dependent on the type of path.
    """
    def __init__(self):
        self.type = 0
        self.up_path_info = None
        self.up_path_hops = []
        self.down_path_info = None
        self.down_path_hops = []

        self.parsed = False

    def parse(self, raw):
        pass

    def pack(self):
        pass

    def reverse(self):
        """
        Reverses the path.
        """
        # Swap down path and up path.
        self.up_path_hops, self.down_path_hops = \
            self.down_path_hops, self.up_path_hops
        self.up_path_info, self.down_path_info = \
            self.down_path_info, self.up_path_info
        # Reverse hops.
        self.up_path_hops.reverse()
        self.down_path_hops.reverse()

    def is_last_hop(self, hop):
        """
        Returns true if 'hop' equals to the last down-path hop.
        """
        return hop is None or hop == self.down_path_hops[-1]

    def is_first_hop(self, hop):
        """
        Returns true if 'hop' equals to the first up-path hop.
        """
        return hop is None or hop == self.up_path_hops[0]

    def get_first_hop_of(self):
        """
        Depending on up_path flag returns the first up- or down-path hop.
        """
        if self.up_path_hops:
            return self.up_path_hops[0]
        elif self.down_path_hops:
            return self.down_path_hops[0]
        else:
            return None

    def get_of(self, index):
        """
        Returns the opaque field for the given index.
        """
        # Build temporary flat list of opaque fields.
        tmp = [self.up_path_info]
        tmp.extend(self.up_path_hops)
        tmp.append(self.down_path_info)
        tmp.extend(self.down_path_hops)
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
    | info OF up-path | hop OF 1 | ... | hop OF N | info OF core-path |
    | hop OF 1 \ ... | hop OF N | info OF down-path |
    | hop OF 1 | ... | hop OF N |
    """
    def __init__(self, raw=None):
        PathBase.__init__(self)
        self.type = PathType.CORE
        self.core_path_info = None
        self.core_path_hops = []

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
        # Parse up-path
        self.up_path_info = InfoOpaqueField(raw[:InfoOpaqueField.LEN])
        offset = InfoOpaqueField.LEN
        for i in range(self.up_path_info.hops):
            self.up_path_hops.append(
                HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN]))
            offset += HopOpaqueField.LEN
        # Parse core-path
        if len(raw) != offset:
            self.core_path_info = \
                InfoOpaqueField(raw[offset:offset + InfoOpaqueField.LEN])
            offset += InfoOpaqueField.LEN
            for i in range(self.core_path_info.hops):
                self.core_path_hops.append(
                    HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN]))
                offset += HopOpaqueField.LEN
        # Parse down-path
        if len(raw) != offset:
            self.down_path_info = \
                InfoOpaqueField(raw[offset:offset + InfoOpaqueField.LEN])
            offset += InfoOpaqueField.LEN
            for i in range(self.down_path_info.hops):
                self.down_path_hops.append(
                    HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN]))
                offset += HopOpaqueField.LEN

        self.parsed = True

    def pack(self):
        """
        Packs the opaque fields and returns a byte array.
        """
        data = []
        if self.up_path_info:
            data.append(self.up_path_info.pack())
            for of in self.up_path_hops:
                data.append(of.pack())
        if self.core_path_info:
            data.append(self.core_path_info.pack())
            for of in self.core_path_hops:
                data.append(of.pack())
        if self.down_path_info:
            data.append(self.down_path_info.pack())
            for of in self.down_path_hops:
                data.append(of.pack())

        return b"".join(data)

    def reverse(self):
        PathBase.reverse(self)
        self.core_path_hops.reverse()

    def get_of(self, index):
        """
        Returns the opaque field for the given index.
        """
        # Build temporary flat list of opaque fields.
        tmp = [self.up_path_info]
        tmp.extend(self.up_path_hops)
        if self.core_path_info:
            tmp.append(self.core_path_info)
            tmp.extend(self.core_path_hops)
        if self.down_path_info:
            tmp.append(self.down_path_info)
            tmp.extend(self.down_path_hops)
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
        @param up_inf: InfoOpaqueField of up_path
        @param up_hops: list of HopOpaqueField of up_path
        @param core_inf: InfoOpaqueField for core_path
        @param core_hops: list of HopOpaqueFields of core_path
        @param dw_inf: InfoOpaqueField of down_path
        @param dw_hops: list of HopOpaqueField of down_path
        """
        if up_hops is None:
            up_hops = []
        if core_hops is None:
            core_hops = []
        if dw_hops is None:
            dw_hops = []

        cp = CorePath()
        cp.up_path_info = up_inf
        cp.up_path_hops = up_hops
        cp.core_path_info = core_inf
        cp.core_path_hops = core_hops
        cp.down_path_info = dw_inf
        cp.down_path_hops = dw_hops
        return cp

    def __str__(self):
        s = []
        s.append("<Core-Path>:\n")

        if self.up_path_info:
            s.append("<Up-Path>:\n")
            s.append(str(self.up_path_info) + "\n")
            for of in self.up_path_hops:
                s.append(str(of) + "\n")
            s.append("</Up-Path>\n")

        if self.core_path_info:
            s.append("<Core-Path>\n")
            s.append(str(self.core_path_info) + "\n")
            for of in self.core_path_hops:
                s.append(str(of) + "\n")
            s.append("</Core-Path>\n")

        if self.down_path_info:
            s.append("<Down-Path>\n")
            s.append(str(self.down_path_info) + "\n")
            for of in self.down_path_hops:
                s.append(str(of) + "\n")
            s.append("</Down-Path>\n")

        s.append("<Core-Path>")
        return "".join(s)


class CrossOverPath(PathBase):
    """
    A shortcut path using a cross-over link.

    The sequence of opaque fields for such a path is:
    | info OF up-path |  hop OF 1 | ... | hop OF N | upstream AD OF |
    | info OF down-path | upstream AD OF | hop OF 1 | ... | hop OF N |
    The upstream AD OF is needed to verify the last hop of the up-path / first
    hop of the down-path respectively.
    """

    def __init__(self, raw=None):
        PathBase.__init__(self)
        self.type = PathType.PEER_LINK
        self.up_path_upstream_ad = None
        self.down_path_upstream_ad = None

        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Parses the raw data and populates the fields accordingly.
        """
        assert isinstance(raw, bytes)
        # Parse up-path
        self.up_path_info = InfoOpaqueField(raw[:InfoOpaqueField.LEN])
        offset = InfoOpaqueField.LEN
        for i in range(self.up_path_info.hops):
            self.up_path_hops.append(
                HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN]))
            offset += HopOpaqueField.LEN
        self.up_path_upstream_ad = \
            HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN])
        offset += HopOpaqueField.LEN

        # Parse down-path
        self.down_path_info = \
            InfoOpaqueField(raw[offset:offset + InfoOpaqueField.LEN])
        offset += InfoOpaqueField.LEN
        self.down_path_upstream_ad = \
            HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN])
        offset += HopOpaqueField.LEN
        for i in range(self.down_path_info.hops):
            self.down_path_hops.append(
                HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN]))
            offset += HopOpaqueField.LEN

        self.parsed = True

    def pack(self):
        """
        Packs the opaque fields and returns a byte array.
        """
        data = []
        data.append(self.up_path_info.pack())
        for of in self.up_path_hops:
            data.append(of.pack())
        data.append(self.up_path_upstream_ad.pack())
        data.append(self.down_path_info.pack())
        data.append(self.down_path_upstream_ad.pack())
        for of in self.down_path_hops:
            data.append(of.pack())

        return b"".join(data)

    def reverse(self):
        # Reverse hops and info fields.
        PathBase.reverse(self)
        # Reverse upstream AD fields.
        self.up_path_upstream_ad, self.down_path_upstream_ad = \
            self.down_path_upstream_ad, self.up_path_upstream_ad

    def get_of(self, index):
        # Build temporary flat list of opaque fields.
        tmp = [self.up_path_info]
        tmp.extend(self.up_path_hops)
        tmp.append(self.up_path_upstream_ad)
        tmp.append(self.down_path_info)
        tmp.append(self.down_path_upstream_ad)
        tmp.extend(self.down_path_hops)
        return tmp[index]

    def __str__(self):
        s = []
        s.append("<CrossOver-Path>:\n<Up-Path>:\n")
        s.append(str(self.up_path_info) + "\n")
        for of in self.up_path_hops:
            s.append(str(of) + "\n")
        s.append("Upstream AD: " + str(self.up_path_upstream_ad) + "\n")
        s.append("</Up-Path>\n<Down-Path>\n")
        s.append(str(self.down_path_info) + "\n")
        s.append("Upstream AD: " + str(self.down_path_upstream_ad) + "\n")
        for of in self.down_path_hops:
            s.append(str(of) + "\n")
        s.append("</Down-Path>\n</CrossOver-Path>")

        return "".join(s)


class PeerPath(PathBase):
    """
    A shortcut path using a crossover link.

    The sequence of opaque fields for such a path is:
    | info OF up-path |  hop OF 1 | ... | hop OF N | peering link OF |
    | upstream AD OF | info OF down-path | upstream AD OF | peering link OF |
    | hop OF 1 | ... | hop OF N |
    The upstream AD OF is needed to verify the last hop of the up-path / first
    hop of the down-path respectively.
    """

    def __init__(self, raw=None):
        PathBase.__init__(self)
        self.type = PathType.PEER_LINK
        self.up_path_peering_link = None
        self.up_path_upstream_ad = None
        self.down_path_peering_link = None
        self.down_path_upstream_ad = None
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Parses the raw data and populates the fields accordingly.
        """
        assert isinstance(raw, bytes)
        # Parse up-path
        self.up_path_info = InfoOpaqueField(raw[:InfoOpaqueField.LEN])
        offset = InfoOpaqueField.LEN
        for i in range(self.up_path_info.hops):
            self.up_path_hops.append(
                HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN]))
            offset += HopOpaqueField.LEN
        self.up_path_peering_link = \
            HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN])
        offset += HopOpaqueField.LEN
        self.up_path_upstream_ad = \
            HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN])
        offset += HopOpaqueField.LEN


        # Parse down-path
        self.down_path_info = \
            InfoOpaqueField(raw[offset:offset + InfoOpaqueField.LEN])
        offset += InfoOpaqueField.LEN
        self.down_path_upstream_ad = \
            HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN])
        offset += HopOpaqueField.LEN
        self.down_path_peering_link = \
            HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN])
        offset += HopOpaqueField.LEN
        for i in range(self.down_path_info.hops):
            self.down_path_hops.append(
                HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN]))
            offset += HopOpaqueField.LEN

        self.parsed = True

    def pack(self):
        """
        Packs the opaque fields and returns a byte array.
        """
        data = []
        data.append(self.up_path_info.pack())
        for of in self.up_path_hops:
            data.append(of.pack())
        data.append(self.up_path_peering_link.pack())
        data.append(self.up_path_upstream_ad.pack())
        data.append(self.down_path_info.pack())
        data.append(self.down_path_upstream_ad.pack())
        data.append(self.down_path_peering_link.pack())
        for of in self.down_path_hops:
            data.append(of.pack())

        return b"".join(data)

    def reverse(self):
        # Reverse hop and info fields.
        PathBase.reverse(self)
        # Reverse upstream AD and peering link fields.
        self.up_path_upstream_ad, self.down_path_upstream_ad = \
            self.down_path_upstream_ad, self.up_path_upstream_ad
        self.up_path_peering_link, self.down_path_peering_link = \
            self.down_path_peering_link, self.up_path_peering_link

    def get_of(self, index):
        # Build temporary flat list of opaque fields.
        tmp = [self.up_path_info]
        tmp.extend(self.up_path_hops)
        tmp.append(self.up_path_peering_link)
        tmp.append(self.up_path_upstream_ad)
        tmp.append(self.down_path_info)
        tmp.append(self.down_path_upstream_ad)
        tmp.append(self.down_path_peering_link)
        tmp.extend(self.down_path_hops)
        return tmp[index]

    def __str__(self):
        s = []
        s.append("<Peer-Path>:\n<Up-Path>:\n")
        s.append(str(self.up_path_info) + "\n")
        for of in self.up_path_hops:
            s.append(str(of) + "\n")
        s.append("Upstream AD: " + str(self.up_path_upstream_ad) + "\n")
        s.append("Peering link: " + str(self.up_path_peering_link) + "\n")
        s.append("</Up-Path>\n<Down-Path>\n")
        s.append(str(self.down_path_info) + "\n")
        s.append("Peering link: " + str(self.down_path_peering_link) + "\n")
        s.append("Upstream AD: " + str(self.down_path_upstream_ad) + "\n")
        for of in self.down_path_hops:
            s.append(str(of) + "\n")
        s.append("</Down-Path>\n</Peer-Path>")

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
        self.up_path_info = InfoOpaqueField(raw[:InfoOpaqueField.LEN])
        # We do this so we can still reverse the path.
        self.down_path_info = self.up_path_info

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
        return self.up_path_info

    def __str__(self):
        return "<Empty-Path></Empty-Path>"


class PathCombinator(object):
    """
    Class that contains functions required to build end-to-end SCION paths.
    """

    @staticmethod
    def _build_core_path(up_path, core_path, down_path):
        """
        Joins up_, core_ and down_path into core fullpath. core_path can be
        'None' in case of a intra-ISD core_path of length 0.
        Returns object of CorePath class.
        """
        if not up_path or not down_path or not up_path.ads or not down_path.ads:
            return None

        # If we have a core path, check that the core_path connects the
        # up_ and down_path. Otherwise, check that up- and down-path meet at a
        # single core AD.
        if ((core_path and
             (core_path.get_first_ad().ad_id != up_path.get_first_ad().ad_id or
             core_path.get_last_ad().ad_id != down_path.get_first_ad().ad_id)) or
             (not core_path and
              (up_path.get_first_ad().ad_id != down_path.get_first_ad().ad_id))):
            return None

        full_path = CorePath()
        full_path.up_path_info = up_path.iof
        for block in reversed(up_path.ads):
            full_path.up_path_hops.append(copy.deepcopy(block.pcbm.hof))
        full_path.up_path_hops[-1].info = OpaqueFieldType.LAST_OF

        if core_path:
            full_path.core_path_info = core_path.iof
            for block in core_path.ads:
                full_path.core_path_hops.append(copy.deepcopy(block.pcbm.hof))
            full_path.core_path_hops[0].info = OpaqueFieldType.LAST_OF

        full_path.down_path_info = down_path.iof
        for block in down_path.ads:
            full_path.down_path_hops.append(copy.deepcopy(block.pcbm.hof))
        full_path.down_path_hops[0].info = OpaqueFieldType.LAST_OF
        return full_path

    @staticmethod
    def _join_shortcuts(up_path, down_path, point, peer=True):
        """
        Joins up_ and down_path (objects of PCB class) into shortcut fullpath.
        Depending on scenario returns object of PeerPath or CrossOverPath class.
        point: tuple (up_path_index, down_path_index) position of peer/xovr link
        peer:  true for peer, false for xovr path
        """
        up_path = copy.deepcopy(up_path)
        down_path = copy.deepcopy(down_path)
        (up_index, dw_index) = point

        if peer:
            path = PeerPath()
            info = OpaqueFieldType.INTRATD_PEER
        else:
            path = CrossOverPath()
            info = OpaqueFieldType.NON_TDC_XOVR

        path.up_path_info = up_path.iof
        path.up_path_info.info = info
        path.up_path_info.hops -= up_index
        for i in reversed(range(up_index, len(up_path.ads))):
            path.up_path_hops.append(up_path.ads[i].pcbm.hof)
        path.up_path_hops[-1].info = OpaqueFieldType.LAST_OF
        path.up_path_upstream_ad = up_path.ads[up_index - 1].pcbm.hof

        if peer:
            up_ad = up_path.ads[up_index]
            down_ad = down_path.ads[dw_index]
            for up_peer in up_ad.pms:
                for down_peer in down_ad.pms:
                    if (up_peer.ad_id == down_ad.pcbm.ad_id and
                            down_peer.ad_id == up_ad.pcbm.ad_id):
                        path.up_path_peering_link = up_peer.hof
                        path.down_path_peering_link = down_peer.hof

        path.down_path_info = down_path.iof
        path.down_path_info.info = info
        path.down_path_info.hops -= dw_index
        path.down_path_upstream_ad = down_path.ads[dw_index - 1].pcbm.hof
        for i in range(dw_index, len(down_path.ads)):
            path.down_path_hops.append(down_path.ads[i].pcbm.hof)
        path.down_path_hops[0].info = OpaqueFieldType.LAST_OF

        return path

    @staticmethod
    def _build_shortcut_path(up_path, down_path):
        """
        Takes PCB objects (up/down_path) and tries to combine them as short path
        """
        # TODO check if stub ADs are the same...
        if not up_path or not down_path or not up_path.ads or not down_path.ads:
            return None
        # looking for xovr and peer points
        xovrs = []
        peers = []
        for up_i in range(1, len(up_path.ads)):
            for down_i in range(1, len(down_path.ads)):
                up_ad = up_path.ads[up_i]
                down_ad = down_path.ads[down_i]
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
                return PathCombinator._join_shortcuts(up_path, down_path,
                                                      peers[-1], True)
            else:
                return PathCombinator._join_shortcuts(up_path, down_path,
                                                      xovrs[-1], False)
        elif xovrs:
            return PathCombinator._join_shortcuts(up_path, down_path,
                                                  xovrs[-1],
                                                  False)
        else:  # peers only
            return PathCombinator._join_shortcuts(up_path, down_path,
                                                  peers[-1],
                                                  True)

    @staticmethod
    def build_shortcut_paths(up_paths, down_paths):
        """
        Returns a list of all shortcut paths (peering and crossover paths) that
        can be built using the provided up- and down-paths.
        """
        paths = []
        for up in up_paths:
            for down in down_paths:
                path = PathCombinator._build_shortcut_path(up, down)
                if path and path not in paths:
                    paths.append(path)

        return paths

    @staticmethod
    def build_core_paths(up_path, down_path, core_paths):
        """
        Returns list of all paths that can be built as combination of paths from
        up_paths, core_paths and down_paths.
        """
        paths = []
        if not core_paths:
            paths.append(PathCombinator._build_core_path(up_path,
                                                         [],
                                                         down_path))
        else:
            for core_path in core_paths:
                path = PathCombinator._build_core_path(up_path,
                                                       core_path,
                                                       down_path)
                if path and path not in paths:
                    paths.append(path)
        return paths

