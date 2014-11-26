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

from lib.packet.opaque_field import *


class PathType(object):
    """
    Defines constants for the SCION path types.
    """
    EMPTY = 0x00  # Empty path
    CORE = 0x80  # Path to the core
    CROSS_OVER = 0xc0  # Path with cross over
    PEER_LINK = 0xf0  # Path with peer link


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

    def get_first_hop(self):
        """
        Returns the first up_path hop.
        """
        return self.up_path_hops[0]

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
    | info OF up-path | hop OF 1 | ... | hop OF N | info OF down-path |
    | hop OF 1 | ... | hop OF N |
    """
    def __init__(self, raw=None):
        PathBase.__init__(self)
        self.type = PathType.CORE

        if raw is not None:
            self.parse(raw)

# TODO PSz: a flag is needed to distinguish downPath-only case. I.e. if
# SCIONPacket.up_path is false and path has only one special OF, then it should
# parse only DownPath. It would be easier to put down/up flag to SOF.
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
        if self.down_path_info:
            data.append(self.down_path_info.pack())
            for of in self.down_path_hops:
                data.append(of.pack())

        return b"".join(data)

    @classmethod
    def from_values(cls, iof, hofs):
        cp = CorePath()
        cp.up_path_info = iof
        cp.up_path_hops = hofs
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
   
    This is currently need for intra AD communication, which doesn't need
    a SCION path but still uses SCION packets for communication.
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
        return b'' #TODO(PSz): Empty Path should pack to b'', not '\x00'*8 
        # return self.up_path_info.pack()
    
    def is_first_hop(self, hop):
        return True
    
    def is_last_hop(self, hop):
        return True
    
    def get_first_hop(self):
        return None
    
    def get_of(self, index):
        return self.up_path_info
    
    def __str__(self):
        return "<Empty-Path></Empty-Path>"
