# Copyright 2015 ETH Zurich
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
:mod:`path_transport` --- path_transport extension header
=========================================================
"""
# Stdlib
import math
import struct

# SCION
from lib.errors import SCIONParseError
from lib.packet.ext_hdr import EndToEndExtension
from lib.packet.opaque_field import OpaqueField
from lib.packet.packet_base import HeaderBase
from lib.packet.path import parse_path
from lib.packet.pcb import PathSegment
from lib.packet.scion_addr import SCIONAddr
from lib.types import ExtEndToEndType
from lib.util import calc_padding, Raw


class PathTransOFPath(HeaderBase):
    """
    Class used by PathTransportExt to encapsulate a path in data-plane format.
    """
    NAME = "PathTransOFPath"
    MIN_LEN = 2

    def __init__(self, raw=None):
        """
        Initialize an instance of the class PathTransOFPath.

        :param raw:
        :type raw:
        """
        self.src_addr = None
        self.dst_addr = None
        self.path = None
        if raw is not None:
            self._parse(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.MIN_LEN, min_=True)
        src_type = data.pop(1)
        dst_type = data.pop(1)
        self.src_addr = SCIONAddr((src_type, data.get()))
        data.pop(len(self.src_addr))
        self.dst_addr = SCIONAddr((dst_type, data.get()))
        data.pop(len(self.dst_addr))
        padding_len = len(data) % OpaqueField.LEN
        self.path = parse_path(data.pop(len(data) - padding_len))

    @classmethod
    def from_values(cls, src_addr, dst_addr, path):
        inst = cls()
        inst.src_addr = src_addr
        inst.dst_addr = dst_addr
        inst.path = path
        return inst

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.src_addr.host_addr.TYPE))
        packed.append(struct.pack("!B", self.dst_addr.host_addr.TYPE))
        packed.append(self.src_addr.pack())
        packed.append(self.dst_addr.pack())
        packed.append(self.path.pack())
        return b"".join(packed)

    def __len__(self):
        return len(self.pack())

    def __str__(self):
        return "%s->%s\n%s" % (self.src_addr, self.dst_addr, self.path)


class PathTransType(object):
    OF_PATH = 0
    PCB_PATH = 1


class PathTransportExt(EndToEndExtension):
    """
    For path of type OF_PATH, the  header is presented below, path is in
    data-plane format and instantiated as object of PathTransOFPath.
    0B       1        2        3        4        5        6        7
    +--------+--------+--------+--------+--------+--------+--------+--------+
    | xxxxxxxxxxxxxxxxxxxxxxxx |OF_PATH |src_type|dst_type|  scion_src_addr |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |     (cont., var len)     |         scion_dst_addr (var len)           |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |    Path (list of opaque fields, var len) + padding (if necessary)     |
    +--------+--------+--------+--------+--------+--------+--------+--------+

    For path of type PCB_PATH, the  header is presented below, path is in
    control-plane format and instantiated as object of PathSegment.
    0B       1        2        3        4        5        6        7
    +--------+--------+--------+--------+--------+--------+--------+--------+
    | xxxxxxxxxxxxxxxxxxxxxxxx |PCB_PATH|       Path (as PathSegment)       |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |             Path (cont., var len) + padding (if necessary)            |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    """
    NAME = "PathTransportExt"
    EXT_TYPE = ExtEndToEndType.PATH_TRANSPORT

    def __init__(self, raw=None):
        """
        Initialize an instance of the class PathTransportExt

        :param raw:
        :type raw:
        """
        super().__init__()
        self.path_type = None
        self.path = None
        if raw is not None:
            self._parse(raw)

    @classmethod
    def from_values(cls, path_type, path):
        """
        Construct extension with a path of type path_type.
        """
        inst = cls()
        inst.path_type = path_type
        inst.path = path
        plen = len(inst.path.pack())
        # How many additional lines are needed for a path.
        inst._init_size(math.ceil((plen - 4) / inst.LINE_LEN))
        return inst

    def _parse(self, raw):
        """
        Parse payload to extract path.
        """
        data = Raw(raw, self.NAME, self.MIN_LEN, min_=True)
        super()._parse(data)
        self.path_type = data.pop(1)
        if self.path_type == PathTransType.OF_PATH:
            self.path = PathTransOFPath(data.pop())
        elif self.path_type == PathTransType.PCB_PATH:
            self.path = PathSegment(data.pop())
        else:
            raise SCIONParseError("Unsupported path type: %s", self.path_type)

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.path_type))
        path_packed = self.path.pack()
        packed.append(path_packed)
        # Add possible padding.
        packed.append(bytes(calc_padding(len(path_packed) - 4, self.LINE_LEN)))
        raw = b"".join(packed)
        self._check_len(raw)
        return raw

    def __str__(self):  # pragma: no cover
        tmp = ["%s(%dB):" % (self.NAME, len(self))]
        tmp.append("  Path type: %d\n  %s" % (self.path_type, self.path))
        return "\n".join(tmp)
