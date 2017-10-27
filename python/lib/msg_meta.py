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
:mod:`msg_meta` --- Message Metadata
====================================
"""
from lib.packet.scion_addr import SCIONAddr


class MetadataBase(object):
    """
    Base class for message metadata
    """
    def __init__(self):
        self.ia = None
        self.host = None
        self.path = None  # Ready for sending (i.e., in correct direction)
        self.port = 0
        self.ext_hdrs = ()

    @classmethod
    def from_values(cls, ia=None, host=None, path=None, ext_hdrs=(),
                    reuse=False, port=0):
        inst = cls()
        inst.ia = ia
        inst.host = host
        inst.path = path
        inst.ext_hdrs = ext_hdrs
        inst.port = port
        inst.reuse = reuse  # Indicates to reuse a socket (useful for TCP)
        return inst

    def get_addr(self):
        return SCIONAddr.from_values(self.ia, self.host)

    def close(self):  # Close communication between peers.
        pass

    def __str__(self):
        return "%s:%d" % (self.get_addr(), self.port)


class UDPMetadata(MetadataBase):
    """
    Class for UDP message metadata
    """
    pass


class SCMPMetadata(MetadataBase):
    """
    Class for SCMP message metadata
    """
    pass


class TCPMetadata(MetadataBase):
    """
    Class for TCP message metadata
    """
    @classmethod
    def from_values(cls, ia=None, host=None, path=None,
                    ext_hdrs=(), port=0, sock=None, flags=0):
        inst = super().from_values(ia, host, path, ext_hdrs, port)
        inst.sock = sock
        inst.flags = flags
        return inst

    def close(self):
        self.sock.active = False


class SockOnlyMetadata:
    def __init__(self):
        self.sock = None

    @classmethod
    def from_values(cls, sock):
        inst = SockOnlyMetadata()
        inst.sock = sock
        return inst

    def __str__(self):
        return "Unix Socket: Fd: %d" % (self.sock.sock.fileno())
