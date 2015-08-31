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
:mod:`packet_base` --- Packet base class
========================================
"""


class HeaderBase(object):
    """
    Base class for headers.

    Each header class must implement parse, pack and __str__.

    :ivar parsed: whether or not the header has been parsed.
    :vartype parsed: bool
    """

    def __init__(self):
        """
        Initialize an instance of the class HeaderBase.
        """
        self.parsed = False

    def parse(self, raw):
        pass

    def pack(self):
        pass

    def __len__(self):
        pass

    def __str__(self):
        pass

    def __repr__(self):
        return self.__str__()


class PacketBase(object):
    """
    Base class for packets.

    :ivar parsed: whether or not the packet has been parsed.
    :vartype parsed: bool
    :ivar raw: the raw bytes of the packet contents.
    :vartype raw: bytes
    :ivar hdr: the packet header.
    :vartype hdr: :class:`HeaderBase`
    :ivar payload: the packet payload
    :vartype payload: :class:`PacketBase` or bytes
    """

    def __init__(self):
        """
        Initialize an instance of the class PacketBase.
        """
        self._hdr = None
        self._payload = None
        self.parsed = False
        self.raw = None

    def get_payload(self):
        """
        Returns the packet payload.
        """
        return self._payload

    def set_payload(self, new_payload):
        """
        Set the packet payload.  Expects bytes or a Packet subclass.
        """
        if (not isinstance(new_payload, PacketBase) and
                not isinstance(new_payload, PayloadBase) and
                not isinstance(new_payload, bytes)):
            raise TypeError("payload must be bytes or packet/payload subclass.")
        else:
            self._payload = new_payload

    @property
    def hdr(self):
        """
        Returns the packet header.
        """
        return self._hdr

    @hdr.setter
    def hdr(self, new_hdr):
        self.set_hdr(new_hdr)

    def set_hdr(self, new_hdr):
        """
        Sets the packet header. Expects a Header subclass.
        """
        if not isinstance(new_hdr, HeaderBase):
            raise TypeError("hdr must be a header subclass.")
        else:
            self._hdr = new_hdr

    def parse(self, raw):
        pass

    def pack(self):
        pass

    def __len__(self):
        return len(self.hdr) + len(self._payload)

    def __str__(self):
        s = []
        s.append(str(self.hdr) + "\n")
        s.append("Payload:\n" + str(self._payload))
        return "".join(s)

    def __repr__(self):
        return self.__str__()

    def __hash__(self):
        return hash(self.pack())

    def __eq__(self, other):
        if type(other) is type(self):
            return self.raw == other.raw
        else:
            return False


class PayloadBase(object):
    """
    Interface that payloads of packets must implement.
    """
    def __init__(self):
        """
        Initialize an instance of the class PayloadBase.
        """
        self.raw = None
        self.parsed = False

    def parse(self, raw):
        self.raw = raw

    def pack(self):
        return self.raw

    def __len__(self):
        if self.raw is not None:
            return len(self.raw)
        else:
            return 0

    def __hash__(self):
        return hash(self.raw)

    def __eq__(self, other):
        if type(other) is type(self):
            return self.raw == other.raw
        else:
            return False
