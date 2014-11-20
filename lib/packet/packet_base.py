"""
packet_base.py

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


class HeaderBase(object):
    """
    Base class for headers.

    Each header class must implement parse, pack and __str__.

    Attributes:
        parsed: a boolean indicating whether the header has been parsed.
    """

    def __init__(self):
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

    Attributes:
        parsed: a boolean indicating whether the packet has been parsed.
        raw: a bytes literal representing the raw bytes of the packet.
        hdr: a header (subclass of HeaderBase) representing the packet header.
        payload: a packet (subclass of PacketBase) or bytes literal
            representing the packet payload.
    """

    def __init__(self):
        self._hdr = None
        self._payload = None
        self.parsed = False
        self.raw = None

    @property
    def payload(self):
        """
        Returns the packet payload.
        """
        return self._payload

    @payload.setter
    def payload(self, new_payload):
        """
        Set the packet payload.  Expects bytes or a Packet subclass.
        """
        if (not isinstance(new_payload, PacketBase) and
            not isinstance(new_payload, bytes)):
            raise TypeError("payload must be bytes or packet subclass.")
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
        return len(self.hdr) + len(self.payload)

    def __str__(self):
        s = []
        s.append(str(self.hdr) + "\n")
        s.append("Payload:\n" + str(self.payload))
        return "".join(s)

    def __repr__(self):
        return self.__str__()
