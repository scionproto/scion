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
# Stdlib
import struct
from abc import ABCMeta, abstractmethod

# SCION
from lib.types import PayloadClass
from lib.util import hex_str


class HeaderBase(object, metaclass=ABCMeta):  # pragma: no cover
    """
    Base class for headers.
    """
    def __init__(self, raw=None):
        if raw is not None:
            self._parse(raw)

    @abstractmethod
    def _parse(self, raw):
        raise NotImplementedError

    @abstractmethod
    def from_values(self, *args, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def pack(self):
        raise NotImplementedError

    @abstractmethod
    def __len__(self):
        raise NotImplementedError

    @abstractmethod
    def __str__(self):
        raise NotImplementedError


class L4HeaderBase(HeaderBase):
    """
    Base class for L4 headers.
    """
    TYPE = None


class PacketBase(object, metaclass=ABCMeta):  # pragma: no cover
    """
    Base class for packets.
    """
    def __init__(self, raw=None):
        """
        Initialize an instance of the class PacketBase.
        """
        self._payload = b""
        if raw is not None:
            self._parse(raw)

    @abstractmethod
    def _parse(self, raw):
        raise NotImplementedError

    @abstractmethod
    def from_values(self, raw):
        raise NotImplementedError

    @abstractmethod
    def pack(self):
        raise NotImplementedError

    def get_payload(self):
        return self._payload

    def set_payload(self, new_payload):
        assert isinstance(new_payload, PayloadBase)
        self._payload = new_payload

    @abstractmethod
    def __len__(self):
        raise NotImplementedError

    @abstractmethod
    def __str__(self):
        raise NotImplementedError


class PayloadBase(object, metaclass=ABCMeta):  # pragma: no cover
    """
    Interface that payloads of packets must implement.
    """
    METADATA_LEN = 0

    def __init__(self, raw=None):
        if raw is not None:
            self._parse(raw)

    @abstractmethod
    def _parse(self, raw):
        raise NotImplementedError

    @abstractmethod
    def from_values(self, raw):
        raise NotImplementedError

    @abstractmethod
    def pack(self):
        raise NotImplementedError

    def pack_meta(self):
        return b""

    def pack_full(self):
        return self.pack_meta() + self.pack()

    def total_len(self):
        return self.METADATA_LEN + len(self)

    @abstractmethod
    def __len__(self):
        raise NotImplementedError

    @abstractmethod
    def __str__(self):
        raise NotImplementedError


class PayloadRaw(PayloadBase):  # pragma: no cover
    def __init__(self, raw=None):
        self._raw = b""
        super().__init__(raw)

    def _parse(self, raw):
        self._raw = raw or b""

    def from_values(cls, raw):
        assert isinstance(raw, bytes)
        inst = cls()
        inst._raw = raw
        return inst

    def pack(self):
        return self._raw

    def __eq__(self, other):
        return self._raw == other._raw

    def __len__(self):
        return len(self._raw)

    def __str__(self):
        return hex_str(self._raw)


class SCIONPayloadBase(PayloadBase):  # pragma: no cover
    """
    All child classes must define two attributes:
        PAYLOAD_CLASS: Global payload class, defined by PayloadClass.
        PAYLOAD_TYPE: Payload type specific to that class. Defined by the
        various payload classes
    """
    # 1B each for payload class and type.
    METADATA_LEN = 2

    def pack_meta(self):
        return struct.pack("!BB", self.PAYLOAD_CLASS, self.PAYLOAD_TYPE)


class PathMgmtPayloadBase(SCIONPayloadBase):
    PAYLOAD_CLASS = PayloadClass.PATH
    PAYLOAD_TYPE = None
