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

# External
import capnp

# SCION
import proto.scion_capnp as P
from lib.errors import SCIONParseError
from lib.util import hex_str


class Serializable(object, metaclass=ABCMeta):  # pragma: no cover
    """
    Base class for all objects which serialize into raw bytes.
    """
    def __init__(self, raw=None):
        if raw:
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


class Cerealizable(object, metaclass=ABCMeta):
    """
    Base class for all objects which serialize to Cap'n Proto.

    Each subclass needs to specify a class attribute for the corresponding
    proto file (P) and the proto message name (P_CLS), e.g.,

    P = capnp.load("proto/foo.capnp")
    P_CLS = P.Foo
    """
    def __init__(self, p):
        assert not isinstance(p, bytes)
        self.p = p
        self._packed = False

    @classmethod
    def from_raw(cls, raw):
        assert isinstance(raw, bytes), type(raw)
        try:
            return cls(cls.P_CLS.from_bytes_packed(raw).as_builder())
        except capnp.lib.capnp.KjException as e:
            raise SCIONParseError("Unable to parse %s capnp message: %s" %
                                  (cls, e)) from None

    @classmethod
    def from_raw_multiple(cls, raw):
        assert isinstance(raw, bytes), type(raw)
        try:
            for p in cls.P_CLS.read_multiple_bytes_packed(raw):
                yield cls(p.as_builder())
        except capnp.lib.capnp.KjException as e:
            raise SCIONParseError("Unable to parse %s capnp message: %s" %
                                  (cls, e)) from None

    @abstractmethod
    def from_values(self, *args, **kwargs):
        raise NotImplementedError

    @classmethod
    def from_dict(cls, d):
        return cls(cls.P_CLS.new_message(**d))

    def to_dict(self):
        return self.p.to_dict()

    def pack(self, *args, **kwargs):
        assert not self._packed, "May only be packed once"
        self._packed = True
        return self._pack(*args, **kwargs)

    def _pack(self):
        return self.p.to_bytes_packed()

    def __bool__(self):
        return True

    def __len__(self):
        return self.p.total_size.word_count * 8

    def copy(self):
        return type(self)(self.p.copy())

    def __copy__(self):
        return type(self)(self.p.copy())

    def __deepcopy__(self, memo):
        # http://stackoverflow.com/a/15774013
        inst = type(self)(self.p.copy())
        memo[id(self)] = inst
        return inst

    def __eq__(self, other):  # pragma: no cover
        raise NotImplementedError

    def short_desc(self):
        return str(self.p)

    def __str__(self):
        return "%s: %s" % (self.NAME, self.short_desc())


class L4HeaderBase(Serializable, metaclass=ABCMeta):  # pragma: no cover
    """
    Base class for L4 headers.
    """
    TYPE = None

    def pack(self, payload, checksum=None):
        self.total_len = self.LEN + len(payload)
        if checksum is None:
            checksum = self._calc_checksum(payload)
        return self._pack(checksum)

    @abstractmethod
    def validate(self, payload):
        raise NotImplementedError


class PacketBase(Serializable):  # pragma: no cover
    """
    Base class for packets.
    """
    def __init__(self, raw=None):
        """
        Initialize an instance of the class PacketBase.
        """
        self._payload = b""
        super().__init__(raw)

    def get_payload(self):
        return self._payload

    def set_payload(self, new_payload):
        assert isinstance(new_payload, (PayloadBase, SCIONPayloadBaseProto))
        self._payload = new_payload


class PayloadBase(Serializable):  # pragma: no cover
    """
    Interface that payloads of packets must implement.
    """
    METADATA_LEN = 0

    def pack_meta(self):
        return b""

    def pack_full(self):
        return self.pack_meta() + self.pack()

    def total_len(self):
        return self.METADATA_LEN + len(self)


class PayloadRaw(PayloadBase):  # pragma: no cover
    SNIPPET_LEN = 32

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
        s = "PayloadRaw(%dB): %s" % (len(self._raw),
                                     hex_str(self._raw[:self.SNIPPET_LEN]))
        if len(self._raw) > self.SNIPPET_LEN:
            s += "[...]"
        return s


class SCIONPayloadBaseProto(Cerealizable):  # pragma: no cover
    """
    All child classes must define the PAYLOAD_CLASS attributed, defined by
    lib.types.PayloadClass
    """
    # 4B length prepended to the capnp block
    METADATA_LEN = 4
    PAYLOAD_TYPE = None

    def pack_full(self):
        assert not self._packed, "May only be packed once"
        self._packed = True
        return self._pack_full(self.p)

    def _pack_full(self, p):
        wrapper = P.SCION.new_message(**{self.PAYLOAD_CLASS: p})
        raw = wrapper.to_bytes_packed()
        meta = struct.pack("!I", len(raw))
        return meta + raw
