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
from abc import ABCMeta, abstractmethod

# External
import capnp

# SCION
from lib.errors import SCIONParseError, SCIONTypeError
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
        assert not isinstance(p, bytes), type(p)
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
    def from_proto(cls, p):  # pragma: no cover
        return cls(p)

    def proto(self):
        return self.p

    @classmethod
    def from_dict(cls, d):
        return cls(cls.P_CLS.new_message(**d))

    def to_dict(self):
        return self.proto().to_dict()

    def pack(self, *args, **kwargs):
        assert not self._packed, "May only be packed once"
        self._packed = True
        return self._pack(*args, **kwargs)

    def _pack(self):
        return self.proto().to_bytes_packed()

    def __bool__(self):
        return True

    def __len__(self):
        return self.proto().total_size.word_count * 8

    def copy(self):
        return type(self)(self.proto().copy())

    def __copy__(self):
        return type(self)(self.proto().copy())

    def __deepcopy__(self, memo):
        # http://stackoverflow.com/a/15774013
        inst = type(self)(self.p.copy())
        memo[id(self)] = inst
        return inst

    def __eq__(self, other):  # pragma: no cover
        raise NotImplementedError

    def short_desc(self):
        return str(self.proto())

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
        assert isinstance(new_payload, (Serializable, CerealBox)), type(new_payload)
        self._payload = new_payload


class CerealBox(object, metaclass=ABCMeta):
    """
    CerealBox represents capnp structs that have a unnamed union. In the simplest case, a CerealBox
    object contains a Cerealizable object, but CerealBoxes can also be nested
    (e.g. CtrlPayload(PathMgmt(RevInfo.from_values(...)))).

    All child classes must define the NAME, P_CLS, and CLASS_FIELD_MAP attributes.
    """
    def __init__(self, union):
        self.union = union

    @classmethod
    def from_proto(cls, p):  # pragma: no cover
        """
        Internal constructor, used by sub-classes to create the corresponding python object from a
        capnp object. The appropriate python class is selected by looking up the union field name in
        CLASS_FIELD_MAP.
        """
        type_ = p.which()
        for cls_, field in cls.CLASS_FIELD_MAP.items():
            if type_ == field:
                return cls._from_union(p, cls_.from_proto(getattr(p, type_)))
        raise SCIONParseError("Unsupported %s proto type: %s" % (cls.NAME, type_))

    @classmethod
    def _from_union(cls, p, union):  # pragma: no cover
        """
        Internal constructor, overridden by sub-classes which have more fields than just a single
        unnamed union.

        p is passed in to be available to subclasses which override this.
        """
        return cls(union)

    def proto(self):
        """
        Return the corresponding capnp object.
        """
        return self.P_CLS.new_message(**{self.type(): self.union.proto()})

    def type(self):
        """
        Return the type of the union, represented by the union field name.
        """
        c = self.CLASS_FIELD_MAP.get(self.union.__class__)
        if c is not None:
            return c
        raise SCIONTypeError("Unsupported %s proto class %s (%s)" %
                             (self.NAME, self.union.__class__, type(self.union)))

    def inner_type(self):
        """
        Return the type of the innermost Cerealizable object, represented by the union field name in
        the innermost CerealBox object.
        """
        if isinstance(self.union, CerealBox):
            return self.union.inner_type()
        return self.type()

    def pack(self):
        return self.proto().to_bytes_packed()

    def copy(self):
        return self.__class__(self.union.copy())

    def __len__(self):
        return self.proto().total_size.word_count * 8

    def __str__(self):
        return "%s(%dB): %s" % (self.NAME, len(self), self.union)


class PayloadRaw(Serializable):  # pragma: no cover
    NAME = "PayloadRaw"
    SNIPPET_LEN = 32

    def __init__(self, raw=None):
        self._raw = b""
        super().__init__(raw)

    def _parse(self, raw):
        self._raw = raw or b""

    def from_values(cls, raw):
        assert isinstance(raw, bytes), type(raw)
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
        s = "%s(%dB): %s" % (
            self.NAME, len(self._raw), hex_str(self._raw[:self.SNIPPET_LEN]))
        if len(self._raw) > self.SNIPPET_LEN:
            s += "[...]"
        return s
