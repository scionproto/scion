# Copyright 2017 ETH Zurich
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
:mod:`types` --- DRKey types
============================

For all type classes used in DRKey
"""

# stdlib
import struct

# SCION
from lib.crypto.symcrypto import mac
from lib.packet.packet_base import Cerealizable
from lib.types import TypeBase, AddrType


###########################
# DRKey types
###########################

# Block size of AES-128
BLOCK_SIZE = 16


class DRKeyProtoKeyType(TypeBase):
    """ Available protocol DRKey types."""
    AS_TO_AS = 0
    AS_TO_HOST = 1
    HOST_TO_HOST = 2
    AS_TO_HOST_PAIR = 3


class DRKeyProtocols(TypeBase):
    """ Available protocols. Protocol must be registered in suite._protocol_map"""
    OPT = 0
    SCMP_AUTH = 1


class DRKeyMiscType(TypeBase):
    """ Available misc types. """
    UNSET = "unset"
    OPT = "opt"


class DRKeyMiscBase(Cerealizable):
    """ Basis for DRKeyProtocolRequest and DRKeyProtocolReply misc types. """
    pass


class DRKeyInputType(TypeBase):
    """
    Input type for second order DRKey derivation. The derivation has either 0, 1 or 2 addresses
    as input. DRKeyInputType is used to protect against input which differs but could result in
    the same DRKey: eg. [0.0.0.0, 0::0] and [0::0, 0.0.0.0] result in the same input except for
    the DRKeyInputType.
    """
    _IPV4 = 1                   # 0001
    _IPV6 = 2                   # 0010
    _SVC = 3                    # 0011

    NONE = 0                    # 0000
    IPV4 = 4                    # 0100
    IPV6 = 8                    # 1000
    SVC = 12                    # 1100

    IPV4_IPV4 = IPV4 | _IPV4    # 0101
    IPV4_IPV6 = IPV4 | _IPV6    # 0110
    IPV4_SVC = IPV4 | _SVC      # 0111

    IPV6_IPV4 = IPV6 | _IPV4    # 1001
    IPV6_IPV6 = IPV6 | _IPV4    # 1010
    IPV6_SVC = IPV6 | _SVC      # 1011

    SVC_IPV4 = SVC | _IPV4      # 1101
    SVC_IPV6 = SVC | _IPV6      # 1110
    SVC_SVC = SVC | _SVC        # 1111

    @classmethod
    def from_hosts(cls, first=None, second=None):
        """
        Returns the DRKeyInputType based on the input.
        If second is set, first has to be set as well.

        :param HostAddrBase first: first host in the input. (Can be None)
        :param HostAddrBase second: second host in the input. (Can be None)
        :returns: the input type.
        :rtype: int
        """
        assert first or not second
        input_type = cls.NONE
        if not first:
            return input_type
        if first.TYPE == AddrType.IPV4:
            input_type |= cls.IPV4
        elif first.TYPE == AddrType.IPV6:
            input_type |= cls.IPV6
        elif first.TYPE == AddrType.SVC:
            input_type |= cls.SVC
        if not second:
            return input_type
        if second.TYPE == AddrType.IPV4:
            input_type |= cls._IPV4
        elif second.TYPE == AddrType.IPV6:
            input_type |= cls._IPV6
        elif second.TYPE == AddrType.SVC:
            input_type |= cls.SVC
        return input_type


class DRKeyProtocolBase(object):
    """ Base class for a DRKey protocol."""
    # the prefix used for key derivation. At most 255 bytes.
    PREFIX = b""

    @staticmethod
    def verify_request(request, meta):
        """
        Verify that a second order DRKey request is valid.
        I.e. the requester is allowed to request the key the timestamp is recent, the
        request is well formed.

        :param DRKeyProtocolRequest request: the protocol DRKey request.
        :param UDPMetadata meta: the metadata
        :raises: SCIONVerificationError if the request is invalid.
        """
        raise NotImplementedError()

    @staticmethod
    def required_drkeys(request, meta):
        """
        Returns a list of the needed first order DRKey required to derive the second order
        DRKey and misc.

        :param DRKeyProtocolRequest request: the protocol DRKey request.
        :param UDPMetadata meta: the metadata.
        :returns: list of needed first order DRKeys.
        :rtype: [FirstOrderDRKey]
        """
        raise NotImplementedError()

    @classmethod
    def generate_drkey(cls, drkeys, request, meta):
        """
        Generate the raw second order DRKey.

        :param [FirstOrderDRKey] drkeys: list of the required first order DRKeys.
        :param DRKeyProtocolRequest request: the protocol DRKey request.
        :param UDPMetadata meta: the metadata.
        :returns: the raw second order DRKey.
        :rtype: bytes
        """
        raise NotImplementedError()

    @classmethod
    def _derive_drkey(cls, drkey, first=None, second=None):
        """
        Derive raw second order DRKey. Prepends the type of the input and the length of the
        protocol prefix befor deriving.

        :param FirstOrderDRKey drkey: First order DRKey used for derivation.
        :param HostAddrBase first: First host address in the input
        :param HostAddrBase second: Second host address in the input
        :returns: the derived raw second order DRKey.
        :rtype bytes
        """
        l = [struct.pack("!B", DRKeyInputType.from_hosts(first, second)),
             struct.pack("!B", len(cls.PREFIX)), cls.PREFIX]
        if first:
            l.append(first.pack())
        if second:
            l.append(second.pack())
        l.append(bytes(BLOCK_SIZE - (sum((len(e) for e in l)) % BLOCK_SIZE)))
        return mac(drkey.drkey, b"".join(l))

    @staticmethod
    def generate_misc_reply(drkeys, request, meta):
        """
        Generate misc on the certificate server. (optional)
        This misc is added to the DRKeyProtocolReply and sent to the end host.
        If further processing is necessary on the end host, it can be done in
        parse_misc_reply.

        :param [FirstOrderDRKey] drkeys: list of the required first order DRKeys.
        :param DRKeyProtocolRequest request: the protocol DRKey request.
        :param UDPMetadata meta: the metadata.
        :returns: the created misc or None.
        :rtype: DRKeyMiscBase
        """

        return None

    @staticmethod
    def parse_misc_reply(request, reply):
        """
        Parse can do further manipulations on DRKeyProtocolReply.misc,
        based on both the DRKeyProtocolRequest and DRKeyProtocolReply.
        (optional)

        :param DRKeyProtocolRequest request: the protocol DRKey request.
        :param DRKeyProtocolReply reply: the protocol DRKey reply.
        """
        pass


class DRKeySecretValue(object):
    """ DRKey secret value. """

    def __init__(self, secret, exp_time):
        self.secret = secret
        self.exp_time = exp_time

    def tuple(self):
        return self.exp_time,


class BaseDRKey(object):
    """ Base for first order and protocol DRKey. """

    def tuple(self):
        raise NotImplementedError

    def __hash__(self):
        return hash(self.tuple())

    def __eq__(self, other):
        return self.tuple() == other.tuple()

    def __ne__(self, other):
        return not (self == other)


class FirstOrderDRKey(BaseDRKey):
    """ First order DRKey. """

    def __init__(self, src_ia, dst_ia, exp_time=None, drkey=None):
        """
        Create first order DRKey (src_ia -> dst_ia).

        :param ISD_AS src_ia: source ISD-AS of the DRKey.
        :param ISD_AS dst_ia: destination ISD-AS of the DRKey.
        :param int exp_time: expiration time of the DRKey (format: drkey_time())
        :param bytes drkey: the raw DRKey.
        """
        self.src_ia = src_ia
        self.dst_ia = dst_ia
        self.drkey = drkey
        self.exp_time = exp_time

    def tuple(self):
        return self.src_ia, self.dst_ia, self.exp_time

    def __str__(self):
        drkey = self.drkey.hex() if self.drkey else "None"
        return "FirstOrderDRKey (%s->%s): %s expires %s" % (
            self.src_ia, self.dst_ia, drkey, self.exp_time
        )


class SecondOrderDRKey(BaseDRKey):

    def __init__(self, drkey, exp_time, key_type, protocol, src_ia, dst_ia,
                 add_ia=None, src_host=None, dst_host=None, add_host=None):
        """
        Create second order DRKey.

        :param bytes drkey: raw protocol DRKey.
        :param int exp_time: expiration time of the protocol DRKey.
        :param DRKeyProtoKeyType key_type: type of the protocol DRKey.
        :param DRKeyProtocols protocol: the protocol.
        :param ISD_AS src_ia: source ISD-AS of the DRKey.
        :param ISD_AS dst_ia: destination ISD-AS of the DRKey.
        :param ISD_AS add_ia: additional ISD-AS of the DRKey.
        :param HostAddrBase src_host: source host of the DRKey.
        :param HostAddrBase dst_host: destination host of the DRKey.
        :param HostAddrBase add_host: additional host of the DRKey.
        """
        self.exp_time = exp_time
        self.key_type = key_type
        self.protocol = protocol
        self.src_host = src_host
        self.dst_host = dst_host
        self.add_host = add_host
        self.src_ia = src_ia
        self.dst_ia = dst_ia
        self.add_ia = add_ia
        self.drkey = drkey

    @classmethod
    def from_protocol_exchange(cls, request, reply):
        """
        Generate second order DRKey from DRKeyProtocolRequest and DRKeyProtocolReply exchange.

        :param DRKeyProtocolRequest request: the protocol DRKey request.
        :param DRKeyProtocolReply reply: the protocol DRKey reply.
        :returns: the resulting SecondOrderDRKey.
        :rtype: SecondOrderDRKey
        """
        return cls(
            reply.p.drkey, reply.p.expTime, request.p.reqType,
            request.p.protocol, request.src_ia, request.dst_ia, request.add_ia,
            request.src_host, request.dst_host, request.add_host
        )

    def tuple(self):
        return (self.key_type, self.protocol, self.src_host, self.dst_host,
                self.add_host, self.src_ia, self.dst_ia, self.add_ia)

    def __str__(self):
        src = "%s" % self.src_ia
        src = "%s:%s" % (src, self.src_host) if self.src_host else src
        dst = "%s" % self.dst_ia
        dst = "%s:%s" % (dst, self.dst_host) if self.dst_host else dst
        add = ";%s" % self.add_ia if self.add_ia else ""
        add = "%s:%s" % (add, self.add_host) if self.add_host else add
        drkey = self.drkey.hex() if self.drkey else "None"

        return "SecondOrderDRKey (%s->%s%s): %s proto %s type %s expires %s" % (
            src, dst, add, drkey, self.protocol, self.key_type, self.exp_time
        )
