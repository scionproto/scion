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
:mod:`drkey_mgmt` --- SCION DRKey management packets
=====================================================
"""
# External
import capnp  # noqa

# SCION
import proto.drkey_mgmt_capnp as P

from lib.drkey.opt.misc import OPTMiscReply, OPTMiscRequest
from lib.drkey.types import DRKeyMiscType
from lib.errors import SCIONParseError
from lib.packet.host_addr import haddr_parse
from lib.packet.packet_base import SCIONPayloadBaseProto
from lib.packet.scion_addr import ISD_AS
from lib.types import DRKeyMgmtType, PayloadClass


class DRKeyMgmtBase(SCIONPayloadBaseProto):
    """ Base class for DRKey management. """
    PAYLOAD_CLASS = PayloadClass.DRKEY

    def _pack_full(self, p):
        wrapper = P.DRKeyMgmt.new_message(**{self.PAYLOAD_TYPE: p})
        return super()._pack_full(wrapper)


class DRKeyRequest(DRKeyMgmtBase):
    """ First order DRKey request. """
    NAME = "DRKeyRequest"
    PAYLOAD_TYPE = DRKeyMgmtType.FIRST_ORDER_REQUEST
    P_CLS = P.DRKeyReq

    def __init__(self, p):
        super().__init__(p)
        self.isd_as = ISD_AS(p.isdas)

    @classmethod
    def from_values(cls, prefetch, isd_as, timestamp, signature, cert_ver, trc_ver):
        """
        Get DRKey request from values.

        :param Bool prefetch: indicates if request is for current (False) or next (True) DRKey.
        :param ISD_AS isd_as: source ISD-AS of the requested DRKey.
        :param int timestamp: signature creation time (format: drkey_time()).
        :param bytes signature: signature of (isd_as, prefetch, timestamp).
        :param int cert_ver: version of the certificate used to create signature.
        :param int trc_ver: version of the trc associated with the certificate.
        :returns: the resulting DRKeyRequest object.
        :rtype: DRKeyRequest
        """
        p = cls.P_CLS.new_message(isdas=isd_as.int(), timestamp=timestamp, signature=signature,
                                  certVer=cert_ver, trcVer=trc_ver)
        p.flags.prefetch = prefetch
        return cls(p)

    def short_desc(self):
        return ("ISD-AS: %s prefetch: %s TS: %s" %
                (self.isd_as, self.p.flags.prefetch, self.p.timestamp))


class DRKeyReply(DRKeyMgmtBase):
    NAME = "DRKeyReply"
    PAYLOAD_TYPE = DRKeyMgmtType.FIRST_ORDER_REPLY
    P_CLS = P.DRKeyRep

    def __init__(self, p):
        super().__init__(p)
        self.isd_as = ISD_AS(p.isdas)

    @classmethod
    def from_values(cls, isd_as, time, exp_time, cipher, signature,
                    cert_ver_src, cert_ver_dst, trc_ver):
        """
        Get the DRKeyReply from values.

        :param ISD_AS isd_as: source ISD-AS of the DRKey.
        :param int time: signature creation time (format drkey_time()).
        :param int exp_time: expiration time of the first order DRKey.
        :param bytes cipher: the encrypted first order DRKey.
        :param bytes signature: the signature of (isd_as, cipher, time, exp_time).
        :param int cert_ver_src: version of certificate for signing key/public key.
        :param int cert_ver_dst: version of certificate for private key.
        :param int trc_ver: version of trc associated with source cert.
        :returns: the resulting DRKeyReply.
        :rtype: DRKeyReply
        """
        return cls(cls.P_CLS.new_message(
            isdas=isd_as.int(), timestamp=time, expTime=exp_time,
            cipher=cipher, signature=signature, certVerSrc=cert_ver_src,
            certVerDst=cert_ver_dst, trcVer=trc_ver))

    def short_desc(self):
        return ("ISD-AS: %s expTime: %s certs: (src=%s, dst=%s, trc=%s) TS: %s"
                % (self.isd_as, self.p.expTime, self.p.certVerSrc,
                   self.p.certVerDst, self.p.trcVer, self.p.timestamp))


class DRKeyProtocolRequest(DRKeyMgmtBase):
    """ DRKey protocol request for second order DRKey. """
    NAME = "DRKeyProtocolRequest"
    PAYLOAD_TYPE = DRKeyMgmtType.PROTOCOL_REQUEST
    P_CLS = P.DRKeyProtocolReq

    class Params(object):
        timestamp = None        # int (format: drkey_time())
        request_type = None     # DRKeyProtoKeyType (4 > x >= 0)
        request_id = None       # int
        protocol = None         # DRKeyProtocols
        src_ia = None           # ISD_AS
        dst_ia = None           # ISD_AS
        add_ia = None           # ISD_AS
        src_host = None         # HostAddrBase
        dst_host = None         # HostAddrBase
        add_host = None         # HostAddrBase
        misc = None             # DRKeyMiscType

    @classmethod
    def _parse_host(cls, union):
        if union.which() == "holder":
            return haddr_parse(union.holder.type, union.holder.host)
        return None

    @classmethod
    def _parse_misc(cls, union):
        type_ = union.which()
        misc_map = {
            DRKeyMiscType.UNSET: lambda x: None,
            DRKeyMiscType.OPT: OPTMiscRequest,
        }
        handler = misc_map.get(type_)
        if not handler:
            raise SCIONParseError("Unsupported misc type: %s" % type_)
        return handler(getattr(union, type_))

    @classmethod
    def _set_misc(cls, union, misc):
        misc_map = {
            OPTMiscRequest: DRKeyMiscType.OPT,
        }
        type_ = misc_map.get(type(misc))
        if not type_:
            raise SCIONParseError("Unsupported misc type: %s" % type(misc))
        setattr(union, type_, misc.p)

    def __init__(self, p):
        super().__init__(p)

        self.src_ia = ISD_AS(p.srcIA)
        self.dst_ia = ISD_AS(p.dstIA)
        if p.addIA.which() == "ia":
            self.add_ia = ISD_AS(p.addIA.ia)
        else:
            self.add_ia = None
        self.src_host = self._parse_host(p.srcHost)
        self.dst_host = self._parse_host(p.dstHost)
        self.add_host = self._parse_host(p.addHost)
        self.misc = self._parse_misc(p.misc)

    @classmethod
    def from_values(cls, params):  # pragma: no cover
        """
        Get the DRKeyProtocolRequest from values.

        :param Params params: object holding the necessary parameters.
        :returns: the resulting DRKeyProtocolRequest.
        :rtype: DRKeyProtocolRequest
        """
        proto = cls.P_CLS.new_message(
            reqType=params.request_type, srcIA=params.src_ia.int(), dstIA=params.dst_ia.int(),
            protocol=params.protocol, reqID=params.request_id, timestamp=params.timestamp)
        if params.add_ia:
            proto.addIA.ia = params.add_ia.int()
        if params.src_host:
            proto.srcHost.holder = P.DRKeyHostHolder.new_message(
                type=params.src_host.TYPE, host=params.src_host.pack())
        if params.dst_host:
            proto.dstHost.holder = P.DRKeyHostHolder.new_message(
                type=params.dst_host.TYPE, host=params.dst_host.pack())
        if params.add_host:
            proto.addHost.holder = P.DRKeyHostHolder.new_message(
                type=params.add_host.TYPE, host=params.add_host.pack())
        if params.misc:
            cls._set_misc(proto.misc, params.misc)
        return cls(proto)

    def tuple(self):
        return (self.p.reqType, self.p.protocol, self.src_host, self.dst_host,
                self.add_host, self.src_ia, self.dst_ia, self.add_ia)

    def short_desc(self):
        return "ID: %s ReqType: %s Src (%s,%s) Dst: (%s,%s) Add: (%s,%s)" % (
            self.p.reqID, self.p.reqType, self.src_ia, self.src_host,
            self.dst_ia, self.dst_host, self.add_ia, self.dst_host)


class DRKeyProtocolReply(DRKeyMgmtBase):
    """ DRKey protocol reply for second order DRKey. """
    NAME = "DRKeyProtocolReply"
    PAYLOAD_TYPE = DRKeyMgmtType.PROTOCOL_REPLY
    P_CLS = P.DRKeyProtocolRep

    @classmethod
    def _parse_misc(cls, union):
        type_ = union.which()
        misc_map = {
            DRKeyMiscType.UNSET: lambda x: None,
            DRKeyMiscType.OPT: OPTMiscReply,
        }
        handler = misc_map.get(type_)
        if not handler:
            raise SCIONParseError("Unsupported misc type: %s" % type_)
        return handler(getattr(union, type_))

    @classmethod
    def _set_misc(cls, union, misc):
        misc_map = {
            OPTMiscReply: DRKeyMiscType.OPT,
        }
        type_ = misc_map.get(type(misc))
        if not type_:
            raise SCIONParseError("Unsupported misc type: %s" % type(misc))
        setattr(union, type_, misc.p)

    def __init__(self, p):
        super().__init__(p)
        self.misc = self._parse_misc(p.misc)

    @classmethod
    def from_values(cls, req_id, drkey, exp_time, timestamp, misc=None):   # pragma: no cover
        """
        Get DRKeyProtocolReply from values.

        :param int req_id: id of the corresponding request.
        :param bytes drkey: the protocol DRKey.
        :param int exp_time: expiration time of the protocol DRKey
        :param int timestamp: timestamp of the creation time.
        :param misc:
        :returns: the resulting DRKeyProtocolReply
        :rtype: DRKeyProtocolReply
        """
        proto = cls.P_CLS.new_message(
            reqID=req_id, drkey=drkey, expTime=exp_time, timestamp=timestamp)
        if misc:
            cls._set_misc(proto.misc, misc)
        return cls(proto)

    def short_desc(self):
        return "ID: %s expTime: %s" % (self.p.reqID, self.p.expTime)


def parse_drkeymgmt_payload(wrapper):  # pragma: no cover
    type_ = wrapper.which()
    for c in (DRKeyRequest, DRKeyReply, DRKeyProtocolRequest, DRKeyProtocolReply):
        if c.PAYLOAD_TYPE == type_:
            return c(getattr(wrapper, type_))
    raise SCIONParseError("Unsupported DRKey management type: %s" % type_)
