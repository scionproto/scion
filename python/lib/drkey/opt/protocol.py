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
:mod:`protocol` --- SCION DRKey Protocol rules for OPT
=====================================================
"""
# External
import logging

# SCION
from lib.crypto.symcrypto import mac
from lib.drkey.drkey_mgmt import DRKeyProtocolRequest, DRKeyProtocolReply
from lib.drkey.opt.misc import OPTMiscReply, OPTMiscRequest
from lib.drkey.types import (
    DRKeyProtocolBase,
    DRKeyProtocols,
    DRKeyProtoKeyType,
    FirstOrderDRKey,
    SecondOrderDRKey,
)
from lib.drkey.util import drkey_time, get_drkey_exp_time
from lib.errors import SCIONVerificationError
from lib.msg_meta import UDPMetadata
from lib.packet.scion_addr import SCIONAddr


class OPTProtocol(DRKeyProtocolBase):

    PREFIX = b"OPT"

    @staticmethod
    def verify_request(req, meta):
        assert isinstance(req, DRKeyProtocolRequest)
        assert isinstance(meta, UDPMetadata)

        if not req.p.reqType == DRKeyProtoKeyType.HOST_TO_HOST:
            raise SCIONVerificationError("Invalid request code %s" % req.p.reqType)
        OPTProtocol._check_misc(req)
        # FIXME(roosd): remove 'or True'. Needed one sciond per AS
        if req.src_ia == meta.ia and (req.src_host == meta.host or True):
            if not req.dst_ia or not req.dst_host:
                raise SCIONVerificationError("Destination host not set")
        # FIXME(roosd): remove 'or True'. Needed one sciond per AS
        elif req.dst_ia == meta.ia and (req.dst_host == meta.host or True):
            if not req.src_ia or not req.src_host:
                raise SCIONVerificationError("Source host not set")
        else:
            raise SCIONVerificationError("Requester %s:%s has no access" % (meta.ia, meta.host))

    @staticmethod
    def required_drkeys(req, meta):
        exp_time = get_drkey_exp_time()
        l = [FirstOrderDRKey(req.src_ia, req.dst_ia, exp_time)]
        for isd_as in req.misc.path:
            l.append(FirstOrderDRKey(isd_as, req.src_ia, exp_time))
        return l

    @classmethod
    def generate_drkey(cls, drkeys, req, meta):
        assert isinstance(req, DRKeyProtocolRequest)
        assert isinstance(meta, UDPMetadata)
        drkey = super()._derive_drkey(drkeys[0], req.src_host, req.dst_host)
        return mac(drkey, req.misc.p.sessionID)

    @staticmethod
    def _check_misc(req):
        if not isinstance(req.misc, OPTMiscRequest):
            raise SCIONVerificationError(
                "Invalid misc '%s'. Should be 'opt'" % req.p.misc.which())
        if len(req.misc.p.sessionID) != 16:
            raise SCIONVerificationError(
                "Invalid SessionID length %sB. Expected 16B" % len(req.misc.p.sessionID))
        if req.misc.path:
            logging.debug("%s %s %s", len(req.misc.path), req.misc.path[0], req.misc.path[-1])
            if req.misc.path[0] != req.src_ia:
                raise SCIONVerificationError(
                    "Invalid source %s. Expected" % req.misc.path[0], req.src_ia)
            if req.misc.path[-1] != req.dst_ia:
                raise SCIONVerificationError(
                    "Invalid destination %s. Expected" % req.misc.path[-1], req.src_ia)

    @classmethod
    def generate_misc_reply(cls, drkeys, req, meta):
        assert isinstance(req, DRKeyProtocolRequest)
        assert isinstance(meta, UDPMetadata)
        proto_drkeys = [mac(cls._derive_drkey(drkey, req.src_host, req.dst_host),
                            req.misc.p.sessionID) for drkey in drkeys[1:]]
        return OPTMiscReply.from_values(proto_drkeys)

    @staticmethod
    def parse_misc_reply(req, rep):
        assert isinstance(rep, DRKeyProtocolReply)
        assert isinstance(req, DRKeyProtocolRequest)

        if not rep.misc.raw_drkeys:
            return None
        rep.misc.drkeys = []
        for i, drkey in enumerate(rep.misc.raw_drkeys):
            rep.misc.drkeys.append(SecondOrderDRKey(
                drkey, rep.p.expTime, req.p.reqType, req.p.protocol, req.misc.path[i],
                req.src_ia, add_ia=req.dst_ia, dst_host=req.src_host,
                add_host=req.dst_host
            ))


def get_sciond_params(src, dst, path=None):
    assert isinstance(src, SCIONAddr)
    assert isinstance(dst, SCIONAddr)
    params = DRKeyProtocolRequest.Params()
    params.timestamp = drkey_time()
    params.protocol = DRKeyProtocols.OPT
    params.request_id = 0
    params.request_type = DRKeyProtoKeyType.HOST_TO_HOST
    params.src_ia = src.isd_as
    params.src_host = src.host
    params.dst_ia = dst.isd_as
    params.dst_host = dst.host
    params.misc = OPTMiscRequest.from_values(bytes(16), path or [])
    return params
