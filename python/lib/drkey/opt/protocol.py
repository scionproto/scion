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
import binascii

# SCION
from lib.crypto.symcrypto import mac, sha256
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
from lib.packet.opt.defines import OPTMode
from lib.packet.opt.opt_ext import SCIONOriginValidationPathTraceExtn
from lib.packet.opt.ov_ext import SCIONOriginValidationExtn
from lib.packet.opt.pt_ext import SCIONPathTraceExtn


# Validity period for timestamp check, in ms
expiration_delay = 2 * 1000


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
        log_entry = ['\n\nSession: '+str(binascii.hexlify(req.misc.p.sessionID))]
        temp_list = [cls._derive_drkey(drkey, req.src_host, req.dst_host) for drkey in drkeys[1:]]
        log_entry.append("\nFirstOrders:")
        for k in drkeys[1:]:
            log_entry.append('\n' + str(binascii.hexlify(k.drkey)))
        log_entry.append("\nSecondOrders:")
        for raw in temp_list:
            log_entry.append('\n' + str(binascii.hexlify(raw)))
        proto_drkeys = [mac(cls._derive_drkey(drkey, req.src_host, req.dst_host),
                            req.misc.p.sessionID) for drkey in drkeys[1:]]
        log_entry.append("\nProtoKeys:")
        for val in proto_drkeys:
            log_entry.append('\n' + str(binascii.hexlify(val)))
        # logging.debug(''.join(log_entry))
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


def find_opt_extn(spkt):
    for e in spkt.ext_hdrs:
        if isinstance(e, SCIONOriginValidationPathTraceExtn):
            return e
    return None


def find_pathtrace_extn(spkt):
    for e in spkt.ext_hdrs:
        if isinstance(e, SCIONPathTraceExtn):
            return e
    return None


def find_originvalidation_extn(spkt):
    for e in spkt.ext_hdrs:
        if isinstance(e, SCIONOriginValidationExtn):
            return e
    return None


def generate_sessionID(spkt):
    hashed_dst = sha256(str(spkt.addrs.dst.isd_as).encode('utf-8') +
                        spkt.addrs.dst.host.addr.packed)[:16]
    assert (len(hashed_dst) == 16)
    return bytes(16)


def set_pvf(spkt, drkey):
    assert isinstance(drkey, SecondOrderDRKey)
    extn_hdr = find_opt_extn(spkt)
    if not extn_hdr:
        extn_hdr = find_pathtrace_extn(spkt)
    extn_hdr.PVF = mac(drkey.drkey, extn_hdr.datahash)
    # logging.debug("\nS:\nUsed key {}, on hash {}, got PVF {}".format(
    #     drkey, pathtrace_hdr.datahash, pathtrace_hdr.PVF)
    # )
    return


def verify_pvf(spkt, drkey, keylist):
    assert isinstance(drkey, SecondOrderDRKey)
    extn_hdr = find_opt_extn(spkt)
    if not extn_hdr:
        extn_hdr = find_pathtrace_extn(spkt)
    packet_hash = extn_hdr.datahash  # compute over payload
    computed_pvf = mac(drkey.drkey, packet_hash)
    log_entry = []
    log_entry.append("\n\nInitial  computed_pvf:\n from {} to {} with key {}".format(
        binascii.hexlify(packet_hash),
        binascii.hexlify(computed_pvf),
        binascii.hexlify(drkey.drkey))
    )
    try:
        keylist = [key.drkey for key in keylist]  # get raw keys from SecondOrderDRKeys
    except AttributeError:
        pass  # Unless they are already raw keys
    for key in keylist:
        old_pvf = binascii.hexlify(computed_pvf)
        extended_pvf = packet_hash + computed_pvf
        computed_pvf = mac(key, extended_pvf)
        log_entry.append("\nIntermediate computed_pvf: from {} to {} with key {} over {}".format(
            old_pvf, binascii.hexlify(computed_pvf),
            binascii.hexlify(key),
            binascii.hexlify(extended_pvf))
        )
    # logging.debug("".join(log_entry))
    header_timestamp = int.from_bytes(extn_hdr.timestamp, byteorder='big')
    drk_time = drkey_time()
    timestamp_valid = (drk_time - header_timestamp) < expiration_delay
    if not timestamp_valid:
        raise SCIONVerificationError(
            "OPT Timestamp expired\n Got: {}\n Expected value larger than: {}".format(
             header_timestamp,
             drk_time - expiration_delay)
        )
    if not extn_hdr.PVF == computed_pvf:
        raise SCIONVerificationError(
            "Invalid PVF\n Got ({}): {}\n Expected ({}): {}".format(
             len(extn_hdr.PVF), binascii.hexlify(extn_hdr.PVF),
             len(computed_pvf), binascii.hexlify(computed_pvf))
        )
    else:
        logging.debug("PVF validated")
    return


def generate_pvf(drkey, datahash):
    return mac(drkey.drkey, datahash)


def generate_intermediate_pvfs(spkt, ia_drkey, ias_keylist):
    extn_hdr = find_opt_extn(spkt)
    if not extn_hdr:
        extn_hdr = find_pathtrace_extn(spkt)
    packet_hash = extn_hdr.datahash  # compute over payload
    ia, drkey = ia_drkey
    computed_pvf = mac(drkey, packet_hash)
    intermediate_pvfs = [(ia, computed_pvf)]
    for ia_drkey in ias_keylist:
        ia, drkey = ia_drkey
        extended_pvf = packet_hash + computed_pvf
        computed_pvf = mac(drkey, extended_pvf)
        intermediate_pvfs.append((ia, computed_pvf))
    return intermediate_pvfs


def verify_ov(spkt, drkey):
    assert isinstance(drkey, SecondOrderDRKey)
    origin_validation_hdr = find_originvalidation_extn(spkt)
    packet_hash = origin_validation_hdr.datahash
    computed_ov = mac(drkey.drkey, packet_hash)
    if not origin_validation_hdr.OVs[:-1] == computed_ov:
        raise SCIONVerificationError("Invalid OV")
    return


def get_sciond_params(spkt, mode=1, path=None):
    extn = None
    if mode == OPTMode.OPT:
        extn = find_opt_extn(spkt)
    if mode == OPTMode.PATH_TRACE_ONLY:
        extn = find_pathtrace_extn(spkt)
    if mode == OPTMode.ORIGIN_VALIDATION_ONLY:
        extn = find_originvalidation_extn(spkt)
    if not extn:
        return None

    params = DRKeyProtocolRequest.Params()
    params.timestamp = drkey_time()
    params.protocol = DRKeyProtocols.OPT
    params.request_id = 0

    # MAC created with key S->D
    params.request_type = DRKeyProtoKeyType.HOST_TO_HOST
    params.src_ia = spkt.addrs.src.isd_as
    params.dst_ia = spkt.addrs.dst.isd_as

    params.src_host = spkt.addrs.src.host
    params.dst_host = spkt.addrs.dst.host

    params.misc = OPTMiscRequest.from_values(extn.sessionID, path or [])

    return params


def get_sciond_params_src(spkt):
    params = DRKeyProtocolRequest.Params()
    params.timestamp = drkey_time()
    params.protocol = DRKeyProtocols.OPT
    params.request_id = 0

    params.request_type = DRKeyProtoKeyType.HOST_TO_HOST
    params.src_ia = spkt.addrs.src.isd_as
    params.dst_ia = spkt.addrs.dst.isd_as

    params.src_host = spkt.addrs.src.host
    params.dst_host = spkt.addrs.dst.host

    params.misc = OPTMiscRequest.from_values(bytes(16), [])

    return params
