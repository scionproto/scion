#!/usr/bin/python3
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
:mod:`base` --- SCION certificate server
========================================
"""
# Stdlib
import datetime
import logging
import threading

# External packages
from nacl.exceptions import CryptoError
from prometheus_client import Counter, Gauge

# SCION
from external.expiring_dict import ExpiringDict
from lib.crypto.asymcrypto import get_enc_key, get_sig_key
from lib.crypto.certificate_chain import CertificateChain, verify_sig_chain_trc
from lib.crypto.trc import TRC
from lib.crypto.symcrypto import crypto_hash
from lib.crypto.symcrypto import kdf
from lib.defines import CERTIFICATE_SERVICE, GEN_CACHE_PATH
from lib.drkey.drkey_mgmt import (
    DRKeyMgmt,
    DRKeyReply,
    DRKeyRequest,
)
from lib.drkey.suite import (
    decrypt_drkey,
    drkey_signing_input_req,
    get_drkey_reply,
    get_drkey_request,
    get_signing_input_rep,
)
from lib.drkey.types import DRKeySecretValue, FirstOrderDRKey
from lib.drkey.util import drkey_time, get_drkey_exp_time
from lib.errors import SCIONVerificationError
from lib.main import main_default, main_wrapper
from lib.packet.cert_mgmt import (
    CertMgmt,
    CertChainReply,
    CertChainRequest,
    TRCReply,
    TRCRequest,
)
from lib.packet.ctrl_pld import CtrlPayload, mk_ctrl_req_id
from lib.packet.svc import SVCType
from lib.requests import RequestHandler
from lib.thread import thread_safety_net
from lib.types import (
    CertMgmtType,
    DRKeyMgmtType,
    PayloadClass,
)
from lib.util import (
    SCIONTime,
    sleep_interval,
)
from lib.zk.cache import ZkSharedCache
from lib.zk.errors import ZkNoConnection
from lib.zk.id import ZkID
from lib.zk.zk import ZK_LOCK_SUCCESS, Zookeeper
from scion_elem.scion_elem import SCIONElement


# Exported metrics.
REQS_TOTAL = Counter("cs_requests_total", "# of total requests", ["server_id", "isd_as", "type"])
IS_MASTER = Gauge("cs_is_master", "true if this process is the replication master",
                  ["server_id", "isd_as"])

# Max amount of DRKey secret values. 1 current, 1 prefetch, 1 buffer.
DRKEY_MAX_SV = 3
# Max TTL of first order DRKey. 1 Day prefetch, 1 Day current.
DRKEY_MAX_TTL = datetime.timedelta(days=2).total_seconds()
# Max number of stored first order DRKeys
DRKEY_MAX_KEYS = 10**6
# Timeout for first order DRKey requests
DRKEY_REQUEST_TIMEOUT = 5


class CertServer(SCIONElement):
    """
    The SCION Certificate Server.
    """
    SERVICE_TYPE = CERTIFICATE_SERVICE
    # ZK path for incoming cert chains
    ZK_CC_CACHE_PATH = "cert_chain_cache"
    # ZK path for incoming TRCs
    ZK_TRC_CACHE_PATH = "trc_cache"
    ZK_DRKEY_PATH = "drkey_cache"

    def __init__(self, server_id, conf_dir, spki_cache_dir=GEN_CACHE_PATH, prom_export=None):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param str prom_export: prometheus export address.
        """
        super().__init__(server_id, conf_dir, spki_cache_dir=spki_cache_dir,
                         prom_export=prom_export)
        self.config = self._load_as_conf()
        cc_labels = {**self._labels, "type": "cc"} if self._labels else None
        trc_labels = {**self._labels, "type": "trc"} if self._labels else None
        drkey_labels = {**self._labels, "type": "drkey"} if self._labels else None
        self.cc_requests = RequestHandler.start(
            "CC Requests", self._check_cc, self._fetch_cc, self._reply_cc,
            labels=cc_labels,
        )
        self.trc_requests = RequestHandler.start(
            "TRC Requests", self._check_trc, self._fetch_trc, self._reply_trc,
            labels=trc_labels,
        )
        self.drkey_protocol_requests = RequestHandler.start(
            "DRKey Requests", self._check_drkey, self._fetch_drkey, self._reply_proto_drkey,
            labels=drkey_labels,
        )

        self.CTRL_PLD_CLASS_MAP = {
            PayloadClass.CERT: {
                CertMgmtType.CERT_CHAIN_REQ: self.process_cert_chain_request,
                CertMgmtType.CERT_CHAIN_REPLY: self.process_cert_chain_reply,
                CertMgmtType.TRC_REQ: self.process_trc_request,
                CertMgmtType.TRC_REPLY: self.process_trc_reply,
            },
            PayloadClass.DRKEY: {
                DRKeyMgmtType.FIRST_ORDER_REQUEST:
                    self.process_drkey_request,
                DRKeyMgmtType.FIRST_ORDER_REPLY:
                    self.process_drkey_reply,
            },
        }

        zkid = ZkID.from_values(self.addr.isd_as, self.id,
                                [(self.addr.host, self._port)]).pack()
        self.zk = Zookeeper(self.topology.isd_as, CERTIFICATE_SERVICE,
                            zkid, self.topology.zookeepers)
        self.zk.retry("Joining party", self.zk.party_setup)
        self.trc_cache = ZkSharedCache(self.zk, self.ZK_TRC_CACHE_PATH,
                                       self._cached_trcs_handler)
        self.cc_cache = ZkSharedCache(self.zk, self.ZK_CC_CACHE_PATH,
                                      self._cached_certs_handler)
        self.drkey_cache = ZkSharedCache(self.zk, self.ZK_DRKEY_PATH,
                                         self._cached_drkeys_handler)
        self.signing_key = get_sig_key(self.conf_dir)
        self.private_key = get_enc_key(self.conf_dir)
        self.drkey_secrets = ExpiringDict(DRKEY_MAX_SV, DRKEY_MAX_TTL)
        self.first_order_drkeys = ExpiringDict(DRKEY_MAX_KEYS, DRKEY_MAX_TTL)

    def worker(self):
        """
        Worker thread that takes care of reading shared entries from ZK, and
        handling master election.
        """
        worker_cycle = 1.0
        start = SCIONTime.get_time()
        while self.run_flag.is_set():
            sleep_interval(start, worker_cycle, "CS.worker cycle",
                           self._quiet_startup())
            start = SCIONTime.get_time()
            # Update IS_MASTER metric.
            if self._labels:
                IS_MASTER.labels(**self._labels).set(int(self.zk.have_lock()))
            try:
                self.zk.wait_connected()
                self.trc_cache.process()
                self.cc_cache.process()
                self.drkey_cache.process()
                # Try to become a master.
                ret = self.zk.get_lock(lock_timeout=0, conn_timeout=0)
                if ret:  # Either got the lock, or already had it.
                    if ret == ZK_LOCK_SUCCESS:
                        logging.info("Became master")
                    self.trc_cache.expire(worker_cycle * 10)
                    self.cc_cache.expire(worker_cycle * 10)
                    self.drkey_cache.expire(worker_cycle * 10)
            except ZkNoConnection:
                logging.warning('worker(): ZkNoConnection')
                pass

    def _cached_trcs_handler(self, raw_entries):
        """
        Handles cached (through ZK) TRCs, passed as a list.
        """
        for raw in raw_entries:
            trc = TRC.from_raw(raw.decode('utf-8'))
            rep = CtrlPayload(CertMgmt(TRCReply.from_values(trc)))
            self.process_trc_reply(rep, None, from_zk=True)
        if len(raw_entries) > 0:
            logging.debug("Processed %s trcs from ZK", len(raw_entries))

    def _cached_certs_handler(self, raw_entries):
        """
        Handles cached (through ZK) chains, passed as a list.
        """
        for raw in raw_entries:
            cert = CertificateChain.from_raw(raw.decode('utf-8'))
            rep = CtrlPayload(CertMgmt(CertChainReply.from_values(cert)))
            self.process_cert_chain_reply(rep, None, from_zk=True)
        if len(raw_entries) > 0:
            logging.debug("Processed %s certs from ZK", len(raw_entries))

    def _cached_drkeys_handler(self, raw_entries):
        for raw in raw_entries:
            msg = CtrlPayload(DRKeyMgmt(DRKeyReply.from_raw(raw)))
            self.process_drkey_reply(msg, None, from_zk=True)

    def _share_object(self, pld, is_trc):
        """
        Share path segments (via ZK) with other path servers.
        """
        pld_packed = pld.pack()
        pld_hash = crypto_hash(pld_packed).hex()
        try:
            if is_trc:
                self.trc_cache.store("%s-%s" % (pld_hash, SCIONTime.get_time()),
                                     pld_packed)
            else:
                self.cc_cache.store("%s-%s" % (pld_hash, SCIONTime.get_time()),
                                    pld_packed)
        except ZkNoConnection:
            logging.warning("Unable to store %s in shared path: "
                            "no connection to ZK" % "TRC" if is_trc else "CC")
            return
        logging.debug("%s stored in ZK: %s" % ("TRC" if is_trc else "CC",
                                               pld_hash))

    def process_cert_chain_request(self, cpld, meta):
        """Process a certificate chain request."""
        cmgt = cpld.union
        req = cmgt.union
        assert isinstance(req, CertChainRequest), type(req)
        key = req.isd_as(), req.p.version
        logging.info("Cert chain request received for %sv%s from %s", *key, meta)
        REQS_TOTAL.labels(**self._labels, type="cc").inc()
        local = meta.ia == self.addr.isd_as
        if not self._check_cc(key):
            if not local:
                logging.warning(
                    "Dropping CC request from %s for %sv%s: "
                    "CC not found && requester is not local)",
                    meta, *key)
            else:
                self.cc_requests.put((key, (meta, req, cpld.req_id)))
            return
        self._reply_cc(key, (meta, req, cpld.req_id))

    def process_cert_chain_reply(self, cpld, meta, from_zk=False):
        """Process a certificate chain reply."""
        cmgt = cpld.union
        rep = cmgt.union
        assert isinstance(rep, CertChainReply), type(rep)
        ia_ver = rep.chain.get_leaf_isd_as_ver()
        logging.info("Cert chain reply received for %sv%s (ZK: %s)" %
                     (ia_ver[0], ia_ver[1], from_zk))
        self.trust_store.add_cert(rep.chain)
        if not from_zk:
            self._share_object(rep.chain, is_trc=False)
        # Reply to all requests for this certificate chain
        self.cc_requests.put((ia_ver, None))

    def _check_cc(self, key):
        isd_as, ver = key
        ver = None if ver == CertChainRequest.NEWEST_VERSION else ver
        cert_chain = self.trust_store.get_cert(isd_as, ver)
        if cert_chain:
            return True
        logging.debug('Cert chain not found for %sv%s', *key)
        return False

    def _fetch_cc(self, key, req_info):
        # Do not attempt to fetch the CertChain from a remote AS if the cacheOnly flag is set.
        _, orig_req, _ = req_info
        if orig_req.p.cacheOnly:
            return
        self._send_cc_request(*key)

    def _send_cc_request(self, isd_as, ver):
        req = CertChainRequest.from_values(isd_as, ver, cache_only=True)
        path_meta = self._get_path_via_sciond(isd_as)
        if path_meta:
            meta = self._build_meta(isd_as, host=SVCType.CS_A, path=path_meta.fwd_path())
            req_id = mk_ctrl_req_id()
            self.send_meta(CtrlPayload(CertMgmt(req), req_id=req_id), meta)
            logging.info("Cert chain request sent to %s via [%s]: %s [id: %016x]",
                         meta, path_meta.short_desc(), req.short_desc(), req_id)
        else:
            logging.warning("Cert chain request (for %s) not sent: "
                            "no path found", req.short_desc())

    def _reply_cc(self, key, req_info):
        isd_as, ver = key
        ver = None if ver == CertChainRequest.NEWEST_VERSION else ver
        meta = req_info[0]
        req_id = req_info[2]
        cert_chain = self.trust_store.get_cert(isd_as, ver)
        self.send_meta(
            CtrlPayload(CertMgmt(CertChainReply.from_values(cert_chain)), req_id=req_id), meta)
        logging.info("Cert chain for %sv%s sent to %s [id: %016x]", isd_as, ver, meta, req_id)

    def process_trc_request(self, cpld, meta):
        """Process a TRC request."""
        cmgt = cpld.union
        req = cmgt.union
        assert isinstance(req, TRCRequest), type(req)
        key = req.isd_as()[0], req.p.version
        logging.info("TRC request received for %sv%s from %s [id: %s]",
                     *key, meta, cpld.req_id_str())
        REQS_TOTAL.labels(**self._labels, type="trc").inc()
        local = meta.ia == self.addr.isd_as
        if not self._check_trc(key):
            if not local:
                logging.warning(
                    "Dropping TRC request from %s for %sv%s: "
                    "TRC not found && requester is not local)",
                    meta, *key)
            else:
                self.trc_requests.put((key, (meta, req, cpld.req_id)))
            return
        self._reply_trc(key, (meta, req, cpld.req_id))

    def process_trc_reply(self, cpld, meta, from_zk=False):
        """
        Process a TRC reply.

        :param trc_rep: TRC reply.
        :type trc_rep: TRCReply
        """
        cmgt = cpld.union
        trc_rep = cmgt.union
        assert isinstance(trc_rep, TRCReply), type(trc_rep)
        isd, ver = trc_rep.trc.get_isd_ver()
        logging.info("TRCReply received for ISD %sv%s, ZK: %s [id: %s]",
                     isd, ver, from_zk, cpld.req_id_str())
        self.trust_store.add_trc(trc_rep.trc)
        if not from_zk:
            self._share_object(trc_rep.trc, is_trc=True)
        # Reply to all requests for this TRC
        self.trc_requests.put(((isd, ver), None))

    def _check_trc(self, key):
        isd, ver = key
        ver = None if ver == TRCRequest.NEWEST_VERSION else ver
        trc = self.trust_store.get_trc(isd, ver)
        if trc:
            return True
        logging.debug('TRC not found for %sv%s', *key)
        return False

    def _fetch_trc(self, key, req_info):
        # Do not attempt to fetch the TRC from a remote AS if the cacheOnly flag is set.
        _, orig_req, _ = req_info
        if orig_req.p.cacheOnly:
            return
        self._send_trc_request(*key)

    def _send_trc_request(self, isd, ver):
        trc_req = TRCRequest.from_values(isd, ver, cache_only=True)
        path_meta = self._get_path_via_sciond(trc_req.isd_as())
        if path_meta:
            meta = self._build_meta(
                path_meta.dst_ia(), host=SVCType.CS_A, path=path_meta.fwd_path())
            req_id = mk_ctrl_req_id()
            self.send_meta(CtrlPayload(CertMgmt(trc_req), req_id=req_id), meta)
            logging.info("TRC request sent to %s via [%s]: %s [id: %016x]",
                         meta, path_meta.short_desc(), trc_req.short_desc(), req_id)
        else:
            logging.warning("TRC request not sent for %s: no path found.", trc_req.short_desc())

    def _reply_trc(self, key, req_info):
        isd, ver = key
        ver = None if ver == TRCRequest.NEWEST_VERSION else ver
        meta = req_info[0]
        req_id = req_info[2]
        trc = self.trust_store.get_trc(isd, ver)
        self.send_meta(CtrlPayload(CertMgmt(TRCReply.from_values(trc)), req_id=req_id), meta)
        logging.info("TRC for %sv%s sent to %s [id: %016x]", isd, ver, meta, req_id)

    def process_drkey_request(self, cpld, meta):
        """
        Process first order DRKey requests from other ASes.

        :param DRKeyRequest req: the DRKey request
        :param UDPMetadata meta: the metadata
        """
        dpld = cpld.union
        req = dpld.union
        assert isinstance(req, DRKeyRequest), type(req)
        logging.info("DRKeyRequest received from %s: %s [id: %s]",
                     meta, req.short_desc(), cpld.req_id_str())
        REQS_TOTAL.labels(**self._labels, type="drkey").inc()
        try:
            cert = self._verify_drkey_request(req, meta)
        except SCIONVerificationError as e:
            logging.warning("Invalid DRKeyRequest from %s. Reason %s: %s", meta, e,
                            req.short_desc())
            return
        sv = self._get_drkey_secret(get_drkey_exp_time(req.p.flags.prefetch))
        cert_version = self.trust_store.get_cert(self.addr.isd_as).certs[0].version
        trc_version = self.trust_store.get_trc(self.addr.isd_as[0]).version
        rep = get_drkey_reply(sv, self.addr.isd_as, meta.ia, self.private_key,
                              self.signing_key, cert_version, cert, trc_version)
        self.send_meta(CtrlPayload(DRKeyMgmt(rep), req_id=cpld.req_id), meta)
        logging.info("DRKeyReply sent to %s: %s [id: %s]",
                     meta, req.short_desc(), cpld.req_id_str())

    def _verify_drkey_request(self, req, meta):
        """
        Verify that the first order DRKey request is legit.
        I.e. the signature is valid, the correct ISD AS is queried, timestamp is recent.

        :param DRKeyRequest req: the first order DRKey request.
        :param UDPMetadata meta: the metadata.
        :returns Certificate of the requester.
        :rtype: Certificate
        :raises: SCIONVerificationError
        """
        if self.addr.isd_as != req.isd_as:
            raise SCIONVerificationError("Request for other ISD-AS: %s" % req.isd_as)
        if drkey_time() - req.p.timestamp > DRKEY_REQUEST_TIMEOUT:
            raise SCIONVerificationError("Expired request from %s. %ss old. Max %ss" % (
                meta.ia, drkey_time() - req.p.timestamp, DRKEY_REQUEST_TIMEOUT))
        trc = self.trust_store.get_trc(meta.ia[0])
        chain = self.trust_store.get_cert(meta.ia, req.p.certVer)
        err = []
        if not chain:
            self._send_cc_request(meta.ia, req.p.certVer)
            err.append("Certificate not present for %s(v: %s)" % (meta.ia, req.p.certVer))
        if not trc:
            self._send_trc_request(meta.ia[0], req.p.trcVer)
            err.append("TRC not present for %s(v: %s)" % (meta.ia[0], req.p.trcVer))
        if err:
            raise SCIONVerificationError(", ".join(err))
        raw = drkey_signing_input_req(req.isd_as, req.p.flags.prefetch, req.p.timestamp)
        try:
            verify_sig_chain_trc(raw, req.p.signature, meta.ia, chain, trc)
        except SCIONVerificationError as e:
            raise SCIONVerificationError(str(e))
        return chain.certs[0]

    def process_drkey_reply(self, cpld, meta, from_zk=False):
        """
        Process first order DRKey reply from other ASes.

        :param DRKeyReply rep: the received DRKey reply
        :param UDPMetadata meta: the metadata
        :param Bool from_zk: if the reply has been received from Zookeeper
        """
        dpld = cpld.union
        rep = dpld.union
        assert isinstance(rep, DRKeyReply), type(rep)
        logging.info("DRKeyReply received from %s: %s [id: %s]",
                     meta, rep.short_desc(), cpld.req_id_str())
        src = meta or "ZK"

        try:
            cert = self._verify_drkey_reply(rep, meta)
            raw = decrypt_drkey(rep.p.cipher, self.private_key, cert.subject_enc_key_raw)
        except SCIONVerificationError as e:
            logging.info("Invalid DRKeyReply from %s. Reason %s: %s", src, e, rep.short_desc())
            return
        except CryptoError as e:
            logging.info("Unable to decrypt DRKeyReply from %s. Reason %s: %s", src, e,
                         rep.short_desc())
            return
        drkey = FirstOrderDRKey(rep.isd_as, self.addr.isd_as, rep.p.expTime, raw)
        self.first_order_drkeys[drkey] = drkey
        if not from_zk:
            pld_packed = rep.copy().pack()
            try:
                self.drkey_cache.store("%s-%s" % (rep.isd_as, rep.p.expTime),
                                       pld_packed)
            except ZkNoConnection:
                logging.warning("Unable to store DRKey for %s in shared path: "
                                "no connection to ZK" % rep.isd_as)
                return
        self.drkey_protocol_requests.put((drkey, None))

    def _verify_drkey_reply(self, rep, meta):
        """
        Verify that the first order DRKey reply is legit.
        I.e. the signature matches, timestamp is recent.

        :param DRKeyReply rep: the first order DRKey reply.
        :param UDPMetadata meta: the metadata.
        :returns Certificate of the responder.
        :rtype: Certificate
        :raises: SCIONVerificationError
        """
        if meta and meta.ia != rep.isd_as:
            raise SCIONVerificationError("Response from other ISD-AS: %s" % rep.isd_as)
        if drkey_time() - rep.p.timestamp > DRKEY_REQUEST_TIMEOUT:
            raise SCIONVerificationError("Expired reply from %s. %ss old. Max %ss" % (
                rep.isd_as, drkey_time() - rep.p.timestamp, DRKEY_REQUEST_TIMEOUT))
        trc = self.trust_store.get_trc(rep.isd_as[0])
        chain = self.trust_store.get_cert(rep.isd_as, rep.p.certVerSrc)
        err = []
        if not chain:
            self._send_cc_request(rep.isd_as, rep.p.certVerSrc)
            err.append("Certificate not present for %s(v: %s)" % (rep.isd_as, rep.p.certVerSrc))
        if not trc:
            self._send_trc_request(rep.isd_as[0], rep.p.trcVer)
            err.append("TRC not present for %s(v: %s)" % (rep.isd_as[0], rep.p.trcVer))
        if err:
            raise SCIONVerificationError(", ".join(err))
        raw = get_signing_input_rep(rep.isd_as, rep.p.timestamp, rep.p.expTime, rep.p.cipher)
        try:
            verify_sig_chain_trc(raw, rep.p.signature, rep.isd_as, chain, trc)
        except SCIONVerificationError as e:
            raise SCIONVerificationError(str(e))
        return chain.certs[0]

    def _check_drkey(self, drkey):
        """
        Check if first order DRKey with the same (SrcIA, DstIA, expTime)
        is available.

        :param FirstOrderDRKey drkey: the searched DRKey.
        :returns: if the the first order DRKey is available.
        :rtype: Bool
        """
        if drkey in self.first_order_drkeys:
            return True
        return False

    def _fetch_drkey(self, drkey, _):
        """
        Fetch missing first order DRKey with the same (SrcIA, DstIA, expTime).

        :param FirstOrderDRKey drkey: The missing DRKey.
        """
        cert = self.trust_store.get_cert(self.addr.isd_as)
        trc = self.trust_store.get_trc(self.addr.isd_as[0])
        if not cert or not trc:
            logging.warning("DRKeyRequest for %s not sent. Own CertChain/TRC not present.",
                            drkey.src_ia)
            return
        req = get_drkey_request(drkey.src_ia, False, self.signing_key,
                                cert.certs[0].version, trc.version)
        path_meta = self._get_path_via_sciond(drkey.src_ia)
        if path_meta:
            meta = self._build_meta(drkey.src_ia, host=SVCType.CS_A, path=path_meta.fwd_path())
            req_id = mk_ctrl_req_id()
            self.send_meta(CtrlPayload(DRKeyMgmt(req)), meta)
            logging.info("DRKeyRequest (%s) sent to %s via %s [id: %016x]",
                         req.short_desc(), meta, path_meta, req_id)
        else:
            logging.warning("DRKeyRequest (for %s) not sent", req.short_desc())

    def _reply_proto_drkey(self, drkey, meta):
        pass  # TODO(roosd): implement in future PR

    def _get_drkey_secret(self, exp_time):
        """
        Get the drkey secret. A new secret is initialized if no secret is found.

        :param int exp_time: expiration time of the drkey secret
        :return: the according drkey secret
        :rtype: DRKeySecretValue
        """
        sv = self.drkey_secrets.get(exp_time)
        if not sv:
            sv = DRKeySecretValue(kdf(self.config.master_as_key, b"Derive DRKey Key"), exp_time)
            self.drkey_secrets[sv.exp_time] = sv
        return sv

    def _init_metrics(self):
        super()._init_metrics()
        for type_ in ("trc", "cc", "drkey"):
            REQS_TOTAL.labels(**self._labels, type=type_).inc(0)
        IS_MASTER.labels(**self._labels).set(0)

    def run(self):
        """
        Run an instance of the Cert Server.
        """
        threading.Thread(
            target=thread_safety_net, args=(self.worker,),
            name="CS.worker", daemon=True).start()
        super().run()


if __name__ == "__main__":
    main_wrapper(main_default, CertServer)
