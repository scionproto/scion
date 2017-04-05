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
import base64
import logging
import os
import struct
import threading
import time

# External packages
from Crypto.Hash import SHA256
from nacl.public import PrivateKey, PublicKey

# SCION
import lib.app.sciond as lib_sciond
from endhost.sciond import SCIOND_API_SOCKDIR
from infrastructure.scion_elem import SCIONElement
from lib.crypto.asymcrypto import encrypt, sign, decrypt
from lib.crypto.symcrypto import cbcmac, kdf
from lib.defines import CERTIFICATE_SERVICE, SCION_UDP_EH_DATA_PORT
from lib.errors import SCIONParseError
from lib.main import main_default, main_wrapper
from lib.packet.cert_mgmt import (
    CertChainReply,
    CertChainRequest,
    TRCReply,
    TRCRequest,
)
from lib.packet.scion import msg_from_raw
from lib.packet.scion_addr import ISD_AS
from lib.packet.scmp_auth.scmp_auth_mgmt import (
    SCMPAuthLocalDRKeyReply,
    SCMPAuthLocalDRKeyRequest,
    SCMPAuthRemoteDRKeyReply,
    SCMPAuthRemoteDRKeyRequest,
)
from lib.packet.svc import SVCType
from lib.requests import RequestHandler
from lib.thread import thread_safety_net
from lib.types import (
    CertMgmtType,
    PayloadClass,
    SCMPAuthMgmtType,
)
from lib.util import (
    get_enc_key_file_path,
    get_sig_key_file_path,
    SCIONTime,
    sleep_interval,
    read_file,
)
from lib.zk.cache import ZkSharedCache
from lib.zk.errors import ZkNoConnection
from lib.zk.id import ZkID
from lib.zk.zk import Zookeeper

API_TOUT = 15


class CertServer(SCIONElement):
    """
    The SCION Certificate Server.
    """
    SERVICE_TYPE = CERTIFICATE_SERVICE
    # ZK path for incoming cert chains
    ZK_CC_CACHE_PATH = "cert_chain_cache"
    # ZK path for incoming TRCs
    ZK_TRC_CACHE_PATH = "trc_cache"
    ZK_SCMP_AUTH_PATH = "scmp_auth_cache"

    def __init__(self, server_id, conf_dir):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        """
        super().__init__(server_id, conf_dir)
        self.cc_requests = RequestHandler.start(
            "CC Requests", self._check_cc, self._fetch_cc, self._reply_cc,
        )
        self.trc_requests = RequestHandler.start(
            "TRC Requests", self._check_trc, self._fetch_trc, self._reply_trc,
        )
        self.scmp_auth_drkey_requests = RequestHandler.start(
            "SCMPAuth DRKey Requests", self._check_scmp_auth_drkey,
            self._fetch_scmp_auth_drkey, self._reply_scmp_auth_drkey
        )

        self.CTRL_PLD_CLASS_MAP = {
            PayloadClass.CERT: {
                CertMgmtType.CERT_CHAIN_REQ: self.process_cert_chain_request,
                CertMgmtType.CERT_CHAIN_REPLY: self.process_cert_chain_reply,
                CertMgmtType.TRC_REQ: self.process_trc_request,
                CertMgmtType.TRC_REPLY: self.process_trc_reply,
            },
            PayloadClass.SCMP_AUTH: {
                SCMPAuthMgmtType.LOCAL_REPLY:
                    self.process_scmp_auth_local_drkey_reply,
                SCMPAuthMgmtType.LOCAL_REQUEST:
                    self.process_scmp_auth_local_drkey_request,
                SCMPAuthMgmtType.REMOTE_REPLY:
                    self.process_scmp_auth_remote_drkey_reply,
                SCMPAuthMgmtType.REMOTE_REQUEST:
                    self.process_scmp_auth_remote_drkey_request,
            }
        }

        zkid = ZkID.from_values(self.addr.isd_as, self.id,
                                [(self.addr.host, self._port)]).pack()
        self.zk = Zookeeper(self.topology.isd_as, CERTIFICATE_SERVICE,
                            zkid, self.topology.zookeepers)
        self.zk.retry("Joining party", self.zk.party_setup)
        self.trc_cache = ZkSharedCache(self.zk, self.ZK_TRC_CACHE_PATH,
                                       self._cached_entries_handler)
        self.cc_cache = ZkSharedCache(self.zk, self.ZK_CC_CACHE_PATH,
                                      self._cached_entries_handler)
        self.scmp_auth_cache = ZkSharedCache(self.zk, self.ZK_SCMP_AUTH_PATH,
                                             self._cached_scmp_auth_handler)

        sig_key_file = get_sig_key_file_path(self.conf_dir)
        self.signing_key = base64.b64decode(read_file(sig_key_file))
        enc_key_file = get_enc_key_file_path(self.conf_dir)
        self.private_key = PrivateKey(base64.b64decode(read_file(enc_key_file)))
        self.public_key = self.private_key.public_key

        self.scmp_auth_keys = {}  # Map: isd_as -> DRKey
        self.scmp_auth_key = kdf(self.config.master_as_key, b"Derive SCMP Key")
        logging.debug("SCMP auth key %s",
                      self.scmp_auth_key.hex())  # TODO(roosd) remove
        logging.debug("zero message mac: msg, %s",
                      cbcmac(self.scmp_auth_key, bytes(16)).hex())
        self._api_addr = os.path.join(SCIOND_API_SOCKDIR, "sd%s.sock" %
                                      self.addr.isd_as)
        self._connector = lib_sciond.init(self._api_addr)

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
            try:
                self.zk.wait_connected()
                self.trc_cache.process()
                self.cc_cache.process()
                self.scmp_auth_cache.process()
                # Try to become a master.
                if self.zk.get_lock(lock_timeout=0, conn_timeout=0):
                    self.trc_cache.expire(worker_cycle * 10)
                    self.cc_cache.expire(worker_cycle * 10)
                    self.scmp_auth_cache.expire(worker_cycle * 10)
            except ZkNoConnection:
                logging.warning('worker(): ZkNoConnection')
                pass

    def _cached_entries_handler(self, raw_entries):
        """
        Handles cached (through ZK) TRCs and Cert Chains.
        """
        for entry in raw_entries:
            payload = msg_from_raw(entry)
            if isinstance(payload, CertChainReply):
                self.process_cert_chain_reply(payload, None, from_zk=True)
            elif isinstance(payload, TRCReply):
                self.process_trc_reply(payload, None, from_zk=True)
            else:
                logging.warning("Entry with unsupported type: %s" % entry)

    def _share_object(self, pld, is_trc):
        """
        Share path segments (via ZK) with other path servers.
        """
        pld_packed = pld.pack()
        pld_hash = SHA256.new(pld_packed).hexdigest()
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

    def _send_reply(self, src, src_port, payload):
        if src.isd_as == self.addr.isd_as:
            # Local request
            next_hop, port = src.host, SCION_UDP_EH_DATA_PORT
            dst_addr = next_hop
        else:
            # Remote request
            next_hop, port = self._get_next_hop(src.isd_as, False, True, True)
            dst_addr = SVCType.CS_A
        if next_hop:
            rep_pkt = self._build_packet(
                dst_addr, dst_ia=src.isd_as, payload=payload, dst_port=src_port)
            self.send(rep_pkt, next_hop, port)
        else:
            logging.warning("Reply not sent: no destination found")

    def process_cert_chain_request(self, req, meta):
        """Process a certificate chain request."""
        assert isinstance(req, CertChainRequest)
        key = req.isd_as(), req.p.version
        logging.info("Cert chain request received for %sv%s", *key)
        local = meta.ia == self.addr.isd_as
        if not self._check_cc(key) and not local:
            logging.warning(
                "Dropping CC request from %s for %sv%s: "
                "CC not found && requester is not local)",
                meta.get_addr(), *key)
        if req.p.cacheOnly:
            self._reply_cc(key, meta)
            return
        self.cc_requests.put((key, meta))

    def process_cert_chain_reply(self, rep, meta, from_zk=False):
        """Process a certificate chain reply."""
        assert isinstance(rep, CertChainReply)
        ia_ver = rep.chain.get_leaf_isd_as_ver()
        logging.info("Cert chain reply received for %sv%s (ZK: %s)" %
                     (ia_ver[0], ia_ver[1], from_zk))
        self.trust_store.add_cert(rep.chain)
        if not from_zk:
            self._share_object(rep, is_trc=False)
        # Reply to all requests for this certificate chain
        self.cc_requests.put((ia_ver, None))

    def _check_cc(self, key):
        cert_chain = self.trust_store.get_cert(*key)
        if cert_chain:
            return True
        logging.debug('Cert chain not found for %sv%s', *key)
        return False

    def _fetch_cc(self, key, _):
        isd_as, ver = key
        req = CertChainRequest.from_values(isd_as, ver)
        dst_addr, port = self._get_next_hop(isd_as, True)
        req_pkt = self._build_packet(SVCType.CS_A, dst_ia=isd_as, payload=req)
        if dst_addr:
            self.send(req_pkt, dst_addr, port)
            logging.info("Cert chain request sent: %s", req.short_desc())
        else:
            logging.warning("Cert chain request (for %s) not sent: "
                            "no destination found", req.short_desc())

    def _reply_cc(self, key, meta):
        isd_as, ver = key
        dst = meta.get_addr()
        port = meta.port
        cert_chain = self.trust_store.get_cert(isd_as, ver)
        self._send_reply(dst, port, CertChainReply.from_values(cert_chain))
        logging.info("Cert chain for %sv%s sent to %s:%s",
                     isd_as, ver, dst, port)

    def process_trc_request(self, req, meta):
        """Process a TRC request."""
        assert isinstance(req, TRCRequest)
        key = req.isd_as()[0], req.p.version
        logging.info("TRC request received for %sv%s", *key)
        local = meta.ia == self.addr.isd_as
        if not self._check_trc(key) and not local:
            logging.warning(
                "Dropping TRC request from %s for %sv%s: "
                "TRC not found && requester is not local)",
                meta.get_addr(), *key)
        if req.p.cacheOnly:
            self._reply_trc(key, meta)
            return
        self.trc_requests.put((key, (meta, req.isd_as()[1]),))

    def process_trc_reply(self, trc_rep, meta, from_zk=False):
        """
        Process a TRC reply.

        :param trc_rep: TRC reply.
        :type trc_rep: TRCReply
        """
        assert isinstance(trc_rep, TRCReply)
        isd, ver = trc_rep.trc.get_isd_ver()
        logging.info("TRCReply received for ISD %sv%s, ZK: %s",
                     isd, ver, from_zk)
        self.trust_store.add_trc(trc_rep.trc)
        if not from_zk:
            self._share_object(trc_rep, is_trc=True)
        # Reply to all requests for this TRC
        self.trc_requests.put(((isd, ver), None))

    def _check_trc(self, key):
        trc = self.trust_store.get_trc(*key)
        if trc:
            return True
        logging.debug('TRC not found for %sv%s', *key)
        return False

    def _fetch_trc(self, key, info):
        isd, ver = key
        isd_as = ISD_AS.from_values(isd, info[1])
        trc_req = TRCRequest.from_values(isd_as, ver)
        req_pkt = self._build_packet(SVCType.CS_A, payload=trc_req)
        next_hop, port = self._get_next_hop(isd_as, True, False, True)
        if next_hop:
            self.send(req_pkt, next_hop, port)
            logging.info("TRC request sent for %sv%s.", *key)
        else:
            logging.warning("TRC request not sent for %sv%s: "
                            "no destination found.", *key)

    def _reply_trc(self, key, info):
        isd, ver = key
        meta = info[0]
        dst = meta.get_addr()
        port = meta.port
        trc = self.trust_store.get_trc(isd, ver)
        self._send_reply(dst, port, TRCReply.from_values(trc))
        logging.info("TRC for %sv%s sent to %s:%s", isd, ver, dst, port)

    def _get_next_hop(self, isd_as, parent=False, child=False, core=False):
        routers = []
        if parent:
            routers += self.topology.parent_border_routers
        if child:
            routers += self.topology.child_border_routers
        if core:
            routers += self.topology.core_border_routers
        for r in routers:
            r_ia = r.interface.isd_as
            if (isd_as == r_ia) or (isd_as[0] == r_ia[0] and isd_as[1] == 0):
                return r.addr, r.port
        return None, None

    def run(self):
        """
        Run an instance of the Cert Server.
        """
        threading.Thread(
            target=thread_safety_net, args=(self.worker,),
            name="CS.worker", daemon=True).start()
        super().run()

    def _cached_scmp_auth_handler(self, raw_entries):
        for entry in raw_entries:
            try:
                rep = SCMPAuthLocalDRKeyReply.from_raw(entry)
            except SCIONParseError as e:
                logging.error("Error parsing ZK SCMPAuth cache: %s", e)
                return
            self.process_scmp_auth_local_drkey_reply(rep)

    def process_scmp_auth_local_drkey_request(self, req, meta):
        assert isinstance(req, SCMPAuthLocalDRKeyRequest)

        # TODO(roosd): Check that privileged to request key
        if self.addr.isd_as == meta.ia:
            self.scmp_auth_drkey_requests.put((req.isd_as, meta))
        else:
            logging.info("Invalid SCMPAuthLocalDRKeyRequest from %s",
                         meta.get_addr())

    def process_scmp_auth_local_drkey_reply(self, rep, meta=None):
        assert isinstance(rep, SCMPAuthLocalDRKeyReply)

        logging.info("SCMPAuthLocalDRKeyReply received for ISD-AS %s",
                     rep.isd_as)
        # TODO(roosd): decrypt before loading from Zookeeper
        self.scmp_auth_keys[rep.isd_as] = rep.cipher
        # Reply to all requests for this SCMPAuth DRKey
        self.scmp_auth_drkey_requests.put((rep.isd_as, None))

    def process_scmp_auth_remote_drkey_request(self, req, meta):
        assert isinstance(req, SCMPAuthRemoteDRKeyRequest)
        if self.addr.isd_as != req.isd_as:
            logging.info("Invalid SCMPAuthRemoteDRKeyRequest from %s",
                         meta.get_addr())
            return

        # TODO(roosd): verify chain
        cert = req.chain.certs[0]
        logging.debug("Type of cert %s", type(cert))
        logging.debug("len key %s", len(cert.subject_enc_key_raw))
        drkey = cbcmac(self.scmp_auth_key,
                       b"".join([struct.pack("!I", meta.ia._isd),
                                 struct.pack("!I", meta.ia._as),
                                 bytes(8)]))
        cipher = encrypt(drkey, self.private_key,
                         PublicKey(cert.subject_enc_key_raw))
        timestamp = int(time.time())
        cert = self.trust_store.get_cert(req.isd_as)
        sig = sign(b"".join([req.isd_as.pack(), cipher]), self.signing_key)
        rep = SCMPAuthRemoteDRKeyReply.from_values(req.isd_as, timestamp,
                                                   cipher, sig, cert)
        self._send_payload(meta.ia, rep, meta.path, meta.host, meta.port)
        logging.info("SCMPAuthRemoteDRKeyReply for %s sent to %s:%s",
                     req.isd_as, meta.get_addr(), meta.port)

    def process_scmp_auth_remote_drkey_reply(self, rep, meta):
        assert isinstance(rep, SCMPAuthRemoteDRKeyReply)
        logging.info("SCMPAuthRemoteDRKeyReply received for ISD-AS %s",
                     rep.isd_as)
        # TODO(roosd): verify signature
        cert = rep.chain.certs[0]
        drkey = decrypt(rep.cipher, self.private_key,
                        PublicKey(cert.subject_enc_key_raw))
        self.scmp_auth_keys[rep.isd_as] = drkey
        # TODO(roosd): encrypt before sharing on Zookeeper
        pld = SCMPAuthLocalDRKeyReply.from_values(rep.isd_as, drkey)
        try:
            self.scmp_auth_cache.store(str(rep.isd_as), pld.pack())
        except ZkNoConnection:
            logging.warning("Unable to store SCMPAuthDRKeyReply in shared path:"
                            "no connection to ZK")
            return
        logging.debug("SCMPAuthLocalDRKeyReply stored in ZK: %s" % rep.isd_as)
        # Reply to all requests for this SCMPAuth DRKey
        self.scmp_auth_drkey_requests.put((rep.isd_as, None))

    def _check_scmp_auth_drkey(self, key):
        drkey = self.scmp_auth_keys.get(key)
        if drkey:
            return True
        logging.debug('SCMPAuthDRKey not found for %s', key)
        return False

    def _fetch_scmp_auth_drkey(self, isd_as, meta):
        timestamp = int(time.time())
        req = SCMPAuthRemoteDRKeyRequest.from_values(
            isd_as, timestamp, sign(isd_as.pack(), self.signing_key),
            self.trust_store.get_cert(self.addr.isd_as))
        path = self._get_path_via_api(isd_as)
        if path and self._send_payload(isd_as, req, path):
            logging.info("SCMPAuthRemoteDRKeyRequest sent: %s", req)
        else:
            logging.warning("SCMPAuthRemoteDRKeyRequest (for %s) not sent",
                            req.short_desc())

    def _reply_scmp_auth_drkey(self, isd_as, meta):
        try:
            drkey = self.scmp_auth_keys.get(isd_as)
        except KeyError:
            logging.warning("SCMPAuthDRKey for %s not found.", isd_as)
            return
        # TODO(roosd): encrypt before sending to BR
        payload = SCMPAuthLocalDRKeyReply.from_values(isd_as, drkey)
        self._send_payload(meta.ia, payload, meta.path, meta.host, meta.port)
        logging.info("SCMPAuthDRKeyLocalReply for %s sent to %s:%s", isd_as,
                     meta.host, meta.port)

    def _get_path_via_api(self, isd_as, flush=False):
        path_entries = self._try_sciond_api(isd_as, flush)
        return path_entries[0].path().fwd_path()

    def _try_sciond_api(self, isd_as, flush=False):
        flags = lib_sciond.PathRequestFlags(flush=flush)
        start = time.time()
        while time.time() - start < API_TOUT:
            try:
                path_entries = lib_sciond.get_paths(
                    isd_as, flags=flags, connector=self._connector)
            except lib_sciond.SCIONDLibError as e:
                logging.error("Error during path lookup: %s" % e)
                continue
            return path_entries
        logging.critical("Unable to get path from local api.")

    def _send_payload(self, isd_as, payload, path, host=SVCType.CS_A, port=0):
        pkt = self._build_packet(host, dst_ia=isd_as, payload=payload,
                                 path=path, dst_port=port)
        next, next_port = self.get_first_hop(pkt)
        if (next, next_port) == (None, None):
            logging.error("Can't find first hop, dropping packet\n%s", pkt)
            return False
        if next == host:
            next_port = port
        return self.send(pkt, next, next_port)

if __name__ == "__main__":
    main_wrapper(main_default, CertServer)
