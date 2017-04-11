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
import threading
import time

# External packages
from Crypto.Hash import SHA256
from nacl.public import PrivateKey

# SCION
import lib.app.sciond as lib_sciond
from endhost.sciond import SCIOND_API_SOCKDIR
from infrastructure.scion_elem import SCIONElement
from lib.crypto.symcrypto import cbcmac, kdf
from lib.defines import CERTIFICATE_SERVICE, SCION_UDP_EH_DATA_PORT
from lib.drkey.drkey_mgmt import (
    DRKeyReply,
    DRKeyRequest,
    DRKeyProtocolReply,
    DRKeyProtocolRequest,
)
from lib.drkey.protocol import DRKeyProtocol
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
from lib.packet.svc import SVCType
from lib.requests import RequestHandler
from lib.thread import thread_safety_net
from lib.types import (
    CertMgmtType,
    DRKeyMgmtType,
    PayloadClass,
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
        self.drkey_requests = RequestHandler.start(
            "DRKey Requests", self._check_drkey,
            self._fetch_drkey, self._reply_drkey
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
                DRKeyMgmtType.PROTOCOL_REQUEST:
                    self.process_protocol_drkey_request,
            },
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
        self.drkey_cache = ZkSharedCache(self.zk, self.ZK_SCMP_AUTH_PATH,
                                         self._cached_entries_handler)

        sig_key_file = get_sig_key_file_path(self.conf_dir)
        self.signing_key = base64.b64decode(read_file(sig_key_file))
        enc_key_file = get_enc_key_file_path(self.conf_dir)
        self.private_key = PrivateKey(base64.b64decode(read_file(enc_key_file)))
        self.public_key = self.private_key.public_key
        self._api_addr = os.path.join(SCIOND_API_SOCKDIR, "sd%s.sock" %
                                      self.addr.isd_as)
        self._connector = lib_sciond.init(self._api_addr)

        self.drkey_secret = kdf(self.config.master_as_key, b"Derive DRKey Key")
        self.drkey_secret_prefetch = self.drkey_secret  # FIXME(roosd): adapt
        key = DRKeyProtocol.derive_drkey(self.drkey_secret, self.addr.isd_as)
        # Map: (isd_as, prefetched) -> (DRKey, expire_time)
        self.first_order_drkeys = {(self.addr.isd_as, False): (key, 0)}
        logging.debug("SCMP auth key %s",
                      self.drkey_secret.hex())  # TODO(roosd) remove
        logging.debug("zero message mac: msg, %s",
                      cbcmac(self.drkey_secret, bytes(16)).hex())

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
                self.drkey_cache.process()
                # Try to become a master.
                if self.zk.get_lock(lock_timeout=0, conn_timeout=0):
                    self.trc_cache.expire(worker_cycle * 10)
                    self.cc_cache.expire(worker_cycle * 10)
                    self.drkey_cache.expire(worker_cycle * 10)
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
            elif isinstance(payload, DRKeyReply):
                self.process_drkey_reply(payload, None, from_zk=True)
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

    def process_protocol_drkey_request(self, req, meta):
        assert isinstance(req, DRKeyProtocolRequest)
        logging.debug("Received DRKeyProtocolRequest from %s", meta.get_addr)
        drkey_req, err = self._decrypt_and_verify_proto_drkey_request(req, meta)
        if err:
            logging.info("Invalid DRKeyProtocolRequest from %s: %s",
                         meta.get_addr(), err)
            return

        self.drkey_requests.put((drkey_req.src_ia, (drkey_req, meta)))

    def process_drkey_request(self, req, meta):
        assert isinstance(req, DRKeyRequest)
        logging.info("DRKeyRequest received from ISD-AS %s", req.isd_as)

        err = self._verify_drkey_request(req, meta)
        if err:
            logging.info("Invalid DRKeyRequest from %s. Reason: %s",
                         meta.get_addr(), err)
            return

        cert = req.chain.certs[0]
        params = DRKeyProtocol.Params()
        params.secret = self.drkey_secret_prefetch if req.p.prefetch else \
            self.drkey_secret
        params.src_ia = self.addr.isd_as
        params.dst_ia = meta.ia
        params.private_key = self.private_key
        params.public_key = cert.subject_enc_key_raw
        params.prefetch = req.p.prefetch
        params.signing_key = self.signing_key
        params.chain = self.trust_store.get_cert(self.addr.isd_as)

        rep = DRKeyProtocol.get_drkey_reply(params)
        self._send_payload(meta.ia, rep, meta.path, meta.host, meta.port)
        logging.info("DRKeyReply for %s sent to %s:%s",
                     req.isd_as, meta.get_addr(), meta.port)

    def process_drkey_reply(self, rep, meta, from_zk=False):
        assert isinstance(rep, DRKeyReply)
        logging.info("DRKeyReply received from ISD-AS %s", rep.isd_as)

        if not from_zk:
            err = self._verify_drkey_reply(rep, meta)
            if err:
                logging.info("Invalid DRKeyReply from %s. Reason: %s",
                             meta.get_addr(), err)
                return
        cert = rep.chain.certs[0]
        drkey = DRKeyProtocol.decrypt_drkey(
            rep.p.cipher, self.private_key, cert.subject_enc_key_raw)
        self._insert_first_order_drkey(rep, drkey)
        if from_zk:
            pld_packed = rep.pack()
            try:
                self.drkey_cache.store("%s-%s" % (rep.isd_as, rep.p.prefetch),
                                       pld_packed)
            except ZkNoConnection:
                logging.warning("Unable to store DRKey for %s in shared path: "
                                "no connection to ZK" % rep.isd_as)
                return
            logging.debug("DRKey for %s stored in ZK." % rep.isd_as)
        self.drkey_requests.put((rep.isd_as, None))

    def _check_drkey(self, isd_as):
        # TODO(roosd): improve logic
        pair = self.first_order_drkeys.get((isd_as, False))
        if not pair:
            return False
        drkey, exp_time = pair
        if not exp_time or exp_time > time.time():
            return True
        return False

    def _fetch_drkey(self, isd_as, _):
        params = DRKeyProtocol.Params()
        params.prefetch = False
        params.dst_ia = isd_as
        params.signing_key = self.signing_key
        params.chain = self.trust_store.get_cert(self.addr.isd_as)
        req = DRKeyProtocol.get_drkey_request(params)
        path = self._get_path_via_api(isd_as)
        if path and self._send_payload(isd_as, req, path):
            logging.info("DRKeyRequest sent: %s", req)
        else:
            logging.warning("DRKeyRequest (for %s) not sent",
                            req.short_desc())

    def _reply_drkey(self, isd_as, value):
        req, meta = value
        assert isinstance(req, DRKeyProtocolRequest.Request)
        # Prefetch without having current key
        if not self._check_drkey(isd_as):
            self.drkey_requests.put((isd_as, value))
            logging.debug("cannot answer, redo request")
            return
        master_drkey, exp_time = self.first_order_drkeys.get((isd_as, False))
        timestamp = int(time.time() * 1000000)
        generator = DRKeyProtocol.get_protocol_drkey_generator(req.p.protocol)
        drkey = generator(master_drkey, req, meta)
        reply = DRKeyProtocolReply.Reply.from_values(
            req.p.reqID, drkey, exp_time)
        cipher, signature = self._encrypt_and_sign_proto_drkey_reply(reply)
        pld = DRKeyProtocolReply.from_values(timestamp, cipher, signature)
        self._send_payload(meta.ia, pld, meta.path, meta.host, meta.port)
        logging.info("DRKeyProtocolReply for (%s) sent to %s:%s",
                     req.short_desc(), meta.host, meta.port)

    def _verify_drkey_request(self, req, meta):
        if self.addr.isd_as != req.isd_as:
            return "wrong ISD-AS: %s" % req.isd_as

        # TODO(roosd): verify chain
        # TODO(roosd): verify signature
        return None

    def _verify_drkey_reply(self, rep, meta):
        # TODO(roosd): verify chain
        # TODO(roosd): verify signature
        # TODO(roosd): verify correct time
        return None

    def _decrypt_and_verify_proto_drkey_request(self, req, meta):
        # TODO(roosd): verify/check timestamp
        # TODO(roosd): decrypt
        decrypted = req.p.cipher
        try:
            request = DRKeyProtocolRequest.Request.from_raw(decrypted)
        except SCIONParseError:
            return None, "failed parsing request"
        return request, None

    def _encrypt_and_sign_proto_drkey_reply(self, reply):
        # TODO(roosd): encrypt and sign
        return reply.pack(), bytes(0)

    def _insert_first_order_drkey(self, rep, drkey):
        # TODO(roosd): improve logic
        key = (rep.isd_as, rep.p.prefetch != 0)
        value = (drkey, DRKeyProtocol.get_exp_time(
            rep.isd_as, self.addr.isd_as, rep.p.timestamp, key[1]))
        self.first_order_drkeys[key] = value

    def _get_path_via_api(self, isd_as, flush=False):
        path_entries = self._try_sciond_api(isd_as, flush)
        if path_entries:
            return path_entries[0].path().fwd_path()
        return None

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
            next_port = SCION_UDP_EH_DATA_PORT
        return self.send(pkt, next, next_port)


if __name__ == "__main__":
    main_wrapper(main_default, CertServer)
