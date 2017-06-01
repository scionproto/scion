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
import logging
import os
import threading

# External packages
import time

# SCION
import lib.app.sciond as lib_sciond
from endhost.sciond import SCIOND_API_SOCKDIR
from infrastructure.scion_elem import SCIONElement
from lib.crypto.certificate_chain import CertificateChain
from lib.crypto.trc import TRC
from lib.crypto.symcrypto import crypto_hash
from lib.defines import CERTIFICATE_SERVICE
from lib.main import main_default, main_wrapper
from lib.packet.cert_mgmt import (
    CertChainReply,
    CertChainRequest,
    TRCReply,
    TRCRequest,
)
from lib.packet.scion_addr import ISD_AS
from lib.packet.svc import SVCType
from lib.requests import RequestHandler
from lib.thread import thread_safety_net
from lib.types import CertMgmtType, PayloadClass
from lib.util import (
    SCIONTime,
    sleep_interval,
)
from lib.zk.cache import ZkSharedCache
from lib.zk.errors import ZkNoConnection
from lib.zk.id import ZkID
from lib.zk.zk import ZK_LOCK_SUCCESS, Zookeeper


API_TOUT = 1


class CertServer(SCIONElement):
    """
    The SCION Certificate Server.
    """
    SERVICE_TYPE = CERTIFICATE_SERVICE
    # ZK path for incoming cert chains
    ZK_CC_CACHE_PATH = "cert_chain_cache"
    # ZK path for incoming TRCs
    ZK_TRC_CACHE_PATH = "trc_cache"

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

        self.CTRL_PLD_CLASS_MAP = {
            PayloadClass.CERT: {
                CertMgmtType.CERT_CHAIN_REQ: self.process_cert_chain_request,
                CertMgmtType.CERT_CHAIN_REPLY: self.process_cert_chain_reply,
                CertMgmtType.TRC_REQ: self.process_trc_request,
                CertMgmtType.TRC_REPLY: self.process_trc_reply,
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
                # Try to become a master.
                ret = self.zk.get_lock(lock_timeout=0, conn_timeout=0)
                if ret:  # Either got the lock, or already had it.
                    if ret == ZK_LOCK_SUCCESS:
                        logging.info("Became master")
                    self.trc_cache.expire(worker_cycle * 10)
                    self.cc_cache.expire(worker_cycle * 10)
            except ZkNoConnection:
                logging.warning('worker(): ZkNoConnection')
                pass

    def _cached_trcs_handler(self, raw_entries):
        """
        Handles cached (through ZK) TRCs, passed as a list.
        """
        for raw in raw_entries:
            trc = TRC.from_raw(raw.decode('utf-8'))
            rep = TRCReply.from_values(trc)
            self.process_trc_reply(rep, None, from_zk=True)
        if len(raw_entries) > 0:
            logging.debug("Processed %s trcs from ZK", len(raw_entries))

    def _cached_certs_handler(self, raw_entries):
        """
        Handles cached (through ZK) chains, passed as a list.
        """
        for raw in raw_entries:
            cert = CertificateChain.from_raw(raw.decode('utf-8'))
            rep = CertChainReply.from_values(cert)
            self.process_cert_chain_reply(rep, None, from_zk=True)
        if len(raw_entries) > 0:
            logging.debug("Processed %s certs from ZK", len(raw_entries))

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

    def process_cert_chain_request(self, req, meta):
        """Process a certificate chain request."""
        assert isinstance(req, CertChainRequest)
        key = req.isd_as(), req.p.version
        logging.info("Cert chain request received for %sv%s from %s", *key, meta)
        local = meta.ia == self.addr.isd_as
        if not self._check_cc(key):
            if not local:
                logging.warning(
                    "Dropping CC request from %s for %sv%s: "
                    "CC not found && requester is not local)",
                    meta, *key)
            else:
                self.cc_requests.put((key, (meta, req)))
            return
        self._reply_cc(key, (meta, req))

    def process_cert_chain_reply(self, rep, meta, from_zk=False):
        """Process a certificate chain reply."""
        assert isinstance(rep, CertChainReply)
        ia_ver = rep.chain.get_leaf_isd_as_ver()
        logging.info("Cert chain reply received for %sv%s (ZK: %s)" %
                     (ia_ver[0], ia_ver[1], from_zk))
        self.trust_store.add_cert(rep.chain)
        if not from_zk:
            self._share_object(rep.chain, is_trc=False)
        # Reply to all requests for this certificate chain
        self.cc_requests.put((ia_ver, None))

    def _check_cc(self, key):
        cert_chain = self.trust_store.get_cert(*key)
        if cert_chain:
            return True
        logging.debug('Cert chain not found for %sv%s', *key)
        return False

    def _fetch_cc(self, key, req_info):
        # Do not attempt to fetch the CertChain from a remote AS if the cacheOnly flag is set.
        _, orig_req = req_info
        if orig_req.p.cacheOnly:
            return
        isd_as, ver = key
        req = CertChainRequest.from_values(isd_as, ver, cache_only=True)
        path_meta = self._get_path_via_api(isd_as)
        if path_meta:
            meta = self._build_meta(isd_as, host=SVCType.CS_A, path=path_meta.fwd_path())
            self.send_meta(req, meta)
            logging.info("Cert chain request sent to %s via [%s]: %s",
                         meta, path_meta.short_desc(), req.short_desc())
        else:
            logging.warning("Cert chain request (for %s) not sent: "
                            "no path found", req.short_desc())

    def _reply_cc(self, key, req_info):
        isd_as, ver = key
        meta = req_info[0]
        cert_chain = self.trust_store.get_cert(isd_as, ver)
        self.send_meta(CertChainReply.from_values(cert_chain), meta)
        logging.info("Cert chain for %sv%s sent to %s", isd_as, ver, meta)

    def process_trc_request(self, req, meta):
        """Process a TRC request."""
        assert isinstance(req, TRCRequest)
        key = req.isd_as()[0], req.p.version
        logging.info("TRC request received for %sv%s from %s", *key, meta)
        local = meta.ia == self.addr.isd_as
        if not self._check_trc(key):
            if not local:
                logging.warning(
                    "Dropping TRC request from %s for %sv%s: "
                    "TRC not found && requester is not local)",
                    meta, *key)
            else:
                self.trc_requests.put((key, (meta, req)))
            return
        self._reply_trc(key, (meta, req))

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
            self._share_object(trc_rep.trc, is_trc=True)
        # Reply to all requests for this TRC
        self.trc_requests.put(((isd, ver), None))

    def _check_trc(self, key):
        trc = self.trust_store.get_trc(*key)
        if trc:
            return True
        logging.debug('TRC not found for %sv%s', *key)
        return False

    def _fetch_trc(self, key, req_info):
        # Do not attempt to fetch the TRC from a remote AS if the cacheOnly flag is set.
        _, orig_req = req_info
        if orig_req.p.cacheOnly:
            return
        isd, ver = key
        isd_as = ISD_AS.from_values(isd, orig_req.isd_as()[1])
        trc_req = TRCRequest.from_values(isd_as, ver, cache_only=True)
        path_meta = self._get_path_via_api(isd_as)
        if path_meta:
            meta = self._build_meta(isd_as, host=SVCType.CS_A, path=path_meta.fwd_path())
            self.send_meta(trc_req, meta)
            logging.info("TRC request sent to %s via [%s]: %s",
                         meta, path_meta.short_desc(), trc_req.short_desc())
        else:
            logging.warning("TRC request not sent for %s: no path found.", trc_req.short_desc())

    def _reply_trc(self, key, req_info):
        isd, ver = key
        meta = req_info[0]
        trc = self.trust_store.get_trc(isd, ver)
        self.send_meta(TRCReply.from_values(trc), meta)
        logging.info("TRC for %sv%s sent to %s", isd, ver, meta)

    def _get_path_via_api(self, isd_as, flush=False):
        flags = lib_sciond.PathRequestFlags(flush=flush)
        start = time.time()
        while time.time() - start < API_TOUT:
            try:
                path_entries = lib_sciond.get_paths(
                    isd_as, flags=flags, connector=self._connector)
            except lib_sciond.SCIONDLibError as e:
                logging.error("Error during path lookup: %s" % e)
                continue
            if path_entries:
                return path_entries[0].path()
        logging.warning("Unable to get path to %s from local api.", isd_as)
        return None

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
