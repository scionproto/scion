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
import threading

# External packages
from Crypto.Hash import SHA256

# SCION
from infrastructure.scion_elem import SCIONElement
from lib.defines import CERTIFICATE_SERVICE, SCION_UDP_PORT
from lib.errors import SCIONParseError
from lib.log import log_exception
from lib.main import main_default, main_wrapper
from lib.packet.cert_mgmt import (
    CertChainReply,
    CertChainRequest,
    TRCReply,
    TRCRequest,
)
from lib.packet.scion import SCIONL4Packet, SVCType
from lib.packet.scion_addr import ISD_AS
from lib.requests import RequestHandler
from lib.thread import thread_safety_net
from lib.types import CertMgmtType, PayloadClass
from lib.util import (
    SCIONTime,
    sleep_interval,
)
from lib.zookeeper import ZkNoConnection, ZkSharedCache, Zookeeper


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

        # Add more IPs here if we support dual-stack
        name_addrs = "\0".join([self.id, str(SCION_UDP_PORT),
                                str(self.addr.host)])
        self.zk = Zookeeper(self.topology.isd_as, CERTIFICATE_SERVICE,
                            name_addrs, self.topology.zookeepers)
        self.zk.retry("Joining party", self.zk.party_setup)
        self.trc_cache = ZkSharedCache(self.zk, self.ZK_TRC_CACHE_PATH,
                                       self._cached_entries_handler)
        self.cc_cache = ZkSharedCache(self.zk, self.ZK_CC_CACHE_PATH,
                                      self._cached_entries_handler)

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
                if self.zk.get_lock(lock_timeout=0, conn_timeout=0):
                    self.trc_cache.expire(worker_cycle * 10)
                    self.cc_cache.expire(worker_cycle * 10)
            except ZkNoConnection:
                logging.warning('worker(): ZkNoConnection')
                pass

    def _cached_entries_handler(self, raw_entries):
        """
        Handles cached (through ZK) TRCs and Cert Chains.
        """
        for entry in raw_entries:
            try:
                pkt = SCIONL4Packet(raw=entry)
                pkt.parse_payload()
                # FIXME(PSz): some checks are necessary, as filesystem may not
                # be synced with ZK. Also, when we change topology, new TRCs and
                # certs are generated, while old ones are still in ZK. It looks
                # to CS like an attack.  This will be fixed when more elements
                # of trust infrastructure are specified and implemented (like
                # TRC cross-signing).
            except SCIONParseError:
                log_exception("Error parsing cached entry: %s" % entry,
                              level=logging.ERROR)
                continue
            payload = pkt.get_payload()
            if isinstance(payload, CertChainReply):
                self.process_cert_chain_reply(pkt, from_zk=True)
            elif isinstance(payload, TRCReply):
                self.process_trc_reply(pkt, from_zk=True)
            else:
                logging.warning("Entry with unsupported type: %s" % entry)

    def _share_object(self, pkt, is_trc):
        """
        Share path segments (via ZK) with other path servers.
        """
        pkt_packed = pkt.pack()
        pkt_hash = SHA256.new(pkt_packed).hexdigest()
        try:
            if is_trc:
                self.trc_cache.store("%s-%s" % (pkt_hash, SCIONTime.get_time()),
                                     pkt_packed)
            else:
                self.cc_cache.store("%s-%s" % (pkt_hash, SCIONTime.get_time()),
                                    pkt_packed)
        except ZkNoConnection:
            logging.warning("Unable to store %s in shared path: "
                            "no connection to ZK" % "TRC" if is_trc else "CC")
            return
        logging.debug("%s stored in ZK: %s" % ("TRC" if is_trc else "CC",
                                               pkt_hash))

    def _send_reply(self, src, src_port, payload):
        if src.isd_as == self.addr.isd_as:
            # Local request
            next_hop = src.host
            dst_addr = next_hop
        else:
            # Remote request
            next_hop = self._get_next_hop(src.isd_as, False, True, True)
            dst_addr = SVCType.CS
        if next_hop:
            rep_pkt = self._build_packet(
                dst_addr, dst_ia=src.isd_as, payload=payload, dst_port=src_port)
            self.send(rep_pkt, next_hop)
        else:
            logging.warning("Reply not sent: no destination found")

    def process_cert_chain_request(self, pkt):
        """Process a certificate chain request."""
        req = pkt.get_payload()
        assert isinstance(req, CertChainRequest)
        key = req.isd_as(), req.p.version
        logging.info("Cert chain request received for %sv%s", *key)
        local = pkt.addrs.src.isd_as == self.addr.isd_as
        if not self._check_cc(key) and not local:
            logging.warning(
                "Dropping CC request from %s for %sv%s: "
                "CC not found && requester is not local)",
                pkt.addrs.src, *key)
        self.cc_requests.put((key, (pkt.addrs.src, pkt.l4_hdr.src_port)))

    def process_cert_chain_reply(self, pkt, from_zk=False):
        """Process a certificate chain reply."""
        rep = pkt.get_payload()
        assert isinstance(rep, CertChainReply)
        ia_ver = rep.chain.get_leaf_isd_as_ver()
        logging.info("Cert chain reply received for %sv%s (ZK: %s)" %
                     (ia_ver[0], ia_ver[1], from_zk))
        self.trust_store.add_cert(rep.chain)
        if not from_zk:
            self._share_object(pkt, is_trc=False)
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
        dst_addr = self._get_next_hop(isd_as, True)
        req_pkt = self._build_packet(SVCType.CS, dst_ia=isd_as, payload=req)
        if dst_addr:
            self.send(req_pkt, dst_addr)
            logging.info("Cert chain request sent: %s", req.short_desc())
        else:
            logging.warning("Cert chain request (for %s) not sent: "
                            "no destination found", req.short_desc())

    def _reply_cc(self, key, info):
        isd_as, ver = key
        src, port = info
        cert_chain = self.trust_store.get_cert(isd_as, ver)
        self._send_reply(src, port, CertChainReply.from_values(cert_chain))
        logging.info("Cert chain for %sv%s sent to %s:%s",
                     isd_as, ver, src, port)

    def process_trc_request(self, pkt):
        """Process a TRC request."""
        req = pkt.get_payload()
        assert isinstance(req, TRCRequest)
        key = req.isd_as()[0], req.p.version
        logging.info("TRC request received for %sv%s", *key)
        local = pkt.addrs.src.isd_as == self.addr.isd_as
        if not self._check_trc(key) and not local:
            logging.warning(
                "Dropping TRC request from %s for %sv%s: "
                "TRC not found && requester is not local)",
                pkt.addrs.src, *key)
        self.trc_requests.put((
            key, (pkt.addrs.src, pkt.l4_hdr.src_port, req.isd_as()[1]),
        ))

    def process_trc_reply(self, pkt, from_zk=False):
        """
        Process a TRC reply.

        :param trc_rep: TRC reply.
        :type trc_rep: TRCReply
        """
        trc_rep = pkt.get_payload()
        assert isinstance(trc_rep, TRCReply)
        isd, ver = trc_rep.trc.get_isd_ver()
        logging.info("TRCReply received for ISD %sv%s, ZK: %s",
                     isd, ver, from_zk)
        self.trust_store.add_trc(trc_rep.trc)
        if not from_zk:
            self._share_object(pkt, is_trc=True)
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
        isd_as = ISD_AS.from_values(isd, info[2])
        trc_req = TRCRequest.from_values(isd_as, ver)
        req_pkt = self._build_packet(SVCType.CS, payload=trc_req)
        next_hop = self._get_next_hop(isd_as, True, False, True)
        if next_hop:
            self.send(req_pkt, next_hop)
            logging.info("TRC request sent for %sv%s.", *key)
        else:
            logging.warning("TRC request not sent for %sv%s: "
                            "no destination found.", *key)

    def _reply_trc(self, key, info):
        isd, ver = key
        src, port, _ = info
        trc = self.trust_store.get_trc(isd, ver)
        self._send_reply(src, port, TRCReply.from_values(trc))
        logging.info("TRC for %sv%s sent to %s:%s", isd, ver, src, port)

    def _get_next_hop(self, isd_as, parent=False, child=False, routing=False):
        routers = []
        if parent:
            routers += self.topology.parent_edge_routers
        if child:
            routers += self.topology.child_edge_routers
        if routing:
            routers += self.topology.routing_edge_routers
        for r in routers:
            r_ia = r.interface.isd_as
            if (isd_as == r_ia) or (isd_as[0] == r_ia[0] and isd_as[1] == 0):
                return r.addr
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
