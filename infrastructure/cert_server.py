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
:mod:`cert_server` --- SCION certificate server
===============================================
"""
# Stdlib
import logging
import threading
from collections import defaultdict

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
from lib.packet.scion import PacketType as PT, SCIONL4Packet
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

    def __init__(self, server_id, conf_dir, is_sim=False):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param bool is_sim: running on simulator
        """
        super().__init__(server_id, conf_dir, is_sim=is_sim)
        self.cc_pend_requests = defaultdict(list)
        self.trc_pend_requests = defaultdict(list)

        self.PLD_CLASS_MAP = {
            PayloadClass.CERT: {
                CertMgmtType.CERT_CHAIN_REQ: self.process_cert_chain_request,
                CertMgmtType.CERT_CHAIN_REPLY: self.process_cert_chain_reply,
                CertMgmtType.TRC_REQ: self.process_trc_request,
                CertMgmtType.TRC_REPLY: self.process_trc_reply,
            },
        }

        if not is_sim:
            # Add more IPs here if we support dual-stack
            name_addrs = "\0".join([self.id, str(SCION_UDP_PORT),
                                    str(self.addr.host_addr)])
            self.zk = Zookeeper(
                self.topology.isd_id, self.topology.ad_id, CERTIFICATE_SERVICE,
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
        while True:
            sleep_interval(start, worker_cycle, "CS.worker cycle")
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

    def _send_reply(self, pkt, reply):
        src_isd, src_ad = pkt.addrs.src_isd, pkt.addrs.src_ad
        if (src_isd, src_ad == self.addr.get_isd_ad()):
            # Local request
            next_hop = pkt.addrs.src_addr
        else:
            # Remote request
            next_hop = self._get_next_hop(src_isd, src_ad, False, True, True)

        if next_hop:
            rep_pkt = self._build_packet(PT.CERT_MGMT, dst_isd=src_isd,
                                         dst_ad=src_ad, payload=reply)
            self.send(rep_pkt, next_hop)
            logging.info("Reply sent to (%d, %d)", src_isd, src_ad)
        else:
            logging.warning("Reply not sent: no destination found")

    def process_cert_chain_request(self, pkt):
        """
        Process a certificate chain request.

        :param cc_req: certificate chain request.
        :type cc_req: CertChainRequest
        """
        cc_req = pkt.get_payload()
        assert isinstance(cc_req, CertChainRequest)
        logging.info("Cert chain request received for %s", cc_req.short_desc())
        isd, ad, ver = cc_req.isd_id, cc_req.ad_id, cc_req.version
        cert_chain = self.trust_store.get_cert(isd, ad, ver)
        local = (pkt.addrs.src_isd, pkt.addrs.src_ad == self.addr.get_isd_ad())
        if not cert_chain and local:
            logging.debug('Cert chain not found for %s', cc_req.short_desc())
            self.cc_pend_requests[(isd, ad, ver)].append(pkt.addrs.src_addr)
            # Requesting certificate chain file from parent's cert server
            self._request_cc(cc_req)
        elif cert_chain:
            logging.debug('Cert chain found for %s', cc_req.short_desc())
            cert_chain_rep = CertChainReply.from_values(cert_chain)
            self._send_reply(pkt, cert_chain_rep)
        else:
            logging.warning("Dropping CC request (CC not found && not local)")

    def _request_cc(self, cc_req):
        req_pkt = self._build_packet(PT.CERT_MGMT, payload=cc_req)
        dst_addr = self._get_next_hop(cc_req.isd_id, cc_req.ad_id, True)
        if dst_addr:
            self.send(req_pkt, dst_addr)
            logging.info("Cert chain request sent for %s", cc_req.short_desc())
        else:
            logging.warning("Cert chain request (for %s) not sent: "
                            "no destination found", cc_req.short_desc())

    def process_cert_chain_reply(self, pkt, from_zk=False):
        """
        Process a certificate chain reply.

        :param pkt: certificate chain reply.
        :type pkt: CertChainReply
        """
        cc_rep = pkt.get_payload()
        assert isinstance(cc_rep, CertChainReply)
        logging.info("Cert chain reply received for %s, ZK: %s" %
                     (cc_rep.short_desc(), from_zk))
        self.trust_store.add_cert(cc_rep.cert_chain)
        if not from_zk:
            self._share_object(pkt, is_trc=False)
        # Reply to all requests for this certificate chain
        isd, ad, ver = cc_rep.cert_chain.get_leaf_isd_ad_ver()
        for dst_addr in self.cc_pend_requests[(isd, ad, ver)]:
            new_cc_rep = CertChainReply.from_values(cc_rep.cert_chain)
            rep_pkt = self._build_packet(dst_addr, payload=new_cc_rep)
            self.send(rep_pkt, dst_addr)
        del self.cc_pend_requests[(isd, ad, ver)]
        logging.info("Cert chain reply sent for %s", cc_rep.short_desc())

    def process_trc_request(self, pkt):
        """
        Process a TRC request.

        :param pkt: TRC request.
        :type pkt: SCIONL4Packet.
        """
        trc_req = pkt.get_payload()
        assert isinstance(trc_req, TRCRequest)
        logging.info("TRC request received for ISD %d", trc_req.isd_id)
        trc = self.trust_store.get_trc(trc_req.isd_id, trc_req.version)
        local = (pkt.addrs.src_isd, pkt.addrs.src_ad == self.addr.get_isd_ad())
        if not trc and local:
            logging.debug('TRC not found for ISD %d.', trc_req.isd_id)
            trc_tuple = (trc_req.isd_id, trc_req.version)
            self.trc_pend_requests[trc_tuple].append(pkt.addrs.src_addr)
            # Requesting TRC file from parent's cert server
            self._request_trc(trc_req)
        elif trc:
            logging.debug('TRC found for ISD %d.', trc_req.isd_id)
            trc_rep = TRCReply.from_values(trc)
            self._send_reply(pkt, trc_rep)
        else:
            logging.warning("Dropping TRC request (TRC not found && not local)")

    def _request_trc(self, trc_req):
        isd, ad, ver = trc_req.isd_id, trc_req.ad_id, trc_req.version
        new_trc_req = TRCRequest.from_values(isd, ad, ver)
        req_pkt = self._build_packet(PT.CERT_MGMT, payload=new_trc_req)
        next_hop = self._get_next_hop(isd, ad, True, False, True)
        if next_hop:
            self.send(req_pkt, next_hop)
            logging.info("TRC request sent for ISD %d.", isd)
        else:
            logging.warning("TRC request not sent for ISD %d: "
                            "no destination found.", isd)

    def process_trc_reply(self, pkt, from_zk=False):
        """
        Process a TRC reply.

        :param trc_rep: TRC reply.
        :type trc_rep: TRCReply
        """
        trc_rep = pkt.get_payload()
        assert isinstance(trc_rep, TRCReply)
        isd, ver = trc_rep.trc.get_isd_ver()
        logging.info("TRCReply received for ISD %d, ZK: %s" % (isd, from_zk))
        self.trust_store.add_trc(trc_rep.trc)
        if not from_zk:
            self._share_object(pkt, is_trc=True)
        count = 0
        # Reply to all requests for this TRC
        for dst_addr in self.trc_pend_requests[(isd, ver)]:
            new_trc_rep = TRCReply.from_values(trc_rep.trc)
            rep_pkt = self._build_packet(dst_addr, payload=new_trc_rep)
            self.send(rep_pkt, dst_addr)
            count += 1
        del self.trc_pend_requests[(isd, ver)]
        logging.info("TRC replies (%d) sent for ISD %d.", count, isd)

    def _get_next_hop(self, isd, ad, parent=False, child=False, routing=False):
        routers = []
        if parent:
            routers += self.topology.parent_edge_routers
        if child:
            routers += self.topology.child_edge_routers
        if routing:
            routers += self.topology.routing_edge_routers
        for r in routers:
            if (isd, ad) == (r.interface.neighbor_isd, r.interface.neighbor_ad):
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
