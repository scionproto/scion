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

from infrastructure.scion_elem import SCIONElement
from ipaddress import IPv4Address
from lib.crypto.certificate import CertificateChain, TRC
from lib.packet.scion import (SCIONPacket, get_type, PacketType as PT,
    CertChainRequest, CertChainReply, TRCRequest, TRCReply)
from lib.util import (read_file, write_file, get_cert_chain_file_path,
    get_trc_file_path, handle_signals)
from lib.log import (init_logging, log_exception)
from lib.thread import thread_safety_net
from lib.util import timed
from lib.zookeeper import (Zookeeper, ZkConnectionLoss, ZkNoNodeError)
from parse import *
import collections
import datetime
import logging
import os
import sys
import threading
import time


class CertServer(SCIONElement):
    """
    The SCION Certificate Server.
    """
    # ZK path for incoming cert chains
    ZK_CERT_CHAIN_CACHE_PATH = "cert_chain_cache"
    # ZK path for incoming TRCs
    ZK_TRC_CACHE_PATH = "trc_cache"

    def __init__(self, addr, topo_file, config_file, trc_file):
        SCIONElement.__init__(self, addr, topo_file, config_file=config_file)
        self.trc = TRC(trc_file)
        self.cert_chain_requests = collections.defaultdict(list)
        self.trc_requests = collections.defaultdict(list)
        self.cert_chains = {}
        self.trcs = {}
        self._latest_entry = 0
        # Set when we have connected and read the existing recent and incoming
        # cert chains and TRCs
        self._state_synced = threading.Event()
        # TODO(lorenzo): def zookeeper host/port in topology
        self.zk = Zookeeper(self.topology.isd_id, self.topology.ad_id,
                            "cs", self.addr.host_addr, ["localhost:2181"],
                            ensure_paths=(self.ZK_CERT_CHAIN_CACHE_PATH,
                                          self.ZK_TRC_CACHE_PATH,))

    def process_cert_chain_request(self, cert_chain_req):
        """
        Process a certificate chain request.
        """
        assert isinstance(cert_chain_req, CertChainRequest)
        logging.info("Certificate chain request received.")
        cert_chain = self.cert_chains.get((cert_chain_req.isd_id,
            cert_chain_req.ad_id, cert_chain_req.version))
        if not cert_chain:
            # Try loading file from disk
            cert_chain_file = get_cert_chain_file_path(self.topology.isd_id,
                self.topology.ad_id, cert_chain_req.isd_id,
                cert_chain_req.ad_id, cert_chain_req.version)
            if os.path.exists(cert_chain_file):
                cert_chain = read_file(cert_chain_file).encode('utf-8')
                self.cert_chains[(cert_chain_req.isd_id, cert_chain_req.ad_id,
                                  cert_chain_req.version)] = cert_chain
        if not cert_chain:
            # Requesting certificate chain file from parent's cert server
            logging.debug('Certificate chain not found.')
            cert_chain_tuple = (cert_chain_req.isd_id, cert_chain_req.ad_id,
                                cert_chain_req.version)
            self.cert_chain_requests[cert_chain_tuple].append(
                cert_chain_req.hdr.src_addr.host_addr)
            new_cert_chain_req = CertChainRequest.from_values(PT.CERT_CHAIN_REQ,
                self.addr, cert_chain_req.ingress_if, cert_chain_req.src_isd,
                cert_chain_req.src_ad, cert_chain_req.isd_id,
                cert_chain_req.ad_id, cert_chain_req.version)
            dst_addr = self.ifid2addr[cert_chain_req.ingress_if]
            self.send(new_cert_chain_req, dst_addr)
            logging.info("New certificate chain request sent.")
        else:
            logging.debug('Certificate chain found.')
            cert_chain_rep = CertChainReply.from_values(self.addr,
                cert_chain_req.isd_id, cert_chain_req.ad_id,
                cert_chain_req.version, cert_chain)
            if get_type(cert_chain_req) == PT.CERT_CHAIN_REQ_LOCAL:
                dst_addr = cert_chain_req.hdr.src_addr.host_addr
            else:
                for router in self.topology.child_edge_routers:
                    if (cert_chain_req.src_isd == router.interface.neighbor_isd
                        and
                        cert_chain_req.src_ad == router.interface.neighbor_ad):
                        dst_addr = router.addr
            self.send(cert_chain_rep, dst_addr)
            logging.info("Certificate chain reply sent.")

    def process_cert_chain_reply(self, cert_chain_rep):
        """
        Process a certificate chain reply.
        """
        assert isinstance(cert_chain_rep, CertChainReply)
        logging.info("Certificate chain reply received")
        cert_chain = cert_chain_rep.cert_chain
        self.cert_chains[(cert_chain_rep.isd_id, cert_chain_rep.ad_id,
                          cert_chain_rep.version)] = cert_chain
        cert_chain_file = get_cert_chain_file_path(self.topology.isd_id,
            self.topology.ad_id, cert_chain_rep.isd_id, cert_chain_rep.ad_id,
            cert_chain_rep.version)
        write_file(cert_chain_file, cert_chain.decode('utf-8'))
        try:
            tmp = CertificateChain(cert_chain_file)
            self.zk.store_shared_item(self.ZK_CERT_CHAIN_CACHE_PATH,
                                      tmp.certs[1].subject +
                                      "-V:" + str(tmp.certs[1].version),
                                      cert_chain)
        except ZkConnectionLoss:
            logging.debug("Unable to store cert chain in shared path: "
                          "no connection to ZK")
            return
        # Reply to all requests for this certificate chain
        for dst_addr in self.cert_chain_requests[(cert_chain_rep.isd_id,
            cert_chain_rep.ad_id, cert_chain_rep.version)]:
            new_cert_chain_rep = CertChainReply.from_values(self.addr,
                cert_chain_rep.isd_id, cert_chain_rep.ad_id,
                cert_chain_rep.version, cert_chain_rep.cert_chain)
            self.send(new_cert_chain_rep, dst_addr)
        del self.cert_chain_requests[(cert_chain_rep.isd_id,
            cert_chain_rep.ad_id, cert_chain_rep.version)]
        logging.info("Certificate chain reply sent.")

    def process_trc_request(self, trc_req):
        """
        Process a TRC request.
        """
        assert isinstance(trc_req, TRCRequest)
        logging.info("TRC request received")
        trc = self.trcs.get((trc_req.isd_id, trc_req.version))
        if not trc:
            # Try loading file from disk
            trc_file = get_trc_file_path(self.topology.isd_id,
                self.topology.ad_id, trc_req.isd_id, trc_req.version)
            if os.path.exists(trc_file):
                trc = read_file(trc_file).encode('utf-8')
                self.trcs[(trc_req.isd_id, trc_req.version)] = trc
        if not trc:
            # Requesting TRC file from parent's cert server
            logging.debug('TRC not found.')
            trc_tuple = (trc_req.isd_id, trc_req.version)
            self.trc_requests[trc_tuple].append(trc_req.hdr.src_addr.host_addr)
            new_trc_req = TRCRequest.from_values(PT.TRC_REQ, self.addr,
                trc_req.ingress_if, trc_req.src_isd, trc_req.src_ad,
                trc_req.isd_id, trc_req.version)
            dst_addr = self.ifid2addr[trc_req.ingress_if]
            self.send(new_trc_req, dst_addr)
            logging.info("New TRC request sent.")
        else:
            logging.debug('TRC found.')
            trc_rep = TRCReply.from_values(self.addr, trc_req.isd_id,
                trc_req.version, trc)
            if get_type(trc_req) == PT.TRC_REQ_LOCAL:
                dst_addr = trc_req.hdr.src_addr.host_addr
            else:
                for router in (self.topology.child_edge_routers +
                               self.topology.routing_edge_routers):
                    if (trc_req.src_isd == router.interface.neighbor_isd and
                        trc_req.src_ad == router.interface.neighbor_ad):
                        dst_addr = router.addr
                        break
            self.send(trc_rep, dst_addr)
            logging.info("TRC reply sent.")

    def process_trc_reply(self, trc_rep):
        """
        Process a TRC reply.
        """
        assert isinstance(trc_rep, TRCReply)
        logging.info("TRC reply received")
        trc = trc_rep.trc
        self.trcs[(trc_rep.isd_id, trc_rep.version)] = trc
        trc_file = get_trc_file_path(self.topology.isd_id, self.topology.ad_id,
            trc_rep.isd_id, trc_rep.version)
        write_file(trc_file, trc.decode('utf-8'))
        try:
            tmp = TRC(trc_file)
            self.zk.store_shared_item(self.ZK_TRC_CACHE_PATH,
                                      "ISD:" + str(tmp.isd_id) +
                                      "-V:" + str(tmp.version),
                                      trc)
        except ZkConnectionLoss:
            logging.debug("Unable to store TRC in shared path: "
                          "no connection to ZK")
            return
        # Reply to all requests for this TRC
        for dst_addr in self.trc_requests[(trc_rep.isd_id, trc_rep.version)]:
            new_trc_rep = TRCReply.from_values(self.addr, trc_rep.isd_id,
                trc_rep.version, trc_rep.trc)
            self.send(new_trc_rep, dst_addr)
        del self.trc_requests[(trc_rep.isd_id, trc_rep.version)]
        logging.info("TRC reply sent.")

    def _get_cert_chain_identifiers(self, entry):
        """
        Get the isd_id, ad_id, and version values from the entry name.
        """
        return parse('ISD:{:d}-AD:{:d}-V:{:d}', entry)

    def _get_trc_identifiers(self, entry):
        """
        Get the isd_id and version values from the entry name.
        """
        return parse('ISD:{:d}-V:{:d}', entry)

    @thread_safety_net("handle_shared_certs")
    def handle_shared_certs(self):
        """
        A thread to handle Zookeeper connects/disconnects and the shared cache
        of cert chains and TRCs.

        On connect, it registers us as in-service, and loads the shared cache
        of cert chains and TRCs from ZK, so that we have enough context should
        we become master.

        While connected, it calls _read_cached_cert_chains() to read updated
        cert chains from the cache. Afterwards, it calls _read_cached_trcs() to
        read updated TRCs from the cache.
        """
        while True:
            if not self.zk.is_connected():
                self._state_synced.clear()
                self.zk.wait_connected()
            else:
                time.sleep(0.5)
            try:
                if not self._state_synced.is_set():
                    # Register that we can now accept and store cert chains
                    self.zk.join_party()
                    # Make sure we re-read the entire cache
                    self._latest_entry = 0
                count = self._read_cached_cert_chains()
                if count:
                    logging.debug("Processed %d new/updated cert chains", count)
                count = self._read_cached_trcs()
                if count:
                    logging.debug("Processed %d new/updated TRCs", count)
            except ZkConnectionLoss:
                continue
            self._state_synced.set()

    def _read_cached_cert_chains(self):
        """
        Read new/updated entries from the shared cache and send them for
        processesing.
        """
        desc = "Fetching list of cert chains from shared cache"
        entries_meta = self.zk.get_shared_metadata(
            self.ZK_CERT_CHAIN_CACHE_PATH, timed_desc=desc)
        if not entries_meta:
            return 0
        new = []
        newest = 0
        for entry, meta in entries_meta:
            if meta.last_modified > self._latest_entry:
                new.append(entry)
            if meta.last_modified > newest:
                newest = meta.last_modified
        self._latest_entry = newest
        desc = "Processing %s new cert chains from shared path" % len(new)
        count = self._process_cached_cert_chains(new, timed_desc=desc)
        return count

    @timed(1.0)
    def _process_cached_cert_chains(self, entries):
        """
        Retrieve new cert chains from the shared cache and send them for local
        processing.
        """
        # TODO(lorenzo): move constant to proper place
        chunk_size = 10
        pcbs = []
        for i in range(0, len(entries), chunk_size):
            for entry in entries[i:i+chunk_size]:
                try:
                    raw = self.zk.get_shared_item(self.ZK_CERT_CHAIN_CACHE_PATH,
                                                  entry)
                except ZkConnectionLoss:
                    logging.warning("Unable to retrieve cert chain from shared "
                                    "cache: no connection to ZK")
                    break
                except ZkNoNodeError:
                    logging.debug("Unable to retrieve cert chain from shared "
                                  "cache: no such entry (%s/%s)" %
                                  (self.ZK_CERT_CHAIN_CACHE_PATH, entry))
                    continue
                isd_id, ad_id, version = self._get_cert_chain_identifiers(entry)
                self.cert_chains[(isd_id, ad_id, version)] = raw
                cert_chain_file = get_cert_chain_file_path(self.topology.isd_id,
                                                           self.topology.ad_id,
                                                           isd_id, ad_id,
                                                           version)
                write_file(cert_chain_file, raw.decode('utf-8'))
        return len(self.cert_chains)

    def _read_cached_trcs(self):
        """
        Read new/updated entries from the shared cache and send them for
        processesing.
        """
        desc = "Fetching list of TRCs from shared cache"
        entries_meta = self.zk.get_shared_metadata(self.ZK_TRC_CACHE_PATH,
                                                   timed_desc=desc)
        if not entries_meta:
            return 0
        new = []
        newest = 0
        for entry, meta in entries_meta:
            if meta.last_modified > self._latest_entry:
                new.append(entry)
            if meta.last_modified > newest:
                newest = meta.last_modified
        self._latest_entry = newest
        desc = "Processing %s new TRCs from shared path" % len(new)
        count = self._process_cached_trcs(new, timed_desc=desc)
        return count

    @timed(1.0)
    def _process_cached_trcs(self, entries):
        """
        Retrieve new TRCs from the shared cache and send them for local
        processing.
        """
        # TODO(lorenzo): move constant to proper place
        chunk_size = 10
        pcbs = []
        for i in range(0, len(entries), chunk_size):
            for entry in entries[i:i+chunk_size]:
                try:
                    raw = self.zk.get_shared_item(self.ZK_TRC_CACHE_PATH, entry)
                except ZkConnectionLoss:
                    logging.warning("Unable to retrieve TRC from shared cache: "
                                    "no connection to ZK")
                    break
                except ZkNoNodeError:
                    logging.debug("Unable to retrieve TRC from shared cache: "
                                  "no such entry (%s/%s)" %
                                  (self.ZK_TRC_CACHE_PATH, entry))
                    continue
                isd_id, version = self._get_trc_identifiers(entry)
                self.trcs[(isd_id, version)] = raw
                trc_file = get_trc_file_path(self.topology.isd_id,
                    self.topology.ad_id, isd_id, version)
                write_file(trc_file, raw.decode('utf-8'))
        return len(self.trcs)

    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.
        """
        spkt = SCIONPacket(packet)
        ptype = get_type(spkt)
        if ptype == PT.CERT_CHAIN_REQ_LOCAL or ptype == PT.CERT_CHAIN_REQ:
            self.process_cert_chain_request(CertChainRequest(packet))
        elif ptype == PT.CERT_CHAIN_REP:
            self.process_cert_chain_reply(CertChainReply(packet))
        elif ptype == PT.TRC_REQ_LOCAL or ptype == PT.TRC_REQ:
            self.process_trc_request(TRCRequest(packet))
        elif ptype == PT.TRC_REP:
            self.process_trc_reply(TRCReply(packet))
        else:
            logging.info("Type not supported")

    def run(self):
        """
        Run an instance of the Certificate Server.
        """
        threading.Thread(target=self.handle_shared_certs,
                         name="CS shared certs",
                         daemon=True).start()
        SCIONElement.run(self)

def main():
    """
    Main function.
    """
    init_logging()
    handle_signals()
    if len(sys.argv) != 5:
        logging.error("run: %s IP topo_file conf_file trc_file", sys.argv[0])
        sys.exit()

    cert_server = CertServer(IPv4Address(sys.argv[1]), sys.argv[2],
                             sys.argv[3], sys.argv[4])

    logging.info("Started: %s", datetime.datetime.now())
    cert_server.run()

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        logging.info("Exiting")
        raise
    except:
        log_exception("Exception in main process:")
        logging.critical("Exiting")
        sys.exit(1)
