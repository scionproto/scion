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
import collections
import datetime
import logging
import os
import re
import sys
import threading
import time

# SCION
from infrastructure.scion_elem import SCIONElement
from lib.crypto.certificate import CertificateChain, TRC
from lib.defines import SCION_UDP_PORT
from lib.log import init_logging, log_exception
from lib.packet.scion import (
    CertChainReply,
    CertChainRequest,
    PacketType as PT,
    SCIONPacket,
    TRCReply,
    TRCRequest,
    get_type,
)
from lib.thread import thread_safety_net
from lib.util import (
    get_cert_chain_file_path,
    get_trc_file_path,
    handle_signals,
    read_file,
    timed,
    write_file,
)
from lib.zookeeper import ZkConnectionLoss, ZkNoNodeError, Zookeeper


class CertServer(SCIONElement):
    """
    The SCION Certificate Server.
    """
    # ZK path for incoming cert chains
    ZK_CERT_CHAIN_CACHE_PATH = "cert_chain_cache"
    # ZK path for incoming TRCs
    ZK_TRC_CACHE_PATH = "trc_cache"

    def __init__(self, server_id, topo_file, config_file, trc_file,
                 is_sim=False):
        """
        Initialize an instance of the class CertServer.

        :param server_id: server identifier.
        :type server_id: int
        :param topo_file: topology file.
        :type topo_file: string
        :param config_file: configuration file.
        :type config_file: string
        :param trc_file: TRC file.
        :type trc_file: string
        :param is_sim: running in simulator
        :type is_sim: bool
        """
        SCIONElement.__init__(self, "cs", topo_file, server_id=server_id,
                              config_file=config_file, is_sim=is_sim)
        self.trc = TRC(trc_file)
        self.cert_chain_requests = collections.defaultdict(list)
        self.trc_requests = collections.defaultdict(list)
        self.cert_chains = {}
        self.trcs = {}
        self._latest_entry_cert_chains = 0
        self._latest_entry_trcs = 0

        if not is_sim:
            # Add more IPs here if we support dual-stack
            name_addrs = "\0".join([self.id, str(SCION_UDP_PORT),
                                    str(self.addr.host_addr)])
            # Set when we have connected and read the existing recent and
            # incoming cert chains and TRCs
            self._state_synced = threading.Event()
            # TODO(lorenzo): def zookeeper host/port in topology
            self.zk = Zookeeper(self.topology.isd_id, self.topology.ad_id,
                                "cs", name_addrs, ["localhost:2181"],
                                ensure_paths=(self.ZK_CERT_CHAIN_CACHE_PATH,
                                              self.ZK_TRC_CACHE_PATH,))

    def _store_cert_chain_in_zk(self, cert_chain_file, cert_chain):
        """
        Store the Certificate Chain in the zookeeper.

        :param cert_chain_file: certificate chain file.
        :type cert_chain_file: string
        :param cert_chain: certificate chain.
        :type cert_chain: CertificateChain
        """
        try:
            tmp = CertificateChain(cert_chain_file)
            self.zk.store_shared_item(self.ZK_CERT_CHAIN_CACHE_PATH,
                                      tmp.certs[0].subject +
                                      "-V:" + str(tmp.certs[0].version),
                                      cert_chain)
        except ZkConnectionLoss:
            logging.debug("Unable to store cert chain in shared path: "
                          "no connection to ZK")
            return

    def process_cert_chain_request(self, cert_chain_req):
        """
        Process a certificate chain request.

        :param cert_chain_req: certificate chain request.
        :type cert_chain_req: CertChainRequest
        """
        assert isinstance(cert_chain_req, CertChainRequest)
        logging.info("Certificate chain request received.")
        cert_chain = self.cert_chains.get((cert_chain_req.isd_id,
                                           cert_chain_req.ad_id,
                                           cert_chain_req.version))
        if not cert_chain:
            # Try loading file from disk
            cert_chain_file = get_cert_chain_file_path(
                self.topology.isd_id, self.topology.ad_id,
                cert_chain_req.isd_id, cert_chain_req.ad_id,
                cert_chain_req.version)
            if os.path.exists(cert_chain_file):
                cert_chain = read_file(cert_chain_file).encode('utf-8')
                self.cert_chains[(cert_chain_req.isd_id, cert_chain_req.ad_id,
                                  cert_chain_req.version)] = cert_chain
                self._store_cert_chain_in_zk(cert_chain_file, cert_chain)
        if not cert_chain:
            # Requesting certificate chain file from parent's cert server
            logging.debug('Certificate chain not found.')
            cert_chain_tuple = (cert_chain_req.isd_id, cert_chain_req.ad_id,
                                cert_chain_req.version)
            self.cert_chain_requests[cert_chain_tuple].append(
                cert_chain_req.hdr.src_addr.host_addr)
            new_cert_chain_req = CertChainRequest.from_values(
                PT.CERT_CHAIN_REQ, self.addr, cert_chain_req.ingress_if,
                cert_chain_req.src_isd, cert_chain_req.src_ad,
                cert_chain_req.isd_id, cert_chain_req.ad_id,
                cert_chain_req.version)
            dst_addr = self.ifid2addr[cert_chain_req.ingress_if]
            self.send(new_cert_chain_req, dst_addr)
            logging.info("New certificate chain request sent.")
        else:
            logging.debug('Certificate chain found.')
            cert_chain_rep = CertChainReply.from_values(
                self.addr, cert_chain_req.isd_id, cert_chain_req.ad_id,
                cert_chain_req.version, cert_chain)
            if get_type(cert_chain_req) == PT.CERT_CHAIN_REQ_LOCAL:
                dst_addr = cert_chain_req.hdr.src_addr.host_addr
            else:
                for router in self.topology.child_edge_routers:
                    if (cert_chain_req.src_isd ==
                            router.interface.neighbor_isd) and (
                            cert_chain_req.src_ad ==
                            router.interface.neighbor_ad):
                        dst_addr = router.addr
            self.send(cert_chain_rep, dst_addr)
            logging.info("Certificate chain reply sent.")

    def process_cert_chain_reply(self, cert_chain_rep):
        """
        Process a certificate chain reply.

        :param cert_chain_rep: certificate chain reply.
        :type cert_chain_rep: CertChainReply
        """
        assert isinstance(cert_chain_rep, CertChainReply)
        logging.info("Certificate chain reply received")
        cert_chain = cert_chain_rep.cert_chain
        self.cert_chains[(cert_chain_rep.isd_id, cert_chain_rep.ad_id,
                          cert_chain_rep.version)] = cert_chain
        cert_chain_file = get_cert_chain_file_path(
            self.topology.isd_id, self.topology.ad_id, cert_chain_rep.isd_id,
            cert_chain_rep.ad_id, cert_chain_rep.version)
        write_file(cert_chain_file, cert_chain.decode('utf-8'))
        self._store_cert_chain_in_zk(cert_chain_file, cert_chain)
        # Reply to all requests for this certificate chain
        for dst_addr in self.cert_chain_requests[
                (cert_chain_rep.isd_id, cert_chain_rep.ad_id,
                 cert_chain_rep.version)]:
            new_cert_chain_rep = CertChainReply.from_values(
                self.addr, cert_chain_rep.isd_id, cert_chain_rep.ad_id,
                cert_chain_rep.version, cert_chain_rep.cert_chain)
            self.send(new_cert_chain_rep, dst_addr)
        del self.cert_chain_requests[
            (cert_chain_rep.isd_id,
             cert_chain_rep.ad_id,
             cert_chain_rep.version)]
        logging.info("Certificate chain reply sent.")

    def _store_trc_in_zk(self, trc_file, trc):
        """
        Store the TRC in the zookeeper.

        :param trc_file: TRC file.
        :type trc_file: string.
        :param trc: TRC.
        :type trc: TRC.
        """
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

    def process_trc_request(self, trc_req):
        """
        Process a TRC request.

        :param trc_req: TRC request.
        :type trc_req: TRCRequest.
        """
        assert isinstance(trc_req, TRCRequest)
        logging.info("TRC request received")
        trc = self.trcs.get((trc_req.isd_id, trc_req.version))
        if not trc:
            # Try loading file from disk
            trc_file = get_trc_file_path(
                self.topology.isd_id, self.topology.ad_id,
                trc_req.isd_id, trc_req.version)
            if os.path.exists(trc_file):
                trc = read_file(trc_file).encode('utf-8')
                self.trcs[(trc_req.isd_id, trc_req.version)] = trc
                self._store_trc_in_zk(trc_file, trc)
        if not trc:
            # Requesting TRC file from parent's cert server
            logging.debug('TRC not found.')
            trc_tuple = (trc_req.isd_id, trc_req.version)
            self.trc_requests[trc_tuple].append(trc_req.hdr.src_addr.host_addr)
            new_trc_req = TRCRequest.from_values(
                PT.TRC_REQ, self.addr, trc_req.ingress_if,
                trc_req.src_isd, trc_req.src_ad, trc_req.isd_id,
                trc_req.version)
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

        :param trc_rep: TRC reply.
        :type trc_rep: TRCReply
        """
        assert isinstance(trc_rep, TRCReply)
        logging.info("TRC reply received")
        trc = trc_rep.trc
        self.trcs[(trc_rep.isd_id, trc_rep.version)] = trc
        trc_file = get_trc_file_path(
            self.topology.isd_id, self.topology.ad_id,
            trc_rep.isd_id, trc_rep.version)
        write_file(trc_file, trc.decode('utf-8'))
        self._store_trc_in_zk(trc_file, trc)
        # Reply to all requests for this TRC
        for dst_addr in self.trc_requests[(trc_rep.isd_id, trc_rep.version)]:
            new_trc_rep = TRCReply.from_values(
                self.addr, trc_rep.isd_id,
                trc_rep.version, trc_rep.trc)
            self.send(new_trc_rep, dst_addr)
        del self.trc_requests[(trc_rep.isd_id, trc_rep.version)]
        logging.info("TRC reply sent.")

    def _get_cert_chain_identifiers(self, entry):
        """
        Get the isd_id, ad_id, and version values from the entry name.

        :param entry: certificate chain full name.
        :type entry: string

        :returns: certificate chain identifiers.
        :rtype: tuple
        """
        identifiers = re.split(':|-', entry)
        return (int(identifiers[1]), int(identifiers[3]), int(identifiers[5]))

    def _get_trc_identifiers(self, entry):
        """
        Get the isd_id and version values from the entry name.

        :param entry: TRC full name
        :type entry: string

        :returns: TRC identifiers.
        :rtype: tuple
        """
        identifiers = re.split(':|-', entry)
        return (int(identifiers[1]), int(identifiers[3]))

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
                    self._latest_entry_cert_chains = 0
                    self._latest_entry_trcs = 0
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

        :returns: number of processed cached certificate chains.
        :rtype: int
        """
        desc = "Fetching list of cert chains from shared cache"
        entries_meta = self.zk.get_shared_metadata(
            self.ZK_CERT_CHAIN_CACHE_PATH, timed_desc=desc)
        if not entries_meta:
            return 0
        new = []
        newest = 0
        for entry, meta in entries_meta:
            if meta.last_modified > self._latest_entry_cert_chains:
                new.append(entry)
            if meta.last_modified > newest:
                newest = meta.last_modified
        self._latest_entry_cert_chains = newest
        desc = "Processing %s new cert chains from shared path" % len(new)
        count = self._process_cached_cert_chains(new, timed_desc=desc)
        return count

    @timed(1.0)
    def _process_cached_cert_chains(self, entries):
        """
        Retrieve new cert chains from the shared cache and send them for local
        processing.

        :param entries: certificate chains.
        :type entries: bytes

        :returns: number of processed certificate chains.
        :rtype: int
        """
        # TODO(lorenzo): move constant to proper place
        chunk_size = 10
        processed = 0
        for i in range(0, len(entries), chunk_size):
            for entry in entries[i:i+chunk_size]:
                isd_id, ad_id, version = self._get_cert_chain_identifiers(entry)
                cert_chain_file = get_cert_chain_file_path(self.topology.isd_id,
                                                           self.topology.ad_id,
                                                           isd_id, ad_id,
                                                           version)
                if not os.path.exists(cert_chain_file):
                    continue
                cert_chain = read_file(cert_chain_file).encode('utf-8')
                self._store_cert_chain_in_zk(cert_chain_file, cert_chain)
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
                self.cert_chains[(isd_id, ad_id, version)] = raw
                processed += 1
        return processed

    def _read_cached_trcs(self):
        """
        Read new/updated entries from the shared cache and send them for
        processesing.

        :returns: number of processed cached TRCs.
        :rtype: int
        """
        desc = "Fetching list of TRCs from shared cache"
        entries_meta = self.zk.get_shared_metadata(self.ZK_TRC_CACHE_PATH,
                                                   timed_desc=desc)
        if not entries_meta:
            return 0
        new = []
        newest = 0
        for entry, meta in entries_meta:
            if meta.last_modified > self._latest_entry_trcs:
                new.append(entry)
            if meta.last_modified > newest:
                newest = meta.last_modified
        self._latest_entry_trcs = newest
        desc = "Processing %s new TRCs from shared path" % len(new)
        count = self._process_cached_trcs(new, timed_desc=desc)
        return count

    @timed(1.0)
    def _process_cached_trcs(self, entries):
        """
        Retrieve new TRCs from the shared cache and send them for local
        processing.

        :param entries: TRCs.
        :type entries: bytes

        :returns: number of processed cached TRCs.
        :rtype: int
        """
        # TODO(lorenzo): move constant to proper place
        chunk_size = 10
        processed = 0
        for i in range(0, len(entries), chunk_size):
            for entry in entries[i:i+chunk_size]:
                isd_id, version = self._get_trc_identifiers(entry)
                trc_file = get_trc_file_path(self.topology.isd_id,
                                             self.topology.ad_id,
                                             isd_id, version)
                if not os.path.exists(trc_file):
                    continue
                trc = read_file(trc_file).encode('utf-8')
                self._store_trc_in_zk(trc_file, trc)
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
                self.trcs[(isd_id, version)] = raw
                processed += 1
        return processed

    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.

        :param packet: incoming packet.
        :type packet: bytes
        :param sender:
        :type sender:
        :param from_local_socket:
        :type from_local_socket:
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
        threading.Thread(
            target=thread_safety_net,
            args=("handle_shared_certs", self.handle_shared_certs),
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
        logging.error("run: %s server_id topo_file conf_file trc_file",
                      sys.argv[0])
        sys.exit()

    cert_server = CertServer(*sys.argv[1:])

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
