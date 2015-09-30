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
import argparse
import collections
import datetime
import logging
import os
import re
import sys

# SCION
from infrastructure.scion_elem import SCIONElement
from lib.crypto.certificate import TRC
from lib.defines import CERTIFICATE_SERVICE, SCION_UDP_PORT
from lib.errors import SCIONBaseError
from lib.log import init_logging, log_exception
from lib.packet.cert_mgmt import (
    CertMgmtType,
    CertChainReply,
    CertChainRequest,
    TRCReply,
    TRCRequest,
)
from lib.packet.packet_base import PayloadClass
from lib.packet.scion import (
    PacketType as PT,
    SCIONL4Packet,
)
from lib.util import (
    get_cert_chain_file_path,
    get_trc_file_path,
    handle_signals,
    read_file,
    write_file,
)
from lib.zookeeper import Zookeeper


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
        super().__init__(CERTIFICATE_SERVICE, topo_file, server_id=server_id,
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
            self.zk = Zookeeper(self.topology.isd_id, self.topology.ad_id,
                                CERTIFICATE_SERVICE, name_addrs,
                                self.topology.zookeepers)
            self.zk.retry("Joining party", self.zk.party_setup)

    def process_cert_chain_request(self, pkt):
        """
        Process a certificate chain request.

        :param cert_chain_req: certificate chain request.
        :type cert_chain_req: CertChainRequest
        """
        cert_chain_req = pkt.get_payload()
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
        if not cert_chain:
            # Requesting certificate chain file from parent's cert server
            logging.debug('Certificate chain not found.')
            cert_chain_tuple = (cert_chain_req.isd_id, cert_chain_req.ad_id,
                                cert_chain_req.version)
            self.cert_chain_requests[cert_chain_tuple].append(
                pkt.addrs.src_addr)
            new_cert_chain_req = CertChainRequest.from_values(
                cert_chain_req.ingress_if, cert_chain_req.src_isd,
                cert_chain_req.src_ad, cert_chain_req.isd_id,
                cert_chain_req.ad_id, cert_chain_req.version)
            req_pkt = self._build_packet(PT.CERT_MGMT,
                                         payload=new_cert_chain_req)
            dst_addr = self.ifid2addr.get(cert_chain_req.ingress_if)
            if dst_addr:
                self.send(req_pkt, dst_addr)
                logging.info("New certificate chain request sent.")
            else:
                logging.warning("Certificate chain request not sent: "
                                "no destination found")
        else:
            logging.debug('Certificate chain found.')
            dst_addr = None
            cert_chain_rep = CertChainReply.from_values(
                cert_chain_req.isd_id, cert_chain_req.ad_id,
                cert_chain_req.version, cert_chain)
            if cert_chain_req.local:
                dst_addr = pkt.addrs.src_addr
            else:
                for router in self.topology.child_edge_routers:
                    if (cert_chain_req.src_isd ==
                            router.interface.neighbor_isd) and (
                            cert_chain_req.src_ad ==
                            router.interface.neighbor_ad):
                        dst_addr = router.addr
            if dst_addr:
                rep_pkt = self._build_packet(dst_addr, payload=cert_chain_rep)
                self.send(rep_pkt, dst_addr)
                logging.info("Certificate chain reply sent.")
            else:
                logging.warning("Certificate chain reply not sent: "
                                "no destination found")

    def process_cert_chain_reply(self, pkt):
        """
        Process a certificate chain reply.

        :param cert_chain_rep: certificate chain reply.
        :type cert_chain_rep: CertChainReply
        """
        cert_chain_rep = pkt.get_payload()
        assert isinstance(cert_chain_rep, CertChainReply)
        logging.info("Certificate chain reply received")
        cert_chain = cert_chain_rep.cert_chain
        self.cert_chains[(cert_chain_rep.isd_id, cert_chain_rep.ad_id,
                          cert_chain_rep.version)] = cert_chain
        cert_chain_file = get_cert_chain_file_path(
            self.topology.isd_id, self.topology.ad_id, cert_chain_rep.isd_id,
            cert_chain_rep.ad_id, cert_chain_rep.version)
        write_file(cert_chain_file, cert_chain.decode('utf-8'))
        # Reply to all requests for this certificate chain
        for dst_addr in self.cert_chain_requests[
                (cert_chain_rep.isd_id, cert_chain_rep.ad_id,
                 cert_chain_rep.version)]:
            new_cert_chain_rep = CertChainReply.from_values(
                cert_chain_rep.isd_id, cert_chain_rep.ad_id,
                cert_chain_rep.version, cert_chain_rep.cert_chain)
            rep_pkt = self._build_packet(dst_addr, payload=new_cert_chain_rep)
            self.send(rep_pkt, dst_addr)
        del self.cert_chain_requests[
            (cert_chain_rep.isd_id,
             cert_chain_rep.ad_id,
             cert_chain_rep.version)]
        logging.info("Certificate chain reply sent.")

    def process_trc_request(self, pkt):
        """
        Process a TRC request.

        :param trc_req: TRC request.
        :type trc_req: TRCRequest.
        """
        trc_req = pkt.get_payload()
        assert isinstance(trc_req, TRCRequest)
        logging.info("TRC request received for ISD %d", trc_req.isd_id)
        trc = self.trcs.get((trc_req.isd_id, trc_req.version))
        if not trc:
            # Try loading file from disk
            trc_file = get_trc_file_path(
                self.topology.isd_id, self.topology.ad_id,
                trc_req.isd_id, trc_req.version)
            if os.path.exists(trc_file):
                trc = read_file(trc_file).encode('utf-8')
                self.trcs[(trc_req.isd_id, trc_req.version)] = trc
        if not trc:
            # Requesting TRC file from parent's cert server
            logging.debug('TRC not found for ISD %d.', trc_req.isd_id)
            trc_tuple = (trc_req.isd_id, trc_req.version)
            self.trc_requests[trc_tuple].append(pkt.addrs.src_addr)
            new_trc_req = TRCRequest.from_values(
                trc_req.ingress_if, trc_req.src_isd, trc_req.src_ad,
                trc_req.isd_id, trc_req.version, local=False)
            req_pkt = self._build_packet(PT.CERT_MGMT, payload=new_trc_req)
            dst_addr = self.ifid2addr.get(trc_req.ingress_if)
            if dst_addr:
                self.send(req_pkt, dst_addr)
                logging.info("New TRC request sent for ISD %d.", trc_req.isd_id)
            else:
                logging.warning("TRC request not sent for ISD %d: "
                                "no destination found.", trc_req.isd_id)
        else:
            logging.debug('TRC found for ISD %d.', trc_req.isd_id)
            trc_rep = TRCReply.from_values(trc_req.isd_id, trc_req.version, trc)
            next_hop = None
            if trc_req.local:
                next_hop = pkt.addrs.src_addr
            else:
                for router in (self.topology.child_edge_routers +
                               self.topology.routing_edge_routers):
                    if (trc_req.src_isd == router.interface.neighbor_isd and
                            trc_req.src_ad == router.interface.neighbor_ad):
                        next_hop = router.addr
                        break
            if next_hop:
                # FIXME(kormat): this only works when there's one CS in an ad.
                # https://github.com/netsec-ethz/scion/issues/389 is needed for
                # when there's more.
                rep_pkt = self._build_packet(
                    PT.CERT_MGMT, dst_isd=trc_req.src_isd,
                    dst_ad=trc_req.src_ad, payload=trc_rep)
                self.send(rep_pkt, next_hop)
                logging.info("TRC reply sent to (%d, %d)", trc_req.src_isd,
                             trc_req.src_ad)
            else:
                logging.warning("TRC reply not sent: no destination found")

    def process_trc_reply(self, pkt):
        """
        Process a TRC reply.

        :param trc_rep: TRC reply.
        :type trc_rep: TRCReply
        """
        trc_rep = pkt.get_payload()
        assert isinstance(trc_rep, TRCReply)
        logging.info("TRC reply received for ISD %d", trc_rep.isd_id)
        trc = trc_rep.trc
        self.trcs[(trc_rep.isd_id, trc_rep.version)] = trc
        trc_file = get_trc_file_path(
            self.topology.isd_id, self.topology.ad_id,
            trc_rep.isd_id, trc_rep.version)
        write_file(trc_file, trc.decode('utf-8'))
        count = 0
        # Reply to all requests for this TRC
        for dst_addr in self.trc_requests[(trc_rep.isd_id, trc_rep.version)]:
            new_trc_rep = TRCReply.from_values(trc_rep.isd_id, trc_rep.version,
                                               trc_rep.trc)
            rep_pkt = self._build_packet(dst_addr, payload=new_trc_rep)
            self.send(rep_pkt, dst_addr)
            count += 1
        del self.trc_requests[(trc_rep.isd_id, trc_rep.version)]
        logging.info("TRC replies (%d) sent for ISD %d.", count, trc_rep.isd_id)

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
        type_map = {
            CertMgmtType.CERT_CHAIN_REQ: self.process_cert_chain_request,
            CertMgmtType.CERT_CHAIN_REPLY: self.process_cert_chain_reply,
            CertMgmtType.TRC_REQ: self.process_trc_request,
            CertMgmtType.TRC_REPLY: self.process_trc_reply,
        }
        pkt = SCIONL4Packet(packet)
        pld = pkt.parse_payload()
        if pld.PAYLOAD_CLASS != PayloadClass.CERT:
            logging.error("Payload class not supported: %s", pld.PAYLOAD_CLASS)
            return
        handler = type_map.get(pld.PAYLOAD_TYPE)
        if handler is None:
            logging.error("CertMgmt type not supported: %s", pld.PAYLOAD_TYPE)
            return
        try:
            handler(pkt)
        except SCIONBaseError:
            log_exception("Error handling packet: %s" % pkt)


def main():
    """
    Main function.
    """
    handle_signals()
    parser = argparse.ArgumentParser()
    parser.add_argument('server_id', help='Server identifier')
    parser.add_argument('topo_file', help='Topology file')
    parser.add_argument('conf_file', help='AD configuration file')
    parser.add_argument('trc_file', help='TRC file')
    parser.add_argument('log_file', help='Log file')
    args = parser.parse_args()
    init_logging(args.log_file)

    cert_server = CertServer(args.server_id, args.topo_file, args.conf_file,
                             args.trc_file)

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
