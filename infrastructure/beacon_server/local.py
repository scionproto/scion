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
:mod:`local` --- Local beacon server
====================================
"""
# Stdlib
import logging

# SCION
from infrastructure.beacon_server.base import BeaconServer
from lib.defines import PATH_SERVICE, SIBRA_SERVICE
from lib.errors import SCIONParseError, SCIONServiceLookupError
from lib.msg_meta import UDPMetadata
from lib.packet.path_mgmt.seg_recs import PathRecordsReg
from lib.packet.pcb import PathSegment
from lib.packet.svc import SVCType
from lib.path_store import PathStore
from lib.types import PathSegmentType as PST


class LocalBeaconServer(BeaconServer):
    """
    PathConstructionBeacon Server in a non-core AS.

    Receives, processes, and propagates beacons received by other beacon
    servers.
    """

    def __init__(self, server_id, conf_dir):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        """
        super().__init__(server_id, conf_dir)
        # Sanity check that we should indeed be a local beacon server.
        assert not self.topology.is_core_as, "This shouldn't be a core BS!"
        self.beacons = PathStore(self.path_policy)
        self.up_segments = PathStore(self.path_policy)
        self.down_segments = PathStore(self.path_policy)
        self.cert_chain_requests = {}
        self.cert_chains = {}
        self.cert_chain = self.trust_store.get_cert(self.addr.isd_as)
        assert self.cert_chain

    def _check_trc(self, isd_as, trc_ver):
        """
        Return True or False whether the necessary Certificate and TRC files are
        found.

        :param ISD_AS isd_as: ISD-AS identifier.
        :param int trc_ver: TRC file version.
        :returns: True if the files exist, False otherwise.
        :rtype: bool
        """
        if self._get_trc(isd_as, trc_ver):
            return True
        return False

    def register_up_segment(self, pcb):
        """
        Send up-segment to Local Path Servers and Sibra Servers

        :raises:
            SCIONServiceLookupError: path server lookup failure
        """
        records = PathRecordsReg.from_values({PST.UP: [pcb]})
        addr, port = self.dns_query_topo(PATH_SERVICE)[0]
        meta = UDPMetadata.from_values(host=addr, port=port)
        self.send_meta(records.copy(), meta)
        addr, port = self.dns_query_topo(SIBRA_SERVICE)[0]
        meta = UDPMetadata.from_values(host=addr, port=port)
        self.send_meta(records, meta)

    def register_down_segment(self, pcb):
        """
        Send down-segment to Core Path Server
        """
        core_path = pcb.get_path(reverse_direction=True)
        records = PathRecordsReg.from_values({PST.DOWN: [pcb]})
        dst_ia = pcb.asm(0).isd_as()
        meta = UDPMetadata.from_values(
            ia=dst_ia, host=SVCType.PS_A, path=core_path)
        self.send_meta(records, meta)

    def register_segments(self):
        """
        Register paths according to the received beacons.
        """
        self.register_up_segments()
        self.register_down_segments()

    def process_pcbs(self, pcbs, raw=True):
        """
        Process new beacons and appends them to beacon list.
        """
        for pcb in pcbs:
            if raw:
                try:
                    pcb = PathSegment.from_raw(pcb)
                except SCIONParseError as e:
                    logging.error("Unable to parse raw pcb: %s", e)
                    continue
            if self.path_policy.check_filters(pcb):
                self._try_to_verify_beacon(pcb)
                self.handle_ext(pcb)

    def process_cert_chain_rep(self, rep, meta):
        """
        Process the Certificate chain reply.

        :param rep: certificate chain reply.
        :type rep: CertChainReply
        """
        logging.info("Certificate chain reply received for %s",
                     rep.short_desc())
        rep_key = rep.cert_chain.get_leaf_isd_as_ver()
        self.trust_store.add_cert(rep.cert_chain)
        if rep_key in self.cert_chain_requests:
            del self.cert_chain_requests[rep_key]

    def _remove_revoked_pcbs(self, rev_info):
        candidates = (self.down_segments.candidates +
                      self.up_segments.candidates +
                      self.beacons.candidates)
        to_remove = self._pcb_list_to_remove(candidates, rev_info)
        # Remove the affected segments from the path stores.
        self.beacons.remove_segments(to_remove)
        self.up_segments.remove_segments(to_remove)
        self.down_segments.remove_segments(to_remove)

    def _handle_verified_beacon(self, pcb):
        """
        Once a beacon has been verified, place it into the right containers.
        """
        self.beacons.add_segment(pcb)
        self.up_segments.add_segment(pcb)
        self.down_segments.add_segment(pcb)

    def handle_pcbs_propagation(self):
        """
        Main loop to propagate received beacons.
        """
        # TODO: define function that dispatches the pcbs among the interfaces
        best_segments = self.beacons.get_best_segments()
        for pcb in best_segments:
            self.propagate_downstream_pcb(pcb)

    def register_up_segments(self):
        """
        Register the paths to the core.
        """
        best_segments = self.up_segments.get_best_segments(sending=False)
        for pcb in best_segments:
            pcb = self._terminate_pcb(pcb)
            if not pcb:
                continue
            pcb.remove_crypto()
            pcb.sign(self.signing_key)
            try:
                self.register_up_segment(pcb)
            except SCIONServiceLookupError as e:
                logging.warning("Unable to send up path registration: %s", e)
                continue
            logging.info("Up path registered: %s", pcb.short_desc())

    def register_down_segments(self):
        """
        Register the paths from the core.
        """
        best_segments = self.down_segments.get_best_segments(sending=False)
        for pcb in best_segments:
            pcb = self._terminate_pcb(pcb)
            if not pcb:
                continue
            pcb.remove_crypto()
            pcb.sign(self.signing_key)
            self.register_down_segment(pcb)
            logging.info("Down path registered: %s", pcb.short_desc())
