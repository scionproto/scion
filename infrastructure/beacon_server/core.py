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
:mod:`core` --- Core beacon server
==================================
"""
# Stdlib
import copy
import logging
from _collections import defaultdict

# SCION
from infrastructure.beacon_server.base import BeaconServer
from lib.defines import PATH_SERVICE
from lib.errors import SCIONParseError, SCIONServiceLookupError
from lib.packet.opaque_field import InfoOpaqueField
from lib.packet.path_mgmt import PathRecordsReg
from lib.packet.pcb import PathSegment
from lib.packet.scion import PacketType as PT
from lib.path_store import PathStore
from lib.types import OpaqueFieldType as OFT, PathSegmentType as PST
from lib.util import SCIONTime


class CoreBeaconServer(BeaconServer):
    """
    PathConstructionBeacon Server in a core AS.

    Starts broadcasting beacons down-stream within an ISD and across ISDs
    towards other core beacon servers.
    """
    def __init__(self, server_id, conf_dir, is_sim=False):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param bool is_sim: running on simulator
        """
        super().__init__(server_id, conf_dir, is_sim=is_sim)
        # Sanity check that we should indeed be a core beacon server.
        assert self.topology.is_core_as, "This shouldn't be a local BS!"
        self.core_beacons = defaultdict(self._ps_factory)

    def _ps_factory(self):
        """

        :returns:
        :rtype:
        """
        return PathStore(self.path_policy)

    def propagate_core_pcb(self, pcb):
        """
        Propagates the core beacons to other core ASes.
        """
        assert isinstance(pcb, PathSegment)
        ingress_if = pcb.if_id
        count = 0
        for core_router in self.topology.routing_edge_routers:
            skip = False
            for asm in pcb.ases:
                if asm.pcbm.isd_as == core_router.interface.isd_as:
                    # Don't propagate a Core PCB back to an AS we know has
                    # already seen it.
                    skip = True
                    break
            if skip:
                continue
            new_pcb = copy.deepcopy(pcb)
            egress_if = core_router.interface.if_id
            last_pcbm = new_pcb.get_last_pcbm()
            if last_pcbm:
                as_marking = self._create_as_marking(ingress_if, egress_if,
                                                     new_pcb.get_timestamp(),
                                                     last_pcbm.hof)
            else:
                as_marking = self._create_as_marking(ingress_if, egress_if,
                                                     new_pcb.get_timestamp())

            new_pcb.add_as(as_marking)
            self._sign_beacon(new_pcb)
            beacon = self._build_packet(PT.BEACON, payload=new_pcb)
            self.send(beacon, core_router.addr)
            count += 1
        return count

    def handle_pcbs_propagation(self):
        """
        Generate a new beacon or gets ready to forward the one received.
        """
        timestamp = int(SCIONTime.get_time())
        # Create beacon for downstream ASes.
        down_iof = InfoOpaqueField.from_values(
            OFT.CORE, False, timestamp, self.topology.isd_as[0])
        downstream_pcb = PathSegment.from_values(down_iof)
        self.propagate_downstream_pcb(downstream_pcb)
        # Create beacon for core ASes.
        core_iof = InfoOpaqueField.from_values(
            OFT.CORE, False, timestamp, self.topology.isd_as[0])
        core_pcb = PathSegment.from_values(core_iof)
        core_count = self.propagate_core_pcb(core_pcb)
        # Propagate received beacons. A core beacon server can only receive
        # beacons from other core beacon servers.
        beacons = []
        for ps in self.core_beacons.values():
            beacons.extend(ps.get_best_segments())
        for pcb in beacons:
            core_count += self.propagate_core_pcb(pcb)
        if core_count:
            logging.info("Propagated %d Core PCBs", core_count)

    def register_segments(self):
        """

        """
        self.register_core_segments()

    def register_core_segment(self, pcb):
        """
        Register the core segment contained in 'pcb' with the local core path
        server.
        """
        pcb.remove_signatures()
        self._sign_beacon(pcb)
        # Register core path with local core path server.
        try:
            ps_addr = self.dns_query_topo(PATH_SERVICE)[0]
        except SCIONServiceLookupError:
            # If there are no local path servers, stop here.
            return
        records = PathRecordsReg.from_values({PST.CORE: [pcb]})
        pkt = self._build_packet(ps_addr, payload=records)
        self.send(pkt, ps_addr)

    def process_pcbs(self, pcbs, raw=True):
        """
        Process new beacons and appends them to beacon list.
        """
        count = 0
        for pcb in pcbs:
            if raw:
                try:
                    pcb = PathSegment(pcb)
                except SCIONParseError as e:
                    logging.error("Unable to parse raw pcb: %s", e)
                    continue
            # Before we append the PCB for further processing we need to check
            # that it hasn't been received before.
            for asm in pcb.ases:
                if asm.pcbm.isd_as == self.topology.isd_as:
                    count += 1
                    break
            else:
                self._try_to_verify_beacon(pcb)
                self.handle_ext(pcb)
        if count:
            logging.debug("Dropped %d previously seen Core Segment PCBs", count)

    def _check_certs_trc(self, isd_as, cert_ver, trc_ver):
        """
        Return True or False whether the necessary TRC file is found.

        :param ISD_AS isd_as: ISD-AS identifier.
        :param int cert_ver: certificate chain file version.
        :param int trc_ver: TRC file version.
        :returns: True if the files exist, False otherwise.
        :rtype: bool
        """
        return bool(self._get_trc(isd_as, trc_ver))

    def process_cert_chain_rep(self, cert_chain_rep):
        raise NotImplementedError

    def _handle_verified_beacon(self, pcb):
        """
        Once a beacon has been verified, place it into the right containers.

        :param pcb: verified path segment.
        :type pcb: PathSegment
        """
        isd_as = pcb.get_first_pcbm().isd_as
        self.core_beacons[isd_as].add_segment(pcb)

    def register_core_segments(self):
        """
        Register the core segment between core ASes.
        """
        core_segments = []
        for ps in self.core_beacons.values():
            core_segments.extend(ps.get_best_segments(sending=False))
        count = 0
        for pcb in core_segments:
            pcb = self._terminate_pcb(pcb)
            self._sign_beacon(pcb)
            self.register_core_segment(pcb)
            count += 1
        logging.info("Registered %d Core paths", count)

    def _remove_revoked_pcbs(self, rev_info, if_id):
        candidates = []
        for ps in self.core_beacons.values():
            candidates += ps.candidates
        to_remove = self._pcb_list_to_remove(candidates, rev_info, if_id)
        # Remove the affected segments from the path stores.
        for ps in self.core_beacons.values():
            ps.remove_segments(to_remove)
