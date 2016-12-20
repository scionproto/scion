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
import logging
from _collections import defaultdict

# SCION
from infrastructure.beacon_server.base import BeaconServer
from lib.defines import PATH_SERVICE, SIBRA_SERVICE
from lib.errors import SCIONParseError, SCIONServiceLookupError
from lib.packet.opaque_field import InfoOpaqueField
from lib.packet.path_mgmt.seg_recs import PathRecordsReg
from lib.packet.pcb import PathSegment
from lib.path_store import PathStore
from lib.types import PathSegmentType as PST
from lib.util import SCIONTime


class CoreBeaconServer(BeaconServer):
    """
    PathConstructionBeacon Server in a core AS.

    Starts broadcasting beacons down-stream within an ISD and across ISDs
    towards other core beacon servers.
    """
    def __init__(self, server_id, conf_dir):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        """
        super().__init__(server_id, conf_dir)
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
        count = 0
        for r in self.topology.routing_border_routers:
            dst_ia = r.interface.isd_as
            if not self._filter_pcb(pcb, dst_ia=dst_ia):
                continue
            new_pcb, meta = self._mk_prop_pcb_meta(
                pcb.copy(), r.interface.isd_as, r.interface.if_id)
            if not new_pcb:
                continue
            self.send_meta(new_pcb, meta)
            count += 1
        return count

    def handle_pcbs_propagation(self):
        """
        Generate a new beacon or gets ready to forward the one received.
        """
        timestamp = int(SCIONTime.get_time())
        # Create beacon for downstream ASes.
        down_iof = InfoOpaqueField.from_values(timestamp, self.addr.isd_as[0])
        downstream_pcb = PathSegment.from_values(down_iof)
        self.propagate_downstream_pcb(downstream_pcb)
        # Create beacon for core ASes.
        core_iof = InfoOpaqueField.from_values(timestamp, self.addr.isd_as[0])
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
        self.register_core_segments()

    def register_core_segment(self, pcb):
        """
        Register the core segment contained in 'pcb' with the local core path
        server.
        """
        pcb.remove_crypto()
        pcb.sign(self.signing_key)
        # Register core path with local core path server.
        try:
            addr, port = self.dns_query_topo(PATH_SERVICE)[0]
        except SCIONServiceLookupError:
            # If there are no local path servers, stop here.
            return
        records = PathRecordsReg.from_values({PST.CORE: [pcb]})
        meta = self.DefaultMeta.from_values(host=addr, port=port)
        self.send_meta(records.copy(), meta)
        addr, port = self.dns_query_topo(SIBRA_SERVICE)[0]
        meta = self.DefaultMeta.from_values(host=addr, port=port)
        self.send_meta(records, meta)

    def process_pcbs(self, pcbs, raw=True):
        """
        Process new beacons and appends them to beacon list.
        """
        count = 0
        for pcb in pcbs:
            if raw:
                try:
                    pcb = PathSegment.from_raw(pcb)
                except SCIONParseError as e:
                    logging.error("Unable to parse raw pcb: %s", e)
                    continue
            if not self._filter_pcb(pcb):
                count += 1
                continue
            self._try_to_verify_beacon(pcb)
            self.handle_ext(pcb)
        if count:
            logging.debug("Dropped %d looping Core Segment PCBs", count)

    def _filter_pcb(self, pcb, dst_ia=None):
        """
        Check that there are no AS- or ISD-level loops in the PCB.

        An AS-level loop is where a beacon passes through any AS more than once.
        An ISD-level loop is where a beacon passes through any ISD more than
        once.
        """
        # Add the current ISD-AS to the end, to look for loops in the final list
        # of hops.
        isd_ases = [asm.isd_as() for asm in pcb.iter_asms()]
        isd_ases.append(self.addr.isd_as)
        # If a destination ISD-AS is specified, add that as well. Used to decide
        # when to propagate.
        if dst_ia:
            isd_ases.append(dst_ia)
        isds = set()
        last_isd = 0
        for isd_as in isd_ases:
            if isd_ases.count(isd_as) > 1:
                # This ISD-AS has been seen before
                return False
            curr_isd = isd_as[0]
            if curr_isd == last_isd:
                continue
            # Switched to a new ISD
            last_isd = curr_isd
            if curr_isd in isds:
                # This ISD has been seen before
                return False
            isds.add(curr_isd)
        return True

    def _check_trc(self, isd_as, trc_ver):
        """
        Return True or False whether the necessary TRC file is found.

        :param ISD_AS isd_as: ISD-AS identifier.
        :param int trc_ver: TRC file version.
        :returns: True if the files exist, False otherwise.
        :rtype: bool
        """
        return bool(self._get_trc(isd_as, trc_ver))

    def process_cert_chain_rep(self, cert_chain_rep, meta):
        raise NotImplementedError

    def _handle_verified_beacon(self, pcb):
        """
        Once a beacon has been verified, place it into the right containers.

        :param pcb: verified path segment.
        :type pcb: PathSegment
        """
        self.core_beacons[pcb.first_ia()].add_segment(pcb)

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
            if not pcb:
                continue
            pcb.sign(self.signing_key)
            self.register_core_segment(pcb)
            count += 1
        logging.info("Registered %d Core paths", count)

    def _remove_revoked_pcbs(self, rev_info):
        candidates = []
        for ps in self.core_beacons.values():
            candidates += ps.candidates
        to_remove = self._pcb_list_to_remove(candidates, rev_info)
        # Remove the affected segments from the path stores.
        for ps in self.core_beacons.values():
            ps.remove_segments(to_remove)
