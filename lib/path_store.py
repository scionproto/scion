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
:mod:`path_store` --- Path record storage and selection for path servers
========================================================================
"""
# Stdlib
import json
import logging
import time
from collections import defaultdict, deque

# SCION
from lib.packet.pcb import PathSegment


class PathPolicy(object):
    """
    Stores a path policy.
    """
    def __init__(self):
        """
        Initialize an instance of the class .

        :param :
        :type :
        :param :
        :type :
        :param :
        :type :
        """
        self.best_set_size = 5
        self.candidates_set_size = 20
        self.history_limit = 0
        self.update_after_number = 0
        self.update_after_time = 0
        self.unwanted_ads = []
        self.property_ranges = {}
        self.property_weights = {}

    def get_path_policy_dict(self):
        path_policy_dict = {'best_set_size': self.best_set_size,
                            'candidates_set_size': self.candidates_set_size,
                            'history_limit': self.history_limit,
                            'update_after_number': self.update_after_number,
                            'update_after_time': self.update_after_time,
                            'unwanted_ads': self.unwanted_ads,
                            'property_ranges': self.property_ranges,
                            'property_weights': self.property_weights}
        return path_policy_dict

    def check_filters(self, pcb):
        """
        Runs some checks, including: unwanted ADs and min/max property values.
        """
        assert isinstance(pcb, PathSegment)
        if not self._check_unwanted_ads(pcb):
            logging.warning("PathStore: pcb discarded (unwanted AD).")
            return False
        if not self._check_property_ranges(pcb):
            logging.warning("PathStore: pcb discarded (property range).")
            return False
        return True

    def _check_unwanted_ads(self, pcb):
        """
        Checks whether any of the ADs in the path belong to the black list.
        """
        for ad in pcb.ads:
            if (ad.pcbm.spcbf.isd_id, ad.pcbm.ad_id) in self.unwanted_ads:
                return False
        return True

    def _check_property_ranges(self, pcb):
        """
        Checks whether any of the path properties has a value outside the
        predefined min-max range.
        """
        check = True
        if self.property_ranges['PeerLinks']:
            check = (check and (self.property_ranges['PeerLinks'][0]
                                <= pcb.get_n_peer_links() <=
                                self.property_ranges['PeerLinks'][1]))
        if self.property_ranges['HopsLength']:
            check = (check and (self.property_ranges['HopsLength'][0]
                                <= pcb.get_n_hops() <=
                                self.property_ranges['HopsLength'][1]))
        if self.property_ranges['DelayTime']:
            check = (check and (self.property_ranges['DelayTime'][0]
                                <= int(time.time()) - pcb.get_timestamp() <=
                                self.property_ranges['DelayTime'][1]))
        if self.property_ranges['GuaranteedBandwidth']:
            check = (check and (self.property_ranges['GuaranteedBandwidth'][0]
                                <= 10 <=
                                self.property_ranges['GuaranteedBandwidth'][1]))
        if self.property_ranges['AvailableBandwidth']:
            check = (check and (self.property_ranges['AvailableBandwidth'][0]
                                <= 10 <=
                                self.property_ranges['AvailableBandwidth'][1]))
        if self.property_ranges['TotalBandwidth']:
            check = (check and (self.property_ranges['TotalBandwidth'][0]
                                <= 10 <=
                                self.property_ranges['TotalBandwidth'][1]))
        return check

    @classmethod
    def from_file(cls, policy_file):
        """
        Create a PathPolicy instance from the file.

        :param policy_file: path to the path policy file
        :type policy_file: str
        :returns: the newly created PathPolicy instance
        :rtype: :class: `PathPolicy`
        """
        try:
            with open(policy_file) as path_policy_fh:
                policy_dict = json.load(path_policy_fh)
        except (ValueError, KeyError, TypeError):
            logging.error("PathPolicy: JSON format error.")
            return
        return cls.from_dict(policy_dict)

    @classmethod
    def from_dict(cls, policy_dict):
        """
        Create a PathPolicy instance from the dictionary.

        :param policy_dict: dictionary representation of path policy
        :type policy_dict: dict
        :returns: the newly created PathPolicy instance
        :rtype: :class:`PathPolicy`
        """
        path_policy = cls()
        path_policy.parse_dict(policy_dict)
        return path_policy

    def parse_dict(self, path_policy):
        """
        Parses the policies from the dictionary.
        """
        self.best_set_size = path_policy['BestSetSize']
        self.candidates_set_size = path_policy['CandidatesSetSize']
        self.history_limit = path_policy['HistoryLimit']
        self.update_after_number = path_policy['UpdateAfterNumber']
        self.update_after_time = path_policy['UpdateAfterTime']
        unwanted_ads = path_policy['UnwantedADs'].split(',')
        for unwanted_ad in unwanted_ads:
            unwanted_ad = unwanted_ad.split('-')
            unwanted_ad = (int(unwanted_ad[0]), int(unwanted_ad[1]))
            self.unwanted_ads.append(unwanted_ad)
        property_ranges = path_policy['PropertyRanges']
        for key in property_ranges:
            property_range = property_ranges[key].split('-')
            property_range = (int(property_range[0]), int(property_range[1]))
            self.property_ranges[key] = property_range
        self.property_weights = path_policy['PropertyWeights']

    def __str__(self):
        path_policy_dict = self.get_path_policy_dict()
        path_policy_str = json.dumps(path_policy_dict, sort_keys=True, indent=4)
        return path_policy_str


class PathStoreRecord(object):
    """
    Path record that gets stored in the the PathStore.

    :ivar pcb: the PCB representing the record.
    :vartype pcb: :class:`lib.packet.pcb.PathSegment`
    :ivar id: the path segment identifier stored in the record's PCB.
    :vartype id: bytes
    :ivar fidelity: the fidelity of the path record.
    :vartype fidelity: float
    :ivar peer_links: the normalized number of peer links in the path segment.
    :vartype peer_links: float
    :ivar hops_length: the normalized length of the path segment.
    :vartype hops_length: float
    :ivar disjointness: the normalized disjointness of the path segment compared
                        to the other paths in the PathStore.
    :vartype disjointness: float
    :ivar last_sent_time: the Unix time at which the path segment was last sent.
    :vartype last_sent_time: int
    :ivar last_seen_time: the Unix time at which the path segment was last seen.
    :vartype last_seen_time: int
    :ivar delay_time: the normalized time in seconds between the PCB's creation
                      and the time it was last seen by the path server.
    :vartype delay_time: float
    :ivar expiration_time: the Unix time at which the path segment expires.
    :vartype expiration_time: int
    :ivar guaranteed_bandwidth: the path segment's guaranteed bandwidth.
    :vartype guaranteed_bandwidth: int
    :ivar available_bandwidth: the path segment's available bandwidth.
    :vartype available_bandwidth: int
    :ivar total_bandwidth: the path segment's total bandwidth.
    :vartype total_bandwidth: int
    """

    def __init__(self, pcb):
        """
        Initialize an instance of the class .

        :param :
        :type :
        :param :
        :type :
        :param :
        :type :
        """
        assert isinstance(pcb, PathSegment)
        self.pcb = pcb
        self.id = pcb.segment_id
        self.fidelity = 0
        self.peer_links = 0
        self.hops_length = 0
        self.disjointness = 0
        self.last_sent_time = 1420070400  # year 2015
        self.last_seen_time = int(time.time())
        self.delay_time = 0
        self.expiration_time = pcb.get_expiration_time()
        self.guaranteed_bandwidth = 0
        self.available_bandwidth = 0
        self.total_bandwidth = 0

    def update_fidelity(self, path_policy):
        """
        Computes a path fidelity based on all path properties and considering
        the corresponding weights, which are stored in the path policy.
        """
        self.fidelity = 0
        now = time.time()
        self.fidelity += (path_policy.property_weights['PeerLinks'] *
                          self.peer_links)
        self.fidelity += (path_policy.property_weights['HopsLength'] /
                          self.hops_length)
        self.fidelity += (path_policy.property_weights['Disjointness'] *
                          self.disjointness)
        self.fidelity += (path_policy.property_weights['LastSentTime'] *
                          (now - self.last_sent_time) / now)
        self.fidelity += (path_policy.property_weights['LastSeenTime'] *
                          self.last_seen_time / now)
        self.fidelity += (path_policy.property_weights['DelayTime'] /
                          self.delay_time)
        self.fidelity += (path_policy.property_weights['ExpirationTime'] *
                          (self.expiration_time - now) / self.expiration_time)
        self.fidelity += (path_policy.property_weights['GuaranteedBandwidth'] *
                          self.guaranteed_bandwidth)
        self.fidelity += (path_policy.property_weights['AvailableBandwidth'] *
                          self.available_bandwidth)
        self.fidelity += (path_policy.property_weights['TotalBandwidth'] *
                          self.total_bandwidth)

    def __eq__(self, other):
        if type(other) is type(self):
            return self.id == other.id
        else:
            return False

    def __str__(self):
        path_info_str = "[PathStoreRecord]\n"
        path_info_str += "ID: " + str(self.id) + "\n"
        path_info_str += "Fidelity: " + str(self.fidelity)
        return path_info_str


class PathStore(object):
    """
    Path Store class.
    """

    def __init__(self, path_policy):
        """
        Initialize an instance of the class .

        :param :
        :type :
        :param :
        :type :
        :param :
        :type :
        """
        self.path_policy = path_policy
        self.candidates = []
        self.best_paths_history = deque(maxlen=self.path_policy.history_limit)

    def add_segment(self, pcb):
        """
        Possibly add a new path to the candidates list.

        :param pcb: The PCB representing the potential path.
        :type pcb: PathSegment
        """
        assert isinstance(pcb, PathSegment)
        if not self.path_policy.check_filters(pcb):
            return
        record = PathStoreRecord(pcb)
        for index in range(len(self.candidates)):
            if self.candidates[index] == record:
                record.last_sent_time = self.candidates[index].last_sent_time
                del self.candidates[index]
                break
        self.candidates.append(record)
        self._update_all_fidelity()
        self.candidates = sorted(self.candidates, key=lambda x: x.fidelity,
                                 reverse=True)
        if len(self.candidates) >= self.path_policy.candidates_set_size:
            self._remove_expired_segments()
            self.candidates = self.candidates[:self.path_policy.best_set_size]
            self.best_paths_history.appendleft(self.candidates)

    def _update_all_peer_links(self):
        """
        Update the peer links property of all path candidates.
        """
        pl_count = []
        for candidate in self.candidates:
            candidate.peer_links = candidate.pcb.get_n_peer_links()
            pl_count.append(candidate.peer_links)
        max_peer_links = max(pl_count)
        for candidate in self.candidates:
            candidate.peer_links /= max_peer_links + 1

    def _update_all_hops_length(self):
        """
        Update the hops length property of all path candidates.
        """
        hl_count = []
        for candidate in self.candidates:
            candidate.hops_length = candidate.pcb.get_n_hops()
            hl_count.append(candidate.hops_length)
        max_hops_length = max(hl_count)
        for candidate in self.candidates:
            candidate.hops_length /= max_hops_length

    def _update_all_disjointness(self):
        """
        Update the disjointness of all path candidates.
        """
        ad_count = defaultdict(int)
        for candidate in self.candidates:
            for ad_marking in candidate.pcb.ads:
                ad_count[ad_marking.pcbm.ad_id] += 1
        tot_ads = sum(ad_count.values())
        for candidate in self.candidates:
            candidate.disjointness = tot_ads
            for ad_marking in candidate.pcb.ads:
                candidate.disjointness -= ad_count[ad_marking.pcbm.ad_id]
            candidate.disjointness /= tot_ads

    def _update_all_delay_time(self):
        """
        Update the delay time property of all path candidates.
        """
        dt_count = []
        for candidate in self.candidates:
            candidate.delay_time = (candidate.last_seen_time -
                                    candidate.pcb.get_timestamp() + 1)
            dt_count.append(candidate.delay_time)
        max_delay_time = max(dt_count)
        for candidate in self.candidates:
            candidate.delay_time /= max_delay_time

    def _update_all_fidelity(self):
        """
        Update the fidelity of all path candidates.
        """
        self._update_all_peer_links()
        self._update_all_hops_length()
        self._update_all_disjointness()
        self._update_all_delay_time()
        for candidate in self.candidates:
            candidate.update_fidelity(self.path_policy)

    def get_best_segments(self, k=None):
        """
        Returns the k best paths from the temporary buffer.
        """
        if k is None:
            k = self.path_policy.best_set_size
        self._remove_expired_segments()
        best_paths = []
        for candidate in self.candidates[:k]:
            best_paths.append(candidate.pcb)
        return best_paths

    def get_latest_history_snapshot(self, k=None):
        """
        Returns the latest k best paths from the history.
        """
        if k is None:
            k = self.path_policy.best_set_size
        best_paths = []
        if self.best_paths_history:
            for candidate in self.best_paths_history[0][:k]:
                best_paths.append(candidate.pcb)
        return best_paths

    def _remove_expired_segments(self):
        """
        Remove candidates if their expiration_time is up.
        """
        seg_ids = []
        now = time.time()
        for candidate in self.candidates:
            if candidate.expiration_time <= now:
                seg_ids.append(candidate.id)
        self.remove_segments(seg_ids)

    def remove_segments(self, seg_ids):
        """
        Removes segments in 'seg_ids' from the candidates.
        """
        self.candidates[:] = [c for c in self.candidates if c.id not in seg_ids]
        if self.candidates:
            self._update_all_fidelity()
            self.candidates = sorted(self.candidates, key=lambda x: x.fidelity,
                                     reverse=True)

    def get_segment(self, seg_id):
        """
        Returns the segment for the corresponding ID or None.
        """
        for record in self.candidates:
            if record.id == seg_id:
                return record.pcb
        return None

    def __str__(self):
        path_store_str = "[PathStore]"
        for candidate in self.candidates:
            path_store_str += "\n" + str(candidate)
        return path_store_str
