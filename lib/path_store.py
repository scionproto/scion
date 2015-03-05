"""
path_store.py

Copyright 2014 ETH Zurich

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from lib.packet.pcb import PathSegment
from Crypto.Hash import SHA256
from collections import defaultdict
import xml.etree.ElementTree as ET
import time
import random
import sys
import logging


class Policy(object):
    """
    Stores a path policy.
    """
    def __init__(self, policy_file=None):
        self.best_set_size = 0
        self.candidates_set_size = 5
        self.disjointness = 2
        self.update_after_number = 0
        self.update_after_time = 0
        self.history_limit = 0
        self.wanted_ads = {}
        self.unwanted_ads = {}
        self.min_max = {}
        self.properties = {}
        self._policy_file = None
        self._config = None
        if policy_file is not None:
            self.load_file(policy_file)
            self.parse()

    def load_file(self, policy_file):
        """
        Loads an XML file and creates an element tree for further parsing.
        """
        assert isinstance(policy_file, str)
        self._policy_file = policy_file
        self._config = ET.parse(policy_file)

    def parse(self):
        """
        Parses the policies in the path store config file.
        """
        assert self._config is not None, "Must load file first"
        policy = self._config.getroot()
        best_set_size = policy.find("BestSetSize")
        if best_set_size is not None:
            self.best_set_size = int(best_set_size.text)
        candidates_set_size = policy.find("CandidatesSetSize")
        if candidates_set_size is not None:
            self.candidates_set_size = int(candidates_set_size.text)
        disjointness = policy.find("Disjointness")
        if disjointness is not None:
            self.disjointness = int(disjointness.text)
        update_after_number = policy.find("UpdateAfterNumber")
        if update_after_number is not None:
            self.update_after_number = int(update_after_number.text)
        update_after_time = policy.find("UpdateAfterTime")
        if update_after_time is not None:
            self.update_after_time = int(update_after_time.text)
        history_limit = policy.find("HistoryLimit")
        if history_limit is not None:
            self.history_limit = int(history_limit.text)
        filters = policy.find("Filters")
        for filt in filters:
            if filt.tag == "WantedAD":
                value = filt.text.split(":")
                if int(value[0]) not in self.wanted_ads:
                    self.wanted_ads[int(value[0])] = []
                if value[1].isdigit():
                    self.wanted_ads[int(value[0])].append(int(value[1]))
            elif filt.tag == "UnwantedAD":
                value = filt.text.split(":")
                if int(value[0]) not in self.unwanted_ads:
                    self.unwanted_ads[int(value[0])] = []
                if value[1].isdigit():
                    self.unwanted_ads[int(value[0])].append(int(value[1]))
            else:
                self.min_max[filt.tag] = int(filt.text)
        properties = policy.find("Properties")
        for propert in properties:
            self.properties[propert.tag] = int(propert.text)

    def __str__(self):
        return ("[Policy]\n" +
            ", ".join(["BestSetSize: " + str(self.best_set_size),
            "UpdateAfterNumber: " + str(self.update_after_number),
            "UpdateAfterTime: " + str(self.update_after_time),
            "HistoryLimit: " + str(self.history_limit),
            "WantedADs: " + str(self.wanted_ads),
            "UnwantedADs: " + str(self.unwanted_ads),
            "MinMax: " + str(self.min_max),
            "Properties: " + str(self.properties)]))


class PathSegmentInfo(object):
    """
    Stores general information about a path.
    """
    def __init__(self, pcb=None, policy=None):
        assert pcb is not None and policy is not None
        self.pcb = pcb
        self.id = ""
        self.fidelity = 0
        self.set_id()
        self.set_fidelity(policy)
        self.timestamp = int(time.time())

    def set_id(self):
        """
        Computes a path ID, which is the concatenation of all AD blocks' IDs,
        ingress_ifs and egress_ifs
        """
        id_str = ""
        for ad in self.pcb.ads:
            id_str += ",".join([str(ad.pcbm.ad_id), str(ad.pcbm.hof.ingress_if),
                                str(ad.pcbm.hof.egress_if)])
            id_str += ","
        id_str += str(self.pcb.iof.timestamp)
        id_str = id_str.encode('utf-8')
        self.id = SHA256.new(id_str).hexdigest()

    def set_fidelity(self, policy):
        """
        Computes a path fidelity based on all path properties and considering
        the corresponding weights, which are stored in the path policy.
        """
        self.fidelity = 0
        self.fidelity += (policy.properties.get("LocalDesirability", 0) *
                          self.get_local_desirability())
        self.fidelity += (policy.properties.get("PathLength", 0) *
                          self.get_path_length())
        self.fidelity += (policy.properties.get("PathFreshness", 0) *
                          self.get_path_freshness())
        self.fidelity += (policy.properties.get("GuaranteedBandwidth", 0) *
                          self.get_guaranteed_bandwidth())
        self.fidelity += (policy.properties.get("AvailableBandwidth", 0) *
                          self.get_available_bandwidth())
        self.fidelity += (policy.properties.get("TotalBandwidth", 0) *
                          self.get_total_bandwidth())
        self.fidelity += (policy.properties.get("Delay", 0) *
                          self.get_delay())
        self.fidelity += (policy.properties.get("Size", 0) *
                          self.get_size())
        self.fidelity += (policy.properties.get("Age", 0) *
                          self.get_age())
        self.fidelity += (policy.properties.get("PeerLinks", 0) *
                          self.get_peer_links())

    def get_local_desirability(self):
        """
        Returns the path desirability.
        """
        return 0

    def get_path_length(self):
        """
        Returns the path length.
        """
        return len(self.pcb.ads)

    def get_path_freshness(self):
        """
        Returns the path freshness.
        """
        return random.randint(0, 3)

    def get_guaranteed_bandwidth(self):
        """
        Returns the path guaranteed bandwidth.
        """
        return 0

    def get_available_bandwidth(self):
        """
        Returns the path available bandwidth.
        """
        return 0

    def get_total_bandwidth(self):
        """
        Returns the path total bandwidth.
        """
        return 0

    def get_delay(self):
        """
        Returns the path delay.
        """
        return 0

    def get_size(self):
        """
        Returns the path size.
        """
        return self.pcb.size

    def get_age(self):
        """
        Returns the path age.

        .. warning::
           The precision of this function is system-dependent and is not
           guaranteed to be better than 1 second. Thus it is possible that two
           successive calls to this function will return decreasing values.
        """
        return int(time.time()) - self.pcb.get_timestamp()

    def get_peer_links(self):
        """
        Returns the number of peering links in the path.
        """
        numPLs = 0
        for ad in self.pcb.ads:
            numPLs += len(ad.pms)
        return numPLs

    def __str__(self):
        path_info_str = ''.join(["[Path]\n", str(self.pcb), "ID: ",
                                 str(self.id), "\n", "Fidelity: ",
                                 str(self.fidelity), "\n", "Timestamp: ",
                                 str(self.timestamp), "\n"])
        return path_info_str


class PathStore(object):
    """
    Path Store class.

    :cvar MIN_LOC_DES: the default minimum local desirability for all candidate
       paths.
    :vartype MIN_LOC_DES: int
    :cvar MAX_LOC_DES: the default maximum local desirability for all candidate
       paths.
    :vartype MAX_LOC_DES: int
    :cvar MIN_LEN: the default minimum length for all candidate paths.
    :vartype MIN_LEN: int
    :cvar MAX_LEN: the default maximum length for all candidate paths.
    :vartype MAX_LEN: int
    :cvar MIN_FRESH: the default minimum freshness for all candidate paths.
    :vartype MIN_FRESH: int
    :cvar MAX_FRESH: the default maximum freshness for all candidate paths.
    :vartype MAX_LEN: int
    :cvar MIN_GUAR_BW: the default minimum guaranteed bandwidth for all
       candidate paths.
    :vartype MIN_GUAR_BW: int
    :cvar MAX_GUAR_BW: the default maximum guaranteed bandwidth for all
       candidate paths.
    :vartype MAX_GUAR_BW: int
    :cvar MIN_AV_BW: the default minimum available bandwidth for all candidate
       paths.
    :vartype MIN_AV_BW: int
    :cvar MAX_AV_BW: the default maximum available bandwidth for all candidate
       paths.
    :vartype MAX_AV_BW: int
    :cvar MIN_TOT_BW: the default minimum total bandwidth for all candidate
       paths.
    :vartype MIN_TOT_BW: int
    :cvar MAX_TOT_BW: the default maximum total bandwidth for all candidate
       paths.
    :vartype MAX_TOT_BW: int
    :cvar MIN_DELAY: the default minimum delay for all candidate paths.
    :vartype MIN_DELAY: int
    :cvar MAX_DELAY: the default maximum delay for all candidate paths.
    :vartype MAX_DELAY: int
    :cvar MIN_SIZE: the default minimum size for all candidate paths.
    :vartype MIN_SIZE: int
    :cvar MAX_SIZE: the default maximum size for all candidate paths.
    :vartype MAX_SIZE: int
    :cvar MIN_AGE: the default minimum age for all candidate paths.
    :vartype MIN_AGE: int
    :cvar MAX_AGE: the default maximum age for all candidate paths.
    :vartype MAX_AGE: int
    :cvar MIN_PEER: the default minimum number of peering links for all
       candidate paths.
    :vartype MIN_PEER: int
    :cvar MAX_PEER: the default maximum number of peering links for all
       candidate paths.
    :vartype MAX_PEER: int
    """

    MIN_LOC_DES = 0
    MAX_LOC_DES = 100
    MIN_LEN = 0
    MAX_LEN = 100
    MIN_FRESH = 0
    MAX_FRESH = 100
    MIN_GUAR_BW = 0
    MAX_GUAR_BW = 100
    MIN_AV_BW = 0
    MAX_AV_BW = 100
    MIN_TOT_BW = 0
    MAX_TOT_BW = 100
    MIN_DELAY = 0
    MAX_DELAY = 100
    MIN_SIZE = 0
    MAX_SIZE = 500
    MIN_AGE = 0
    MAX_AGE = 3600
    MIN_PEER = 1
    MAX_PEER = 20

    def __init__(self, policy_file):
        self.policy = Policy(policy_file)
        self.candidates = []
        self.best_paths_history = []

    def add_path(self, pcb):
        """
        Adds a new path in the cadidates list, if it passes the filter checks.
        """
        path = PathSegmentInfo(pcb, self.policy)
        #if not self._check_filters(path):
        #    logging.warning("The following path is invalid %s", path)
        #    return
        found = False
        old_pos = 0
        new_pos = 0
        for i, candidate in enumerate(self.candidates):
            if candidate.id == path.id:
                found = True
                old_pos = i
            if candidate.fidelity > path.fidelity:
                new_pos += 1
        if found:
            self.candidates[old_pos].timestamp = int(time.time())
            self.candidates[old_pos].fidelity = path.fidelity
            self.candidates.insert(new_pos, self.candidates.pop(old_pos))
        else:
            self.candidates.insert(new_pos, path)

    def _check_filters(self, path):
        """
        Runs some checks, including: (un)wanted ADs and min/max property values.
        """
        return (self._check_wanted_ads(path) and
                self._check_unwanted_ads(path) and
                self._check_min_max(path))

    def _check_wanted_ads(self, path):
        """
        Checks whether all ADs in the path belong to the white list.
        """
        for ad in path.pcb.ads:
            if ad.pcbm.ad_id not in self.policy.wanted_ads:
                return False
            for interface in self.policy.wanted_ads[ad.pcbm.ad_id]:
                if (ad.pcbm.hof.ingress_if != interface and
                    ad.pcbm.hof.egress_if != interface):
                    return False
        return True

    def _check_unwanted_ads(self, path):
        """
        Checks whether any of the ADs in the path belong to the black list.
        """
        for ad in path.pcb.ads:
            if ad.pcbm.ad_id in self.policy.unwanted_ads:
                interfaces = self.policy.unwanted_ads[ad.pcbm.ad_id]
                if len(interfaces) == 0:
                    return False
                for interface in interfaces:
                    if (ad.pcbm.hof.ingress_if == interface or
                        ad.pcbm.hof.egress_if == interface):
                        return False
        return True

    def _check_min_max(self, path):
        """
        Checks whether any of the path properties has a value outside the
        predefined min-max range.
        """
        return (
            (self.policy.min_max.get("MinLocalDesirability",
                                     PathStore.MIN_LOC_DES) <=
             path.get_local_desirability() <=
             self.policy.min_max.get("MaxLocalDesirability",
                                     PathStore.MAX_LOC_DES)) and
            (self.policy.min_max.get("MinPathLength",
                                     PathStore.MIN_LEN) <=
             path.get_path_length() <=
             self.policy.min_max.get("MaxPathLength",
                                     PathStore.MAX_LEN)) and
            (self.policy.min_max.get("MinPathLength",
                                     PathStore.MIN_LEN) <=
             path.get_path_length() <=
             self.policy.min_max.get("MaxPathLength",
                                     PathStore.MAX_LEN)) and
            (self.policy.min_max.get("MinPathFreshness",
                                     PathStore.MIN_FRESH) <=
             path.get_path_freshness() <=
             self.policy.min_max.get("MaxPathFreshness",
                                     PathStore.MAX_FRESH)) and
            (self.policy.min_max.get("MinGuaranteedBandwidth",
                                     PathStore.MIN_GUAR_BW) <=
             path.get_guaranteed_bandwidth() <=
             self.policy.min_max.get("MaxGuaranteedBandwidth",
                                     PathStore.MAX_GUAR_BW)) and
            (self.policy.min_max.get("MinAvailableBandwidth",
                                     PathStore.MIN_AV_BW) <=
             path.get_available_bandwidth() <=
             self.policy.min_max.get("MaxAvailableBandwidth",
                                     PathStore.MAX_AV_BW)) and
            (self.policy.min_max.get("MinTotalBandwidth",
                                     PathStore.MIN_TOT_BW) <=
             path.get_total_bandwidth() <=
             self.policy.min_max.get("MaxTotalBandwidth",
                                     PathStore.MAX_TOT_BW)) and
            (self.policy.min_max.get("MinDelay",
                                     PathStore.MIN_DELAY) <=
             path.get_delay() <=
             self.policy.min_max.get("MaxDelay",
                                     PathStore.MAX_DELAY)) and
            (self.policy.min_max.get("MinSize",
                                     PathStore.MIN_SIZE) <=
             path.get_size() <=
             self.policy.min_max.get("MaxSize",
                                     PathStore.MAX_SIZE)) and
            (self.policy.min_max.get("MinAge",
                                     PathStore.MIN_AGE) <=
             path.get_age() <=
             self.policy.min_max.get("MaxAge",
                                     PathStore.MAX_AGE)) and
            (self.policy.min_max.get("MinPeerLinks",
                                     PathStore.MIN_PEER) <=
             path.get_peer_links() <=
             self.policy.min_max.get("MaxPeerLinks",
                                     PathStore.MAX_PEER)))

    def update_policy(self, policy_file):
        """
        Updates the policy in the path store. Also all paths' fidelity as a
        consequence.
        """
        self.policy = Policy(policy_file)
        for i in range(len(self.candidates)):
            self.candidates[i].set_fidelity(self.policy)
        self.candidates = sorted(self.candidates, 
            key=lambda PathSegmentInfo: PathSegmentInfo.fidelity, reverse=True)

    def get_candidates(self, k=10):
        """
        Returns k path candidates from the temporary buffer.
        """
        return self.candidates[:k]

    def get_last_selection(self, k=10):
        """
        Returns the latest k best paths from the history.
        """
        return self.best_paths_history[0][:k]

    def get_paths(self, k=10):
        """
        Returns the latest k best paths.
        """
        ret = self.best_paths_history[0][:k]
        if len(ret) < k:
            ret += self.candidates
            ret = sorted(ret, key=lambda PathSegmentInfo: PathSegmentInfo.fidelity,
                reverse=True)
            ret = self._check_disjointness(ret)
            ret = ret[:k]
        return ret

    def _check_disjointness(self, paths):
        """
        Checks that the paths disjointness is below a certain level, which is
        stored in the policy.
        """
        to_remove = []
        old_count = defaultdict(lambda: 0)
        new_count = defaultdict(lambda: 0)
        for i, path in enumerate(paths):
            for ad_marking in paths[i].pcb.ads:
                new_count[ad_marking.pcbm.ad_id] += 1
            if max(new_count.values()) > self.policy.disjointness:
                new_count = old_count
                to_remove.insert(0, i)
            else:
                old_count = new_count
        for i in to_remove:
            del paths[i]
        return paths

    def store_selection(self, k=10):
        """
        Stores the best k paths into the path history.
        """
        paths = self.candidates
        paths = self._check_disjointness(paths)
        paths = paths[:k]
        self.best_paths_history.insert(0, paths)
        self.candidates = {}

    def __str__(self):
        path_store_str = "[PathStore]\n"
        path_store_str += str(self.policy) + "\n"
        for candidate in self.candidates:
            path_store_str += str(candidate)
        return path_store_str
