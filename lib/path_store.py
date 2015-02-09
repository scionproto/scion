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
        the corresponding weigths, which are stored in the path policy.
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

    def get_local_desirability(self):
        """
        Returns the path desirability.
        """
        return random.randint(0, 3)

    def get_path_length(self):
        """
        Returns the path length.
        """
        return random.randint(0, 3)

    def get_path_freshness(self):
        """
        Returns the path freshness.
        """
        return random.randint(0, 3)

    def get_guaranteed_bandwidth(self):
        """
        Returns the path guaranteed bandwidth.
        """
        return random.randint(0, 3)

    def get_available_bandwidth(self):
        """
        Returns the path available bandwidth.
        """
        return random.randint(0, 3)

    def get_total_bandwidth(self):
        """
        Returns the path total bandwidth.
        """
        return random.randint(0, 3)

    def get_delay(self):
        """
        Returns the path delay.
        """
        return random.randint(0, 3)

    def get_size(self):
        """
        Returns the path size.
        """
        return random.randint(0, 3)

    def __str__(self):
        path_info_str = ''.join(["[Path]\n", str(self.pcb), "ID: ",
            str(self.id), "\n", "Fidelity: ", str(self.fidelity), "\n",
            "Timestamp: ", str(self.timestamp), "\n"])
        return path_info_str


class PathStore(object):
    """
    Path Store class.
    """
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
            self._check_unwanted_ads(path) and self._check_min_max(path))

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
        return (eval("%d <= %d <= %d" %
                self.policy.min_max.get("MinLocalDesirability", 0),
                path.get_local_desirability(),
                self.policy.min_max.get("MaxLocalDesirability", 100))
            and eval("%d <= %d <= %d" %
                self.policy.min_max.get("MinPathLength", 0),
                path.get_path_length(),
                self.policy.min_max.get("MaxPathLength", 100))
            and eval("%d <= %d <= %d" %
                self.policy.min_max.get("MinPathFreshness", 0),
                path.get_path_freshness(),
                self.policy.min_max.get("MaxPathFreshness", 100))
            and eval("%d <= %d <= %d" %
                self.policy.min_max.get("MinGuaranteedBandwidth", 0),
                path.get_guaranteed_bandwidth(),
                self.policy.min_max.get("MaxGuaranteedBandwidth", 100))
            and eval("%d <= %d <= %d" %
                self.policy.min_max.get("MinAvailableBandwidth", 0),
                path.get_available_bandwidth(),
                self.policy.min_max.get("MaxAvailableBandwidth", 100))
            and eval("%d <= %d <= %d" %
                self.policy.min_max.get("MinTotalBandwidth", 0),
                path.get_total_bandwidth(),
                self.policy.min_max.get("MaxTotalBandwidth", 100))
            and eval("%d <= %d <= %d" %
                self.policy.min_max.get("MinDelay", 0),
                path.get_delay(),
                self.policy.min_max.get("MaxDelay", 100))
            and eval("%d <= %d <= %d" %
                self.policy.min_max.get("MinSize", 0),
                path.get_size(),
                self.policy.min_max.get("MaxSize", 100)))

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
