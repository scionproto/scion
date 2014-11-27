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

from lib.packet.pcb import PCB
import xml.etree.ElementTree as ET
import hashlib, time, random, sys


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
                if int(value[0]) not in self.wanted_ads.keys():
                    self.wanted_ads[int(value[0])] = []
                if value[1].isdigit():
                    self.wanted_ads[int(value[0])].append(int(value[1]))
            elif filt.tag == "UnwantedAD":
                value = filt.text.split(":")
                if int(value[0]) not in self.unwanted_ads.keys():
                    self.unwanted_ads[int(value[0])] = []
                if value[1].isdigit():
                    self.unwanted_ads[int(value[0])].append(int(value[1]))
            else:
                self.min_max[filt.tag] = int(filt.text)
        properties = policy.find("Properties")
        for propert in properties:
            self.properties[propert.tag] = int(propert.text)

    def __str__(self):
        return "[Policy]\n" + \
               ", ".join(["BestSetSize: " + str(self.best_set_size),
                          "UpdateAfterNumber: " + str(self.update_after_number),
                          "UpdateAfterTime: " + str(self.update_after_time),
                          "HistoryLimit: " + str(self.history_limit),
                          "WantedADs: " + str(self.wanted_ads),
                          "UnwantedADs: " + str(self.unwanted_ads),
                          "MinMax: " + str(self.min_max),
                          "Properties: " + str(self.properties)])


class PathInfo(object):
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
        for autonomous_domain in self.pcb.ads:
            id_str += ",".join([str(autonomous_domain.pcbm.ad_id),
                                str(autonomous_domain.pcbm.hof.ingress_if),
                                str(autonomous_domain.pcbm.hof.egress_if)])
            id_str += ","
        id_str += str(self.pcb.iof.timestamp)
        id_str = id_str.encode('utf-8')
        id_hash = hashlib.sha256()
        id_hash.update(id_str)
        self.id = id_hash.hexdigest()

    def set_fidelity(self, policy):
        """
        Computes a path fidelity based on all path properties and considering
        the corresponding weigths, which are stored in the path policy.
        """
        self.fidelity = 0
        self.fidelity += policy.properties.get("LocalDesirability", 0) * \
                         self.get_local_desirability()
        self.fidelity += policy.properties.get("PathLength", 0) * \
                         self.get_path_length()
        self.fidelity += policy.properties.get("PathFreshness", 0) * \
                         self.get_path_freshness()
        self.fidelity += policy.properties.get("GuaranteedBandwidth", 0) * \
                         self.get_guaranteed_bandwidth()
        self.fidelity += policy.properties.get("AvailableBandwidth", 0) * \
                         self.get_available_bandwidth()
        self.fidelity += policy.properties.get("TotalBandwidth", 0) * \
                         self.get_total_bandwidth()
        self.fidelity += policy.properties.get("Delay", 0) * \
                         self.get_delay()
        self.fidelity += policy.properties.get("Size", 0) * \
                         self.get_size()

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
        path_info_str = "[Path]\n"
        path_info_str += str(self.pcb)
        path_info_str += "ID: " + str(self.id) + "\n"
        path_info_str += "Fidelity: " + str(self.fidelity) + "\n"
        path_info_str += "Timestamp: " + str(self.timestamp) + "\n"
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
        Adds a new path if before it passes the checks.
        """
        path = PathInfo(pcb, self.policy)
        if self._check_filters(path) == False:
            print("The following path has not passed the filters checks", path)
            return
        found = False
        old_pos = 0
        new_pos = 0
        for i, candidate in enumerate(self.candidates):
            if candidate.id == path.id:
                found = True
                old_pos = i
            if candidate.fidelity > path.fidelity:
                new_pos += 1
        if found == True:
            self.candidates[old_pos].timestamp = int(time.time())
            self.candidates[old_pos].fidelity = path.fidelity
            self.candidates.insert(new_pos, self.candidates.pop(old_pos))
        else:
            self.candidates.insert(new_pos, path)

    def _check_filters(self, path):
        """
        Runs some checks, including: (un)wanted ADs and min/max property values.
        """
        return self._check_wanted_ads(path) and \
               self._check_unwanted_ads(path) and \
               self._check_min_max(path)

    def _check_wanted_ads(self, path):
        """
        Checks whether all ADs in the path belong to the white list.
        """
        for autonomous_domain in path.pcb.ads:
            if autonomous_domain.pcbm.ad_id not in \
                self.policy.wanted_ads.keys():
                return False
            for interface in \
                self.policy.wanted_ads[autonomous_domain.pcbm.ad_id]:
                if autonomous_domain.pcbm.hof.ingress_if != interface and \
                    autonomous_domain.pcbm.hof.egress_if != interface:
                    return False
        return True

    def _check_unwanted_ads(self, path):
        """
        Checks whether any of the ADs in the path belong to the black list.
        """
        for a_domain in path.pcb.ads:
            if a_domain.pcbm.ad_id in self.policy.unwanted_ads.keys():
                interfaces = self.policy.unwanted_ads[a_domain.pcbm.ad_id]
                if len(interfaces) == 0:
                    return False
                for interface in interfaces:
                    if a_domain.pcbm.hof.ingress_if == interface or \
                       a_domain.pcbm.hof.egress_if == interface:
                        return False
        return True

    def _check_min_max(self, path):
        """
        Checks whether any of the path properties has a value outside the
        predefined min-max range.
        """
        return eval("%d<=%d<=%d" %\
                   (self.policy.min_max.get("MinLocalDesirability", 0),\
                    path.get_local_desirability(),\
                    self.policy.min_max.get("MaxLocalDesirability", 100)))\
               and eval("%d<=%d<=%d" %\
                   (self.policy.min_max.get("MinPathLength", 0),\
                    path.get_path_length(),\
                    self.policy.min_max.get("MaxPathLength", 100)))\
               and eval("%d<=%d<=%d" %\
                   (self.policy.min_max.get("MinPathFreshness", 0),\
                    path.get_path_freshness(),\
                    self.policy.min_max.get("MaxPathFreshness", 100)))\
               and eval("%d<=%d<=%d" %\
                   (self.policy.min_max.get("MinGuaranteedBandwidth", 0),\
                    path.get_guaranteed_bandwidth(),\
                    self.policy.min_max.get("MaxGuaranteedBandwidth", 100)))\
               and eval("%d<=%d<=%d" %\
                   (self.policy.min_max.get("MinAvailableBandwidth", 0),\
                    path.get_available_bandwidth(),\
                    self.policy.min_max.get("MaxAvailableBandwidth", 100)))\
               and eval("%d<=%d<=%d" %\
                   (self.policy.min_max.get("MinTotalBandwidth", 0),\
                    path.get_total_bandwidth(),\
                    self.policy.min_max.get("MaxTotalBandwidth", 100)))\
               and eval("%d<=%d<=%d" %\
                   (self.policy.min_max.get("MinDelay", 0),\
                    path.get_delay(),\
                    self.policy.min_max.get("MaxDelay", 100)))\
               and eval("%d<=%d<=%d" %\
                   (self.policy.min_max.get("MinSize", 0),\
                    path.get_size(),\
                    self.policy.min_max.get("MaxSize", 100)))

    def update_policy(self, policy_file):
        """
        Updates the policy in the path store. Also all paths' fidelity as a
        consequence.
        """
        self.policy = Policy(policy_file)
        for i in range(len(self.candidates)):
            self.candidates[i].set_fidelity(self.policy)
        self.candidates = sorted(self.candidates,\
                                 key=lambda PathInfo: PathInfo.fidelity,\
                                 reverse=True)

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
            ret = sorted(ret, key=lambda PathInfo: PathInfo.fidelity, \
                         reverse=True)
            ret = self._check_disjointness(ret)
            ret = ret[:k]
        return ret

    def _check_disjointness(self, paths):
        """
        Checks that the paths disjointness is below a certain level, which is
        stored in the policy.
        """
        #1 2 3 4 5, 1 2 6, 3 4 8, 1 5, !! 1 9 !!
        to_remove = []
        old_count = {}
        new_count = {}
        for autonomous_domain in paths[0].pcb.ads:
            old_count[autonomous_domain.pcbm.ad_id] = 1
            new_count[autonomous_domain.pcbm.ad_id] = 1
        for i in range(1, len(paths)):
            for autonomous_domain in paths[i].pcb.ads:
                if autonomous_domain.pcbm.ad_id in new_count.keys():
                    new_count[autonomous_domain.pcbm.ad_id] += 1
                else:
                    new_count[autonomous_domain.pcbm.ad_id] = 1
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


def main():
    """
    Main function.
    """
    if len(sys.argv) < 2:
        print("Usage: %s <pathstore_config_file>" % sys.argv[0])
        sys.exit()
    path_store = PathStore(sys.argv[1])
    # Add 5 paths (2 are inserted twice)
    pcb = PCB(b'\x80\x86\xf5\x01\x00\x02\x00\x00\xff\x00\x00\x00\x00\x1a\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01 \x00\x00\x00\x00\x0c\x00;\xd83\x01\x00\x02\x02\x00\x00\x00\x00}\xbe$q+\xd7\xfd\xadS\xd8\x87\xc68\xd6\x0c\xef#\x92$\x00\xf8\xcd\xb4\xf2\xe3y\n\xb0\xde\x05mQ\xc4\x00\xd1\xb7E\tQ\xc1\xea\x9fe\xfd"\xf3\'\xc3E\xa1\xdf\x8a1\x94\xe1\x88i\xe9\xa5\xa5\xc4B\xa7w\xc8-\xd2\x8bM\x99\x8eNLA^wv\xd8t\xf3~\xfb\x9d\xafs5\x17\xc5\x05e|\xdc(:\x03\'<\x13\xa3D\x9d\x89\x06 \xa3\xee\xedT}\x9f\xb9X\xb6\xadm\x85\xf3\x0b\x95h\xa4\x82x\x8eXV3\x07D\ng\x94\xa9*|\xb6\xd8p!\xbf\xf2\xdc\xc3\xae\rC\xfa\xdaA\xc1\xd3\x10\x9fp\xe2\xebN~\x8d,\xf8\xb2\xb0\xbc\x84\x8b\xd5*\x83\xc7\xd0K\x89\xb6\xb3T\xcd\xe6\xaag\xff\xf9\x16\x0b\xd0{&\xc0\xe9\x90/\xb1\xe8\x81C\xab\xe9\xcd\xf7\xb4\xae\xc3\xb1\x8c\x8bS\xa5)b$\x08\xfd\x99\xde\x99W\xfc\x9et\xa6\x92\xb3Y\x08\xc5r\x03f\xcf\\\x86oM\xe1w0s\x99\x8c\x0f\xd5\xd0\xd9\x89,\xe2z,\x11\xa3-;\x01\xa4\\\xa3\x02\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x018\x00\x00\x15\x00\x1a\x00\xb0\x9b\xd2\x01\x00\x02\x02\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x17\x00 \x00\xae\xa5\xc1\x01\x00\x00\x00\x00\x00\x00\x00]<*l`L~\x0f\xac\x10\xbbN7g\xb1\\\r\xbcHh\xbc\xaa)\x8bPyB\x8c(\x8c\x19\xa8\xd3(\xb1O\xbfMP\xd3`Z\x184\x7fV\x96\x15M\x06 T\xaa\xe59\xc2\xc4\xb7\xdb\x92\xc7=\xee\'\xf0\x98\xe3\xa73|\xdd\xbf\xed\x86\xb14lgX\x89\x80\xc4\xee\xd4\x839\x85-\xef8\x84\x7f\x9ds\xe4\x876c\xf5\xda\xc6\x81\xe3\xaa\x9f\xf0R?_r\x08\r\xdb)\x14\x9d]\xb1)\n\x9b\xa9\xdeTr\xa4a\xfc\xcb,ZK\xaf@\x91\x8b\xde\xf3\xc3/`\x8e\xb6\xc6;\xadA\tO>@h\xd6\xbb\xe1\x87\xd86\xaa^\x81$\xf6E\xbe\x90\x1e\xadJ\xa1\x9d\x9b^9C\x86\xb1\xdf\x1f$q\x12R|\xaa\x012\xbf=\xe9\xb4\x9b\xfa\x87\x8c!::\xe7qI6\x9e!\x15>\x80\xca\x1d\xedH\xb10O\xf8\x07q\xf2\xacCY\xe0)\xc9v\x82\xc6\xd0\xcaK+R_p\x1a0\xa0\x0b9\x9c\xce\xf0u\xc4\x8d\x13I\x00\xdfA\xae\xe3{W\xcd\x1a')
    path_store.add_path(pcb)
    pcb = PCB(b'\x80\x84\xf5\x01\x00\x02\x00\x00\xff\x00\x00\x00\x00\x1a\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01 \x00\x00\x00\x00\x0c\x007\xd62\x01\x00\x02\x02\x00\x00\x00\x00\xa6\xb1\xf8\xe2\xe2\xe5\xebMw\xf5\xb1\x86Is\xb3D\xb0\x05\xb4\xf8c\x9e\\\xa9s_5CK<\x8c>\x18\x83\x8b\x06\xf2\x7f\xacFV\xd2M:Wr7=U\x8c\x87\x86\xe4\xd3\xc6\x91\xe2%\x14\x95\xe2\x1cQ\x06[u\x88\xc3c9}\x0c[,\x7f\xa5\xf4E\xde9\xd5\xc5\x1f;\xdav\x82\x19L\xb8>\xc3\x83\xa7\xc6/\x8db\x05\x8aW!m\x87R\x10K\xe9\x89!Y\xa3Z7&\x11\xa3\xd3\x98\'\x81l\x05\x07S\xdf\x14\xcdY\xcc\x98\xbe#\x93\xf7\xd4p\x98\xa2\xc00\xf73\x0f\x15\xb0LqJ\xcfU\x87g:Z\x1c\x82\x8a\x853-\x1e*\xe4\xf5h~\xf5C#s\xfa\xe0\xeb\xf3\xe5\xdd[\xe6h\x14\x04\xcc\x13@\xd7\x8a\xc6\\]:f\x83\xaf\xc8y\xba\xd6\x7f2=\x8eh[\x86\x07\xb6<v$\xcdl<\x01\xbe\xc4\x89\xf2\xa3\t\xea\xf9A\x1a\x0c^\xa1\xffBf\xb5\xfb\x94\xf0\xc4g\xb0\x96I[\xf6K2\xf44WE\x1d%\xac|\xe3\x12\x11S\x0c\x02\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x018\x00\x00\x15\x00\x1a\x00_\x1b{\x01\x00\x02\x02\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x17\x00 \x00\x16\xa8D\x01\x00\x00\x00\x00\x00\x00\x00\xca\xcb~\xf8s\xcb\xb8\xe6\x82-*\xa4\xb7\xc8\xbc\x8b\xb9j\x00.X\x7f\xa9\x07\x8fR\xf4AYWru!s\x96\xdeA\xa0\xb8\xe9h1q\xad+J\xd8w\x11\xc7\xbb\xe1\x12\xa3\x98\x85d\xdf\xf1zA\x88\xb8X\xe0\xd8\xa0u\xad\xb3~\xcc\xc9\xdb_\\\x84z\xe9\xbd\x80\xd6\xffJ\'\x01\x0bz\x8f\x07\xf6\xc7\xb0Z\x1d7\xa8$\x94\x0b%\x9d\xf0\x9a/\xd31\xd3t\\\xf0\x89a\xa9<94\xc9\xf3\xe3\xb9\t\xd8Z\xbd\x84P\xc9il\xd8=m\xf5\xcd$<\xb9}"\xc6AK\xd1\xb4\xd1\xa7\xa1l\x1a\xe8\xb8 \xe6\xb4m\xca\xf4\xad\x04[\x86l\xbd\xaa\x94&\xc3\xb19\x95\xdc\xfe[b\xcf!\x83dG\x9c\xda\r+{\xc1\xf1\x8a\xf2\xeb\xf1\xa4\xa3\xa2\x95\x83\xd0\xf9\xf6\x97\xb6\x8an(\'6~\xfe\xf0\xef\xf3m\x88\x81\xc2\x1dK\x83\x18\xad\xb3\x9f\x01\x84\x1c\xcf\x83\xed\xb3\xd4}s\xf1\xafPQ1\x07C\xd4w\xb0\x81\x8b\xa5\xf4I\xe4L\x96\xadz\xban\xb8\xad')
    path_store.add_path(pcb)
    pcb = PCB(b'\x80\x86\xf5\x01\x00\x02\x00\x00\xff\x00\x00\x00\x00\x1a\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01 \x00\x00\x00\x00\x0c\x00;\xd83\x01\x00\x02\x02\x00\x00\x00\x00}\xbe$q+\xd7\xfd\xadS\xd8\x87\xc68\xd6\x0c\xef#\x92$\x00\xf8\xcd\xb4\xf2\xe3y\n\xb0\xde\x05mQ\xc4\x00\xd1\xb7E\tQ\xc1\xea\x9fe\xfd"\xf3\'\xc3E\xa1\xdf\x8a1\x94\xe1\x88i\xe9\xa5\xa5\xc4B\xa7w\xc8-\xd2\x8bM\x99\x8eNLA^wv\xd8t\xf3~\xfb\x9d\xafs5\x17\xc5\x05e|\xdc(:\x03\'<\x13\xa3D\x9d\x89\x06 \xa3\xee\xedT}\x9f\xb9X\xb6\xadm\x85\xf3\x0b\x95h\xa4\x82x\x8eXV3\x07D\ng\x94\xa9*|\xb6\xd8p!\xbf\xf2\xdc\xc3\xae\rC\xfa\xdaA\xc1\xd3\x10\x9fp\xe2\xebN~\x8d,\xf8\xb2\xb0\xbc\x84\x8b\xd5*\x83\xc7\xd0K\x89\xb6\xb3T\xcd\xe6\xaag\xff\xf9\x16\x0b\xd0{&\xc0\xe9\x90/\xb1\xe8\x81C\xab\xe9\xcd\xf7\xb4\xae\xc3\xb1\x8c\x8bS\xa5)b$\x08\xfd\x99\xde\x99W\xfc\x9et\xa6\x92\xb3Y\x08\xc5r\x03f\xcf\\\x86oM\xe1w0s\x99\x8c\x0f\xd5\xd0\xd9\x89,\xe2z,\x11\xa3-;\x01\xa4\\\xa3\x02\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x018\x00\x00\x15\x00\x1a\x00\xb0\x9b\xd2\x01\x00\x02\x02\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x17\x00 \x00\xae\xa5\xc1\x01\x00\x00\x00\x00\x00\x00\x00]<*l`L~\x0f\xac\x10\xbbN7g\xb1\\\r\xbcHh\xbc\xaa)\x8bPyB\x8c(\x8c\x19\xa8\xd3(\xb1O\xbfMP\xd3`Z\x184\x7fV\x96\x15M\x06 T\xaa\xe59\xc2\xc4\xb7\xdb\x92\xc7=\xee\'\xf0\x98\xe3\xa73|\xdd\xbf\xed\x86\xb14lgX\x89\x80\xc4\xee\xd4\x839\x85-\xef8\x84\x7f\x9ds\xe4\x876c\xf5\xda\xc6\x81\xe3\xaa\x9f\xf0R?_r\x08\r\xdb)\x14\x9d]\xb1)\n\x9b\xa9\xdeTr\xa4a\xfc\xcb,ZK\xaf@\x91\x8b\xde\xf3\xc3/`\x8e\xb6\xc6;\xadA\tO>@h\xd6\xbb\xe1\x87\xd86\xaa^\x81$\xf6E\xbe\x90\x1e\xadJ\xa1\x9d\x9b^9C\x86\xb1\xdf\x1f$q\x12R|\xaa\x012\xbf=\xe9\xb4\x9b\xfa\x87\x8c!::\xe7qI6\x9e!\x15>\x80\xca\x1d\xedH\xb10O\xf8\x07q\xf2\xacCY\xe0)\xc9v\x82\xc6\xd0\xcaK+R_p\x1a0\xa0\x0b9\x9c\xce\xf0u\xc4\x8d\x13I\x00\xdfA\xae\xe3{W\xcd\x1a')
    path_store.add_path(pcb)
    pcb = PCB(b'\x80\x84\xf5\x01\x00\x02\x00\x00\xff\x00\x00\x00\x00\x1a\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01 \x00\x00\x00\x00\x0c\x007\xd62\x01\x00\x02\x02\x00\x00\x00\x00\xa6\xb1\xf8\xe2\xe2\xe5\xebMw\xf5\xb1\x86Is\xb3D\xb0\x05\xb4\xf8c\x9e\\\xa9s_5CK<\x8c>\x18\x83\x8b\x06\xf2\x7f\xacFV\xd2M:Wr7=U\x8c\x87\x86\xe4\xd3\xc6\x91\xe2%\x14\x95\xe2\x1cQ\x06[u\x88\xc3c9}\x0c[,\x7f\xa5\xf4E\xde9\xd5\xc5\x1f;\xdav\x82\x19L\xb8>\xc3\x83\xa7\xc6/\x8db\x05\x8aW!m\x87R\x10K\xe9\x89!Y\xa3Z7&\x11\xa3\xd3\x98\'\x81l\x05\x07S\xdf\x14\xcdY\xcc\x98\xbe#\x93\xf7\xd4p\x98\xa2\xc00\xf73\x0f\x15\xb0LqJ\xcfU\x87g:Z\x1c\x82\x8a\x853-\x1e*\xe4\xf5h~\xf5C#s\xfa\xe0\xeb\xf3\xe5\xdd[\xe6h\x14\x04\xcc\x13@\xd7\x8a\xc6\\]:f\x83\xaf\xc8y\xba\xd6\x7f2=\x8eh[\x86\x07\xb6<v$\xcdl<\x01\xbe\xc4\x89\xf2\xa3\t\xea\xf9A\x1a\x0c^\xa1\xffBf\xb5\xfb\x94\xf0\xc4g\xb0\x96I[\xf6K2\xf44WE\x1d%\xac|\xe3\x12\x11S\x0c\x02\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x018\x00\x00\x15\x00\x1a\x00_\x1b{\x01\x00\x02\x02\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x17\x00 \x00\x16\xa8D\x01\x00\x00\x00\x00\x00\x00\x00\xca\xcb~\xf8s\xcb\xb8\xe6\x82-*\xa4\xb7\xc8\xbc\x8b\xb9j\x00.X\x7f\xa9\x07\x8fR\xf4AYWru!s\x96\xdeA\xa0\xb8\xe9h1q\xad+J\xd8w\x11\xc7\xbb\xe1\x12\xa3\x98\x85d\xdf\xf1zA\x88\xb8X\xe0\xd8\xa0u\xad\xb3~\xcc\xc9\xdb_\\\x84z\xe9\xbd\x80\xd6\xffJ\'\x01\x0bz\x8f\x07\xf6\xc7\xb0Z\x1d7\xa8$\x94\x0b%\x9d\xf0\x9a/\xd31\xd3t\\\xf0\x89a\xa9<94\xc9\xf3\xe3\xb9\t\xd8Z\xbd\x84P\xc9il\xd8=m\xf5\xcd$<\xb9}"\xc6AK\xd1\xb4\xd1\xa7\xa1l\x1a\xe8\xb8 \xe6\xb4m\xca\xf4\xad\x04[\x86l\xbd\xaa\x94&\xc3\xb19\x95\xdc\xfe[b\xcf!\x83dG\x9c\xda\r+{\xc1\xf1\x8a\xf2\xeb\xf1\xa4\xa3\xa2\x95\x83\xd0\xf9\xf6\x97\xb6\x8an(\'6~\xfe\xf0\xef\xf3m\x88\x81\xc2\x1dK\x83\x18\xad\xb3\x9f\x01\x84\x1c\xcf\x83\xed\xb3\xd4}s\xf1\xafPQ1\x07C\xd4w\xb0\x81\x8b\xa5\xf4I\xe4L\x96\xadz\xban\xb8\xad')
    path_store.add_path(pcb)
    pcb = PCB(b"\x80\x83\xf5\x01\x00\x02\x00\x00\xff\x00\x00\x00\x00\x1a\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01 \x00\x00\x00\x00\x0c\x00(>\xda\x01\x00\x02\x02\x00\x00\x00\x00\xac\xc0\x1c\xe6% ?,(\x15\x89\x0b\x14\xac\xe3\xf8(t}\xb8\xe0\xc4\xea\x15\\\xf5`x=\xea7N\xab\xd6%:N\xa3\xb9\xad\xbc\xa7a\xf4\xba\xa1\xafi\x8d\xfe\x9d\xec\xe0\xe6\xaf\xdf\x0b\x88\x1e\xd8\x96\x15\xaf\xfco.\x1a\xb5\\\x03\xbc\xad\x88=<\x1cfQ1\xa9\x1b|\x80\xe3\x88\x10GZn\xefB\x04\xa7\xbeO..tH\xc6#\xd7\xb8L}\x89\xa9\x9e\xd4}\xf9\x9d\xd3\x85\x06P\xee\xb0\x17\x84w\x06K.\x1e\x95\x8ea0.\xb5\x00ov\xfeM\xbf\r\xf1\x9e\x19y\n\xc1@\xd6\xbf\xeb\xcc\xa7\xcb\xf8\x82fSdR\x02r\xf1\xce\x87Z\x9f!ae\xf7\x19\x7f\xb5\x1c\x9di\x13\x0e]\xe3\x98wr\x8eP\x9dX\xa5\x89\xbe\x86\xeb\x16\xd0=\xb9\x8ex3h\xc9\x1f\x87l*F)\xd4\xc7\n\\9S\xbb+r\xd9\xc5\xca\xebl\xdc\xef\xfd\x91t\xc7X\xd8\x1e,\x86\xdbN\x9fl\xd7\xb4\xa6\xc9\xcf0\xbb\xbdZ\xadLV\x14\xa4\x83m^'\xfc\\`)\x02\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x018\x00\x00\x15\x00\x1a\x00\xa5P\x93\x01\x00\x02\x02\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x17\x00 \x00\xf5?\x8f\x01\x00\x00\x00\x00\x00\x00\x00\x9c\xa2w?4\x1b\xc6\xa1\xe5\x86/\x82\x00\x9f\xa9\x80\x18{\xd0\x1bJ\xb8\xa4Z\xbfA\xc8\xe9'\x1dI\xe2\x1dK-\x82\xb7e\xf5\xcar\x9ag\x00Qt\xd8\x8c\xa4C\x8fWc\xad[\x85\xd2 C\xdf\xfe:\xb68C3LJ\x0cP\xc2\x0b\xb0\xc4\x8e\xa6:#X6w\x11N\r\xddR\x86U\xa7\x13\xdb\xf7-r,><]\xe2m\x19\x94\x82~]\x86\xb1\xbeBDW{K\xce\x83\x07L\xbbP\x8b6\x19Wt\x9f.z\x80\x18\x07\xf8*x\x89ed\xc2\xc4-\x8f]\xa3\x8ds\x911\x9dI)P\xd36EPD\xaa\xd8\xf8\xed\xa8\xcc\xa7\x9b\x9e\xc3\x01\xe3@\xadNWh\x89\xcc\xa8\x18\x99#:\xcc8\x94\x9bC\xf7L\xfbi]s\x1c\xb6>\xb6N\x08\xfd\x86\xe6,\x16~y\xd6\x97\xb1\x15\xc4\x96\xe2wb?\x12-\x9a\xd0\xfc\x9f\xc9\xdf^\x02T\x8c\x14\xad\xd2\x0c\x94u\x17\xbco\xbf\x17\xb0\xa6\xech\x99-\xe1\xdbP93b\xf3\x07\r\x13?\x12\xf00")
    path_store.add_path(pcb)
    pcb = PCB(b'\x80\x82\xf5\x01\x00\x02\x00\x00\xff\x00\x00\x00\x00\x1a\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01 \x00\x00\x00\x00\x0c\x00\xa20\x9d\x01\x00\x02\x02\x00\x00\x00\x00r"\xe0\xa8,\x1e>\xe6"\x81\x13(\x07\xcd\xd0\x1b\xe0gv$\x9aA\r\x89-~O\xf3\xfc07\\X\xb6\xb5\xb0\x7fN2l\xe0M\r~\xe9z:q69\xc1\xac\x96\xf8S\xa6\x8a\xe60!Fu3\xc9\xab\x9c{q\xce%\xf4\xf0\xd1\x00v\x7fA\x89\xe2\xb662\x9b<\x16Ew\xb4*uK+\x0f\xa0N\x8a\xce\xe9\xa9BY\xa0\x95E\x1b\xd2\xa1\xd9:\xf5T\x92M\x1d\xee\x02,\xfd\x05\xc4\xc3\xf0\xb4q\xf3\xa6B\xc7\x99d.;\xbc\xce,\x05\xbd\xfd\xd8K\x1d\ry\xeb\x9a\x84\xf0|\xaa\xbf\x90<]\xd62\xef\x9bqV\xdfRp\xcf>\xc7%\xaa\x14\xe3\x8d\xb4r\x95<\xfa\x8b\x82\x98\xdf\xd2G\xcd8\xdaW,#\x8c\x81\xc6\x7f\x12_\xc3-\xec\x82\xa9\xe0j\xd8\xfb\xc3!\xf8\xbbW\xf9^\xa9\xd8\x1ej\x1c\x16\xe5+\x06H&\xbc@\xc2\x87O+|\xe0V}=K\xf4x\xb1\x13\xd2\xf5\x9f\x16nU\x82,*lVpB\xf8\x8b\xb4K\xbb\x9a\xed\x02\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x018\x00\x00\x15\x00\x1a\x00\xd4\xf8\x0e\x01\x00\x02\x02\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x17\x00 \x00w\xccs\x01\x00\x00\x00\x00\x00\x00\x00`\xaaaw\xa3>\xdc\xb7\xd4;?}[\x8b\xdc\xec!yv4\xf2\x17&\xb9w\xb6\xfa\x7f\xe1\x98\x9a\x16D\xaa\xc5\x15\x92h\x1ds+\xb6\x95\x8c\xde\xd83Q\xcdj\x8a\x1f("n3\x94v\x08\xc3\xb0\xecM\x11\xc3\xd1\xe5\xdfd\xa6\xd0\xc5\x9d\x16\xb4\xe2u\x12\xc5\x82\xea+\x98W\x9c\xb5\x98\xfak?V\xce\x08\xa2\x10\xec\xf4\xc3\xba(Zzf_\xd7\r!\xc4\xfb\xa7\x91a\x85j\x9d\xa7m\x99x\x11\xa8W\xa9Lo\xe22\xec\x15\x10\xb6\xb9\xde\xd0\xc4s\xe5\xb1\xeb\xbfi\xa3r@0\x1f\'=\x91)\xf6\n\xe6\xc6~i\xa3\xf1\xad\xeb\xc4\xc9M\xd7\x1a\xdc\xa5\x12u\xfc0\x9a\xc7\xca\xbf\x1d\xff\x10\xff\xde\xca\x9cl\x95!e.#\xfb\x8b\x8e\xf9_\x85g\xf2\x18\xe2"\xac[\x9a\x19\x8d*\'\x01\x12\x01b\x02I\x1a\xb3\x81\x06\xca}\xddX\x933\x7f\x8fp\x0f\xba\x86U\x1e\xb0I\xb8\xa9\xcd3U\x0b\xbd\x1b+$\xa3P\x04\x8a\\,\xe1\xb1\xfb\x944w\xdfI')
    path_store.add_path(pcb)
    pcb = PCB(b'\x80\x81\xf5\x01\x00\x02\x00\x00\xff\x00\x00\x00\x00\x1a\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01 \x00\x00\x00\x00\x0c\x00\x94\xb1\xbb\x01\x00\x02\x02\x00\x00\x00\x00\xa7!9i\xb4\xfeh\x8c\xb1gc\xe1\xb5\x1e\xc9\t\xac\xc4\x1a\xcf\xa5w\x0f\xbe\xa6\xba%:\xc5<\xe79\xff\xd8%N-\xdb\xf4\x0bdUb\x0e\xff\xca\xb0\x8a\x0b<\xcb\xe7m\xd2\xc1G\x16B\xe4\x82\xb1\x9f\xca\x00\x06\xfa\xf2\xc0R|\\\xa7\xd2\x13\x91\x1d\x92DX\xa9NS\xf7^[\xff\x83\xce\x1d\xb6D\xc8\xa5\xef\x0b\xa7\xebS\xd7\x02\x8e\xef\x14\x0e\x14\x06\\\x9cf\xa2JSo\xf7\x1a\xee\xf4\xe1l\xdfq\xde\xe4\xfcj<\xd2\x95\x8f\x87\x93\xb6\xbd\x1dJ\x1b\xc1\xed\x84\xf4\xd7\xa6\x05\xb6\xf2q\xf6\xf1!\xec\xd7Q\xd2G\x1a\x17\\\xf5\x19\x83\xb3\x0b\xcd\x0eH^O\xffj\xb7\xc9\x9cO\x195/Pb\xf7p\xc8\x08M\xc9OE\x9d\xc0\x91\xb6\xaf\x15\xd7~\xd3\x0e\x04i\xe3\xea\xfa\xb2\x8bt\xab\x04\xaa\xdb\x13\xa37FbS\x9d\x87*\xc8\xeb\xb1\xe5;\xeb\xc4\x0b\xad\x91\x06\xd6`\x83\xfd\xe1\x06\x85\xcc\xc6\xad\xce\x08\x18\xb0td)N\xec\x94\xb2\xdd\xfed1T\xa2\xce\x02\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x018\x00\x00\x15\x00\x1a\x00\xb7x\\\x01\x00\x02\x02\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x17\x00 \x00#\x10B\x01\x00\x00\x00\x00\x00\x00\x00\x85\xf7\x86]\x0f7\xd1K\x89\x83\x0e\x02\xbe\xe2\x9c5\xdf\xc9\x1e\xcdi\n)`6I2c\x07\x03\xa5>A\x8e\xa4p^\xdd\r\xc1\xa6]\x9e\xe3\xaa\xab\x15\x0c\xdb\xb6\xae/^{\xe9ONxk\xb0\x89\x1d\xa5\xeb\x164\x91\x88\x9f\x1cB\x97\x7fa@4h|\x95\x93w\xd9\xd9+\xb6\xe2C?\xee\xba\xd8_\xc9-\xa39\xcc\x0ci\x8c\xcf\x83\xe1\xc3\xcc\x07\x94p@\x1c\x13\xa3\xcb\xf3>\xed,\xe2\x93\xfd\x1af6\x14gr\xc6z>\xb0\xd1\x9dv\xb1&\xaeA\xd2\xd6<s\x83\xa6\x1d\xf3\xfc\xf7u\x8f\x92\x93\xda\xceg\xf7xS\xb1\xd4z\xf4\xfcK=)\xfbti\x12\x8f\xbc\xb9bu\x8bw\xc0\xe6\xe2\xfb\x02\xcdP9\x14I&n\x0e\x05\x1d\x84g\xb7%\x82@</\x8b2\x0f\x97\xd0\x9b\xac\xc9E0\xd8?\xbd\x83z\x87\xf3P]\xd0%\xa4\xc3\xf1%\xf5\x0fQ\rLk\xbf\xdd\x94\xa5V\xed\xf9\xfc\xf9lU\xa5%\xc5\xd2\x16\xcfU*\xfc\x8eo!\x8b\xb7g')
    path_store.add_path(pcb)
    print(str(path_store), "\n\n")
    path_store.update_policy(sys.argv[1])
    print(str(path_store), "\n\n")
    path_store.store_selection()
    bests = path_store.get_paths()
    for best in bests:
        print(str(best))

if __name__ == "__main__":
    main()
