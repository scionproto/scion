# Copyright 2016 ETH Zurich
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
:mod:`scion_socket_knowledge_base` --- Stats for SCION Multi-Path Socket
========================================================================
"""

# Stdlib
import logging
import time
import threading

# SCION
from endhost.kbase_lookup_service import KnowledgeBaseLookupService
from lib.thread import thread_safety_net


STATS_PERIOD = 5  # seconds
SOC2REQ = {}  # Map socket objects to HTTP requests (method, path)


class SocketKnowledgeBase(object):
    """
    This class keeps statistics about connections on SCION Multi-path sockets.
    It internally keeps a HashSet of the sockets and queries them periodically,
    recording the stats in a dictionary.
    """

    def __init__(self, topo_file, loc_file, src_ia, target_ia):
        """
        Creates an instance of the knowledge base class.
        """
        self.active_sockets = set()
        self.kbase = {}  # HTTP Req (method, path) to stats (ScionStats)
        self.isd_whitelist = []  # ISDs to whitelist.
        self.source_ISD_AS = src_ia
        self.target_ISD_AS = target_ia
        self.lock = threading.Lock()
        self.gatherer = threading.Thread(
            target=thread_safety_net,
            args=(self._collect_stats,),
            name="stats",
            daemon=True)
        self.gatherer.start()
        self.lookup_service = KnowledgeBaseLookupService(
            self, topo_file, loc_file)

    def add_socket(self, soc, method, path):
        """
        Adds a socket to the knowledge-base to query for stats.
        :param soc: The socket for which the stats gathering should be done.
        :type soc: SCION-socket
        :param method: HTTP method that soc is performing.
        :type method: String
        :param path: Path section of the HTTP Request that soc is performing.
        :type path: String
        """
        logging.debug("Adding a socket to knowledge-base")
        self.lock.acquire()
        SOC2REQ[soc] = (method, path)
        self.active_sockets.add(soc)
        self.lock.release()

    def remove_socket(self, soc):
        """
        Removes a socket from the knowledge-base.
        :param soc: The socket to be removed from stats gathering.
        :type soc: SCION-socket
        """
        self.lock.acquire()
        if soc in self.active_sockets:
            logging.debug("Removing a socket from knowledge-base")
            self.update_single_stat(soc)
            self.active_sockets.remove(soc)
            del SOC2REQ[soc]
        self.lock.release()

    def lookup(self, req_type, res_name):
        """
        Look up and return the stats of a given HTTP request specified
        by the req_type and the resource name.
        :param req_type: HTTP req_type
        :type req_type: String
        :param res_name: The resource name.
        :type res_name: String
        :returns: Dictionary of (req_type, res_name) -> ScionStats
        :rtype: dict
        """
        if (req_type, res_name) in self.kbase:
            return self.kbase[(req_type, res_name)].to_dict()
        else:
            return {}

    def list(self):
        """
        List the current contents of the knowledge-base.
        :returns: List of tuples
        :rtype: list
        """
        return list(self.kbase.keys())

    def set_ISD_whitelist(self, isds):
        """
        Setter function for the ISD_whitelist class member.
        :param isds: List of ISDs to be whitelisted.
        :type isd: list
        """
        if len(isds) > 10:
            logging.error("Invalid arg to set_ISD_whitelist.: %s", isds)
            return {'STATUS': 'INVALID_ISD_WHITELIST'}
        self.isd_whitelist = isds
        logging.info("ISD whitelist set: %s", self.isd_whitelist)
        return {'STATUS': 'OK'}

    def get_ISD_whitelist(self):
        """
        Getter function for isd_whitelist class member.
        :returns Whitelisted ISDs.
        :type isd: list
        """
        return self.isd_whitelist

    def update_single_stat(self, soc):
        """
        Updates the stats of a single socket.
        :param soc: The socket for which the stats should be updated.
        :type soc: SCION-socket
        """
        if soc.is_alive():
            new_stats = soc.get_stats()
            if new_stats is not None:
                method, path = SOC2REQ[soc]
                self.kbase[(method, path)] = new_stats

    def _collect_stats(self):
        """
        Iterate through the list of all currently active sockets and call
        get_stats() on them.
        """
        while True:
            logging.debug("Socket stats:")
            self.lock.acquire()
            for s in self.active_sockets:
                self.update_single_stat(s)
            self.lock.release()

            for (req, stats) in self.kbase.items():
                logging.debug(str(req) + "\n" + str(stats)),

            time.sleep(STATS_PERIOD)
