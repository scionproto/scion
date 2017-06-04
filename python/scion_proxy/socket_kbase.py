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
from lib.thread import thread_safety_net
from scion_proxy.kbase_lookup_service import KnowledgeBaseLookupService


STATS_PERIOD = 5  # seconds
SOC2REQ = {}  # Map socket objects to HTTP requests (conn_id, method, path)
REQ2SOC = {}  # Map HTTP requests (conn_id, method, path) to socket


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
        self.kbase = {}  # Req (conn_id, method, path) to stats (ScionStats)
        self.isd_whitelist = []  # ISDs to whitelist.
        self.source_ISD_AS = src_ia
        self.target_ISD_AS = target_ia
        self.socket_list_lock = threading.Lock()
        self.kbase_lock = threading.Lock()
        self.gatherer = threading.Thread(
            target=thread_safety_net,
            args=(self._collect_stats,),
            name="stats",
            daemon=True)
        self.gatherer.start()
        self.lookup_service = KnowledgeBaseLookupService(
            self, topo_file, loc_file)

    def add_socket(self, soc, conn_id, method, path):
        """
        Adds a socket to the knowledge-base to query for stats.
        :param soc: The socket for which the stats gathering should be done.
        :type soc: SCION-socket
        :param method: HTTP method that soc is performing.
        :type method: String
        :param path: Path section of the HTTP Request that soc is performing.
        :type path: String
        """
        key = conn_id, method, path
        logging.info("Adding a socket to knowledge-base %s %s %s", *key)
        with self.socket_list_lock:
            SOC2REQ[soc] = key
            if key in REQ2SOC:
                logging.error("Request already in KBASE! %s %s %s", *key)
            REQ2SOC[key] = soc
            self.active_sockets.add(soc)

    def remove_socket(self, soc):
        """
        Removes a socket from the knowledge-base.
        :param soc: The socket to be removed from stats gathering.
        :type soc: SCIONSocket
        """
        with self.socket_list_lock:
            if soc in self.active_sockets:
                self.update_single_stat(soc)
                self.active_sockets.remove(soc)
                key = SOC2REQ[soc]
                logging.info("Removing a socket from mappings: %s %s %s", *key)
                del REQ2SOC[key]
                del SOC2REQ[soc]

    def lookup(self, conn_id, req_type, res_name):
        """
        Look up and return the stats of a given HTTP request specified
        by the req_type and the resource name.
        :param conn_id: Unique identifier of the connection/socket.
        :type conn_id: UUID String
        :param req_type: HTTP req_type
        :type req_type: String
        :param res_name: The resource name.
        :type res_name: String
        :returns: ScionStats object as a dict
        :rtype: dict
        """
        result = {}
        with self.kbase_lock:
            key = conn_id, req_type, res_name
            if key in self.kbase:
                result = self.kbase[key].to_dict()
        return result

    def list(self):
        """
        List the current contents of the knowledge-base.
        :returns: List of tuples
        :rtype: list
        """
        with self.kbase_lock:
            result = list(self.kbase.keys())
        return result

    def clear(self):
        """
        Clears the knowledge-base.
        """
        with self.kbase_lock:
            with self.socket_list_lock:
                for req_info in list(self.kbase):
                    # remove data of only the closed (inactive) sockets
                    if req_info not in REQ2SOC:
                        del self.kbase[req_info]

        logging.info("Stale entries in the knowledge-base cleared.")
        return {'STATUS': 'OK'}

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
                key = SOC2REQ[soc]
                with self.kbase_lock:
                    self.kbase[key] = new_stats

    def _collect_stats(self):
        """
        Iterate through the list of all currently active sockets and call
        get_stats() on them.
        """
        while True:
            logging.debug("Socket stats:")
            with self.socket_list_lock:
                logging.info("%s active sockets", len(self.active_sockets)),
                for s in self.active_sockets:
                    self.update_single_stat(s)

            with self.kbase_lock:
                for req in list(self.kbase):
                    logging.debug(str(req) + "\n" + str(self.kbase[req])),

            time.sleep(STATS_PERIOD)
