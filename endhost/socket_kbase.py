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

    def __init__(self):
        """
        Creates an instance of the knowledge base class.
        """
        self.active_sockets = set()
        self.kbase = {}  # HTTP Req (method, path) to stats (ScionStats)
        self.lock = threading.Lock()
        self.gatherer = threading.Thread(
            target=thread_safety_net,
            args=(self._collect_stats,),
            name="stats",
            daemon=True)
        self.gatherer.start()
        self.lookup_service = KnowledgeBaseLookupService(self)

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

    def lookup(self, command, res_name):
        """
        Look up and return the stats of a given HTTP request specified
        by the command and the resource name.
        :param command: HTTP command
        :type command: String
        :param res_name: The resource name.
        :type res_name: String
        """
        if (command, res_name) in self.kbase:
            return self.kbase[(command, res_name)].to_dict()
        else:
            return {}

    def update_single_stat(self, soc):
        """
        Updates the stats of a single socket.
        :param soc: The socket for which the stats should be updated.
        :type soc: SCION-socket
        """
        if soc.is_alive():
            new_stats = soc.getStats()
            if new_stats is not None:
                method, path = SOC2REQ[soc]
                self.kbase[(method, path)] = new_stats

    def _collect_stats(self):
        """
        Iterate through the list of all currently active sockets and call
        getStats() on them.
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
