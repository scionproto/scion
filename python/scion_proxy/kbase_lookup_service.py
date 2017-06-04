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

# DISCLAIMER: This stats gathering service is currently used only as a
# demonstrative tool. If you wish to deploy and use this software in a
# production environment, then access control/authentication mechanisms
# must be implemented.

"""
:mod:`kbase_lookup_service` --- UDP Server to serve SCION socket stats
======================================================================
"""

# Stdlib
import json
import logging
import struct
import threading
import yaml


# SCION
from lib.socket import UDPSocket
from lib.thread import thread_safety_net
from lib.types import AddrType

SERVER_ADDRESS = '', 7777


class KnowledgeBaseLookupService(object):
    """
    This class starts up a UDP server which binds to SERVICE_PORT and
    responds to incoming UDP datagrams which contain lookup requests.
    It pulls the stats from SocketKnowledgeBase object which is also
    the creator of this object.
    """

    def __init__(self, kbase, topo_file, loc_file):
        """
        Creates and initializes an instance of the lookup service.
        :param kbase: Socket knowledge-base object.
        :type kbase: SocketKnowledgeBase
        """
        self.kbase = kbase
        self.topology_file = topo_file
        self.locations_file = loc_file
        # Create a UDP socket
        self.sock = UDPSocket(SERVER_ADDRESS, AddrType.IPV4)
        # Bind the socket to the port
        logging.debug("Socket stats service starting up on %s port %s",
                      SERVER_ADDRESS[0], SERVER_ADDRESS[1])
        # Print the disclaimer
        logging.info("DISCLAIMER: This stats gathering service is currently "
                     "used only as a demonstrative tool. If you wish to use "
                     "it in a production environment, then proper access "
                     "control mechanisms must be implemented.")
        self.service = threading.Thread(
            target=thread_safety_net,
            args=(self._run,),
            name="stats_lookup",
            daemon=True)
        self.service.start()

    def _run(self):
        """
        Serves the incoming requests serially, one by one.
        This can be parallelized in the future, currently there is no
        need to process parallel as only one browser extension
        will talk to this service and send requests one by one.
        """
        while True:
            try:
                self._serve_query()
            except OSError:
                break

    def _serve_query(self):
        """
        Reads and parses a query, looks it up and returns the result.
        """
        req_raw, addr = self._recv_data()
        if req_raw is None or len(req_raw) < 4 or addr is None:
            return
        req_len = struct.unpack("!I", req_raw[:4])[0]
        if req_len != len(req_raw[4:]):
            logging.error('Request length does not match the data length')
            return
        try:
            req_str = req_raw[4:].decode("utf-8")
            request = json.loads(req_str)
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            logging.error('Error decoding request: %s' % e)
            return

        logging.debug('Length of the request = %d' % req_len)
        logging.debug('Received request %s' % req_raw[4:4+req_len])
        assert(isinstance(request, dict))

        try:
            cmd = request['command']
        except KeyError as e:
            logging.error('Key error while parsing request: %s' % e)
            return
        assert(isinstance(cmd, str))

        if cmd == 'LIST':
            resp = self.kbase.list()
        elif cmd == 'LOOKUP':
            try:
                conn_id = request['conn_id']
                req_type = request['req_type']
                res_name = request['res_name']
            except KeyError as e:
                logging.error('Key error while parsing LOOKUP req: %s' % e)
                return
            assert(isinstance(req_type, str))
            resp = self.kbase.lookup(conn_id, req_type, res_name)
        elif cmd == 'CLEAR':
            resp = self.kbase.clear()
        elif cmd == 'TOPO':
            resp = self._get_topology()
        elif cmd == 'LOCATIONS':
            resp = self._get_locations()
        elif cmd == 'ISD_WHITELIST':
            try:
                isds = request['isds']
            except KeyError as e:
                logging.error('Key error in parsing ISD_WHITELIST req: %s' % e)
                return
            assert(isinstance(isds, list))
            resp = self._handle_set_ISD_whitelist(isds)
        elif cmd == 'GET_ISD_WHITELIST':
            resp = self._handle_get_ISD_whitelist()
        elif cmd == 'GET_ISD_ENDPOINTS':
            resp = self._handle_get_ISD_endpoints()
        else:
            logging.error('Unsupported command: %s', cmd)
            return

        assert((isinstance(resp, dict) or isinstance(resp, list)))
        self._send_response(resp, addr)

    def _recv_data(self):
        """
        Reads the data in from the socket.
        :returns:
            Tuple of (`bytes`, (`address`)) containing the data and
            remote address.
        """
        logging.debug('Waiting to receive the request length')
        try:
            req_raw, addr = self.sock.recv()
        except OSError as e:
            logging.error('Error while reading from socket: %s' % e)
            raise OSError("Can't read from the socket: It is dead.")
        logging.debug('Request = %s' % req_raw)
        return req_raw, addr

    def _send_response(self, resp, addr):
        """
        Encodes the response object (dict or list) into JSON and sends it to
        the given address
        :param resp: Response to be sent to the client.
        :type resp: dict or list
        :param addr: Address to send the response to.
        :type addr: AddrType.IPV4
        """
        # prepare the response
        result = []
        try:
            resp_str = json.dumps(resp)
            resp_bytes = resp_str.encode('utf-8')
        except ValueError as e:
            logging.error('Error while encoding JSON: %s' % e)
            return

        # the number of bytes contained in JSON response
        logging.debug("Response length is %d" % len(resp_bytes))
        resp_len = struct.pack("!I", len(resp_bytes))
        result.append(resp_len)
        result.append(resp_bytes)
        try:
            # send the response
            self.sock.send(b''.join(result), addr)
        except OSError as e:
            logging.error('Error while sending response: %s' % e)
            raise OSError("Can't write to the socket: It is dead.")

    def _get_topology(self):
        """
        Reads in the topology file and serves the relevant part of that
        to the visualization extension.
        :returns: A list of links extracted from the topology file.
        :rtype: list
        """
        with open(self.topology_file, 'r') as stream:
            try:
                topo_dict = yaml.load(stream)
                logging.debug('Topology: %s' % topo_dict)
                return topo_dict['links']
            except (yaml.YAMLError, KeyError) as e:
                logging.error('Error while reading the topology YAML: %s' % e)
                return []

    def _get_locations(self):
        """
        Reads in the default locations file and serves the relevant part of that
        to the visualization extension.
        :returns: A dictionary of AS Name to Country Code matching.
        :rtype: dict
        """
        with open(self.locations_file, 'r') as stream:
            try:
                locations_dict = yaml.load(stream)
                logging.debug('Locations: %s' % locations_dict)
                return locations_dict['locations']
            except (yaml.YAMLError, KeyError) as e:
                logging.error('Error while reading the locations YAML: %s' % e)
                return {}

    def _handle_set_ISD_whitelist(self, isds):
        """
        Lets the kbase know of which ISDs should be whitelisted.
        :param isds: List of ISDs (numbers)
        :type isds: list
        :returns: A dictionary indicating the result.
        :rtype: dict
        """
        return self.kbase.set_ISD_whitelist(isds)

    def _handle_get_ISD_whitelist(self):
        """
        Queries the kbase and returns which ISDs are whitelisted.
        :returns: A list (potentially empty) containing the whitelisted ISDs.
        :rtype: list
        """
        return self.kbase.get_ISD_whitelist()

    def _handle_get_ISD_endpoints(self):
        """
        Gets the source and target ISD end-points and returns them as a
        dictionary.
        :returns: a dictionary containing source_ISD_AS and target_ISD_AS
        :rtype: dict
        """
        result = {}
        result["source_ISD_AS"] = list(self.kbase.source_ISD_AS)
        result["target_ISD_AS"] = list(self.kbase.target_ISD_AS)
        return result
