#!/usr/bin/python3
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
:mod:`kbase_lookup_test` --- A test-client to query SCION kbase.
================================================================
"""

# Stdlib
import json
import logging
import struct


# SCION
from lib.log import init_logging
from lib.main import main_wrapper
from lib.socket import UDPSocket
from lib.types import AddrType
from lib.util import handle_signals


CLIENT_LOG_BASE = 'logs/scion_kbase_test_client'
SERVER_ADDRESS = "127.0.0.1", 7777


def main():
    init_logging(CLIENT_LOG_BASE,
                 file_level=logging.DEBUG, console_level=logging.DEBUG)
    handle_signals()
    test_list()
    test_lookup()
    test_topology_lookup()
    test_locations_lookup()
    test_stay_ISD()


def test_list():
    """
    Creates a sample list request, sends it to the UDP server and
    reads the response.
    """
    logging.info('Starting the list test')
    # Open up a UDP socket
    sock = UDPSocket(None, AddrType.IPV4)

    req = {"version": "0.1",
           "command": "LIST"}

    send_req_and_read_resp(sock, req)


def test_lookup():
    """
    Creates a sample look-up request, sends it to the UDP server and
    reads the response.
    """

    logging.info('Starting the look-up test')
    # Create a UDP socket
    sock = UDPSocket(None, AddrType.IPV4)

    req = {"version": "0.1",
           "command": "LOOKUP",
           "req_type": "CONNECT",
           "res_name": "api.github.com:443"}

    send_req_and_read_resp(sock, req)


def test_topology_lookup():
    """
    Creates a sample topology request, sends it to the UDP server
    and reads the response.
    """

    logging.info('Starting the topology request test')
    # Create a UDP socket
    sock = UDPSocket(None, AddrType.IPV4)

    req = {"version": "0.1",
           "command": "TOPO"}

    send_req_and_read_resp(sock, req)


def test_locations_lookup():
    """
    Creates a sample default locations request, sends it to the UDP
    server and reads the response.
    """

    logging.info('Starting the locations request test')
    # Create a UDP socket
    sock = UDPSocket(None, AddrType.IPV4)

    req = {"version": "0.1",
           "command": "LOCATIONS"}

    send_req_and_read_resp(sock, req)


def test_stay_ISD():
    """
    Creates a stay ISD request, sends it to the UDP server.
    """

    logging.info('Starting the stay ISD request test')
    # Create a UDP socket
    sock = UDPSocket(None, AddrType.IPV4)

    req = {"version": "0.1",
           "command": "STAY_ISD",
           "isd": 1}

    send_req_and_read_resp(sock, req)


def send_req_and_read_resp(sock, req):
    """
    Helper function to send the request via the socket to the UPD
    server and receive the response on the same socket.
    :param sock: UDP socket to use for sending the request
    :type sock: socket
    :param req: Request to send to the kbase look-up server
    :type req: dict
    """
    try:
        send(sock, req)

        # Receive the response (length + response body)
        logging.debug('Waiting to receive the response length')
        data_raw, server = sock.recv()
        data_len = struct.unpack("!I", data_raw[0:4])[0]
        logging.debug('Length of the response = %d' % data_len)

        # Unpack the response itself
        logging.debug('Response json')
        logging.debug('Received "%s"' % data_raw[4:4+data_len])

    finally:
        logging.debug('Closing socket')
        sock.close()


def send(sock, req):
    """
    Marshals and sends the request to the UDP server.
    :param sock: UDP socket to use for sending the request
    :type sock: socket
    :param req: Request to send to the kbase look-up server
    :type req: dict
    """
    req_json_bytes = json.dumps(req).encode('utf-8')
    req_to_send = []
    req_to_send.append(struct.pack("!I", len(req_json_bytes)))
    req_to_send.append(req_json_bytes)

    # Send the req length + request itself
    logging.debug('Sending "%s"' % req_json_bytes)
    sock.send(b''.join(req_to_send), SERVER_ADDRESS)


if __name__ == "__main__":
    main_wrapper(main)
