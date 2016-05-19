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
    res = test_list()
    test_lookup(res)
    test_topology_lookup()
    test_locations_lookup()
    test_set_ISD_whitelist()
    test_clear_ISD_whitelist()
    test_ISD_endpoints_lookup()
    test_clear_kbase()
    test_list()


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

    raw_resp = send_req_and_read_resp(sock, req)
    return extract_from_json(raw_resp)


def test_lookup(res):
    """
    Creates a sample look-up request, sends it to the UDP server and
    reads the response.
    """
    if res is None or len(res) == 0:
        return

    logging.info('Starting the look-up test')
    item = res[0]
    # Create a UDP socket
    sock = UDPSocket(None, AddrType.IPV4)

    req = {"version": "0.1",
           "command": "LOOKUP",
           "conn_id": item[0],
           "req_type": item[1],
           "res_name": item[2]}

    logging.info('Sending LOOKUP request %s', req)
    send_req_and_read_resp(sock, req)


def test_clear_kbase():
    """
    Creates a sample clear knowledge-base request, sends it to the
    UDP server and reads the response returned.
    """
    logging.info('Starting the clear test')
    # Open up a UDP socket
    sock = UDPSocket(None, AddrType.IPV4)

    req = {"version": "0.1",
           "command": "CLEAR"}

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


def test_set_ISD_whitelist():
    """
    Creates a ISD whitelist request, sends it to the UDP server.
    """

    logging.info('Starting the ISD whitelist test')
    # Create a UDP socket
    sock = UDPSocket(None, AddrType.IPV4)

    req = {"version": "0.1",
           "command": "ISD_WHITELIST",
           "isds": [1, 3]}

    send_req_and_read_resp(sock, req)
    raw_resp = get_ISD_whitelist()
    res = extract_from_json(raw_resp)
    assert(res == [1, 3])


def test_clear_ISD_whitelist():
    """
    Creates a ISD whitelist request, sends it to the UDP server.
    """

    logging.info('Starting the ISD whitelist test')
    # Create a UDP socket
    sock = UDPSocket(None, AddrType.IPV4)

    req = {"version": "0.1",
           "command": "ISD_WHITELIST",
           "isds": []}

    send_req_and_read_resp(sock, req)
    raw_resp = get_ISD_whitelist()
    res = extract_from_json(raw_resp)
    assert(res == [])


def get_ISD_whitelist():
    """
    Creates an ISD whitelist request, sends it to the UDP server.
    """

    logging.info('Starting the Get ISD whitelist test')
    # Create a UDP socket
    sock = UDPSocket(None, AddrType.IPV4)

    req = {"version": "0.1",
           "command": "GET_ISD_WHITELIST"}

    return send_req_and_read_resp(sock, req)


def test_ISD_endpoints_lookup():
    """
    Creates a get ISD end-points request, sends it to the
    UDP server and reads the response.
    """

    logging.info('Starting the get ISD end-points test')
    # Create a UDP socket
    sock = UDPSocket(None, AddrType.IPV4)

    req = {"version": "0.1",
           "command": "GET_ISD_ENDPOINTS"}

    send_req_and_read_resp(sock, req)


def extract_from_json(req_raw):
    """
    Extract a Python object from a raw JSON and return it.
    :param req_raw: Encoded JSON string
    :type req_raw: bytes
    :returns: A python object.
    :rtype: object
    """
    try:
        req_str = req_raw.decode("utf-8")
        obj = json.loads(req_str)
        return obj
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        logging.error('Error decoding request: %s' % e)
        return None


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

    return data_raw[4:4+data_len]


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
