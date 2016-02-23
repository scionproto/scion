#!/usr/bin/python3
# Copyright 2015 ETH Zurich
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
:mod:`ssp_cli_srv_test` --- A client-server test using SCION Sockets
======================================================================

Running this test has the following requirements:

1) SCION infrastructure should already be running:
From the SCION root directory, run:
./scion.sh run

2) SCION socket library must be built:
From the SCION root directory, run:
./scion.sh sock_bld

3) SCION socket dispatchers for both client and server should be running:
From the SCION root directory in two separate terminals, run:
./scion.sh sock_ser
and
./scion.sh sock_cli
"""

# Stdlib
import hashlib
import logging
import os
import struct
import threading
import time

# SCION
from endhost.scion_socket import ScionServerSocket, ScionClientSocket
from lib.defines import L4_SSP
from lib.log import init_logging
from lib.main import main_wrapper
from lib.packet.scion_addr import ISD_AS
from lib.thread import thread_safety_net
from lib.util import handle_signals

SERVER_PORT = 8080
SERVER_LOG_BASE = 'logs/scion_test_app'
SERVER_IP = "127.2.26.254"
# TODO(ercanucan): Increase this value as the library matures.
DATA_SIZE = 200 * 1024
DIGEST_LEN = 16
TIMEOUT = 60  # How long to wait for hanging threads.


def main():
    init_logging(SERVER_LOG_BASE,
                 file_level=logging.DEBUG, console_level=logging.DEBUG)
    handle_signals()
    server_thread = threading.Thread(target=thread_safety_net, args=(server,),
                                     name="server", daemon=True)
    client_thread = threading.Thread(target=thread_safety_net, args=(client,),
                                     name="client", daemon=True)
    server_thread.start()
    client_thread.start()

    for _ in range(TIMEOUT * 10):
        time.sleep(0.1)
        if not server_thread.is_alive() and not client_thread.is_alive():
            break
    else:
        logging.error("Test timed out.")


def server():
    logging.info("Starting SCION test server application.")
    sock = ScionServerSocket(L4_SSP, SERVER_PORT)

    (server_sock, _) = sock.accept()

    logging.info("Server starts the receive protocol.")
    # firstly, act as a receiver
    _run_receive_protocol(server_sock)

    logging.info("Server starts the send protocol.")
    # secondly, act as a sender
    _run_send_protocol(server_sock)


def client():
    logging.info("Starting SCION test client application.")

    isd_as = ISD_AS.from_values(2, 26)

    target_addr = SERVER_IP, SERVER_PORT
    client_sock = ScionClientSocket(L4_SSP, isd_as, target_addr)

    logging.info("Client starts the send protocol.")
    # firstly, act as a sender
    _run_send_protocol(client_sock)

    # sanity check on get_stats function
    stats = client_sock.get_stats()
    if stats:
        logging.info("interfaces for path 0:")
        for i in range(stats.if_counts[0]):
            ifinfo = stats.if_lists[0][i]
            logging.info("%s %d", ifinfo.isd_as, ifinfo.ifid)

    logging.info("Client starts the receive protocol.")
    # secondly, act as a receiver
    _run_receive_protocol(client_sock)


def _run_send_protocol(sock):
    # generate the data
    msg = _generate_message(DATA_SIZE)
    # send the data length
    _send_data(sock, struct.pack("!I", DATA_SIZE))
    # send the data itself
    _send_data(sock, msg)
    # compute and send the digest
    m = hashlib.md5()
    m.update(msg)
    digest = m.digest()
    logging.info("Digest = %s" % digest)
    _send_data(sock, digest)

    # wait for the ack to finish transfer
    ack = sock.recv(1)
    logging.debug("Ack received = %s" % ack.decode('ascii'))
    logging.info("Finished send protocol successfully.")


def _run_receive_protocol(sock):
    # read the length of the data (assume 4B int)
    data_len = struct.unpack("!I", _receive_data(sock, 4))[0]
    logging.info("Data length is %d" % data_len)

    # read the data
    rcvd_data = _receive_data(sock, data_len)
    logging.info("Received all the data.")

    # read the digest (assume DIGEST_LEN)
    rcvd_digest = _receive_data(sock, DIGEST_LEN)
    logging.info("Received the digest.")

    logging.info("Marking the receive protocol, sending ACK.")
    sock.send(bytes("F", 'ascii'))

    _verify_test_data(rcvd_data, rcvd_digest)

    logging.info("Finished receive protocol successfully.")


def _generate_message(size):
    return os.urandom(size)


def _send_data(sock, msg):
    logging.debug("Sending Data.")
    num_bytes_sent = sock.send(msg)
    if num_bytes_sent < 0:
        logging.error("Error during send on client socket")
        raise Exception("ScionSocket cannot send data.")


def _receive_data(sock, size):
    data_lst = []
    num_bytes_rcvd = 0
    while num_bytes_rcvd < size:
        data = sock.recv(size - num_bytes_rcvd)
        assert(data is not None)
        num_bytes_rcvd += len(data)
        data_lst.append(data)

    return b"".join(data_lst)


def _verify_test_data(data, rcvd_digest):
    m = hashlib.md5()
    m.update(data)
    assert(m.digest() == rcvd_digest)


if __name__ == "__main__":
    main_wrapper(main)
