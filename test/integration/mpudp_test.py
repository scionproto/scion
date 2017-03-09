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
:mod:`mpudp_test` --- SCION libssock UDP tests
==============================================
"""
# Stdlib
import logging

# SCION
from endhost.scion_socket import ScionServerSocket, ScionClientSocket
from lib.main import main_wrapper
from lib.types import L4Proto
from test.integration.base_cli_srv import (
    setup_main,
    TestClientBase,
    TestClientServerBase,
    TestServerBase,
)


DATA_LEN = 1024


def pad_data(data):
    padding = DATA_LEN - len(data)
    return data + bytes(padding)


class MPUDPClient(TestClientBase):
    """
    Simple ping app.
    """
    def _create_socket(self, addr):
        sock = ScionClientSocket(L4Proto.UDP, bytes(self.api_addr, 'ascii'))
        if sock.bind(0, self.addr) < 0:
            return None
        sock.settimeout(self._timeout)
        return sock

    def _recv(self):
        return self.sock.recvfrom(DATA_LEN)[0]

    def _send_pkt(self, spkt, next_=None):
        self.sock.sendto(spkt, (self.dst, self.dport))

    def _build_pkt(self, path=None):
        return pad_data(b"ping " + self.data)

    def _handle_response(self, spkt):
        logging.debug("Received:\n%s", spkt)
        if len(spkt) != DATA_LEN:
            logging.error("Payload length (%sB) != DATA_LEN (%sB)",
                          len(spkt), DATA_LEN)
            return False
        pong = pad_data(b"pong " + self.data)
        if spkt == pong:
            logging.debug('%s: pong received.', self.addr.host)
            self.success = True
            self.finished.set()
            return True
        logging.error(
            "Unexpected payload:\n  Received (%dB): %s\n  "
            "Expected (%dB): %s", len(spkt), spkt, len(pong), pong)
        return False

    def _shutdown(self):
        self.sock.close()


class MPUDPServer(TestServerBase):
    """
    Simple pong app.
    """
    def _create_socket(self, addr):
        sock = ScionServerSocket(L4Proto.UDP, bytes(self.api_addr, 'ascii'))
        sock.settimeout(5.0)
        if sock.bind(0, self.addr) < 0:
            return None
        return sock

    def run(self):
        while not self.finished.is_set():
            data, self.sender = self._recv()
            if not self.sender or (data and not self._handle_request(data)):
                self.success = False
                self.finished.set()
        self._shutdown()

    def _recv(self):
        return self.sock.recvfrom(DATA_LEN)

    def _send_pkt(self, spkt, next_=None):
        self.sock.sendto(spkt, self.sender)

    def _build_pkt(self, path=None):
        return pad_data(b"pong " + self.data)

    def _handle_request(self, spkt):
        expected = b"ping " + self.data
        if not spkt.startswith(expected):
            return False
        # Send back "pong".
        logging.debug('%s: ping received, sending pong.', self.addr.host)
        self._send_pkt(self._build_pkt())
        self.success = True
        self.finished.set()
        return True

    def _shutdown(self):
        self.sock.close()


class TestMPUDP(TestClientServerBase):
    """
    End to end packet transmission test.
    For this test a infrastructure must be running.
    """
    NAME = "MPUDP"

    def _create_server(self, data, finished, addr):
        return MPUDPServer(self._run_sciond(addr), data, finished, addr)

    def _create_client(self, data, finished, src, dst, port):
        return MPUDPClient(self._run_sciond(src), data, finished, src, dst,
                           port)


def main():
    args, srcs, dsts = setup_main("mpudp")
    TestMPUDP(args.client, args.server, srcs, dsts, max_runs=args.runs).run()


if __name__ == "__main__":
    main_wrapper(main)
