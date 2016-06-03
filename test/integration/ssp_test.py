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
:mod:`ssp_test` --- SCION SSP tests
===========================================
"""
# Stdlib
import logging
import random

# SCION
from endhost.scion_socket import ScionServerSocket, ScionClientSocket
from lib.main import main_wrapper
from lib.types import L4Proto, TestSDType
from test.integration.base_cli_srv import (
    setup_main,
    TestClientBase,
    TestClientServerBase,
    TestServerBase,
)


DATA_LEN = 2048


class SSPClient(TestClientBase):
    """
    Simple ping app.
    """
    def __init__(self, sd, data, finished, addr, dst, dport, api=True,
                 timeout=3.0, get_path=True):
        super().__init__(sd, data, finished, addr, dst, dport, api, timeout,
                         get_path)
        self.sock.bind(0, self.addr)
        self.sock.connect(self.dst, self.dport)

    def _create_socket(self, addr):
        sock = ScionClientSocket(L4Proto.SSP, bytes(self.sd.api_addr, 'ascii'))
        return sock

    def _recv(self):
        return self.sock.recv_all(DATA_LEN)

    def _send(self):
        self._send_pkt(self._build_pkt())

    def _send_pkt(self, spkt, next_=None):
        self.sock.send(spkt)

    def _build_pkt(self, path=None):
        data = b"ping " + self.data
        padding = DATA_LEN - len(data)
        return data + bytes(padding)

    def _handle_response(self, spkt):
        logging.debug("Received:\n%s", spkt)
        if len(spkt) != DATA_LEN:
            logging.error("Packet length (%sB) != DATA_LEN (%sB)",
                          len(spkt), DATA_LEN)
            return False
        pong = b"pong " + self.data
        padding = DATA_LEN - len(pong)
        pong += bytes(padding)
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
        self.sock.shutdown(0)
        while self.sock.recv(DATA_LEN):
            pass
        self.sock.close()


class SSPServer(TestServerBase):
    """
    Simple pong app.
    """
    def _create_socket(self, addr):
        sock = ScionServerSocket(L4Proto.SSP, bytes(self.sd.api_addr, 'ascii'))
        sock.bind(random.randint(1025, 65535), self.addr)
        sock.listen()
        return sock

    def run(self):
        self.new_sock = self.sock.accept()[0]
        while not self.finished.is_set():
            data = self._recv()
            if data and not self._handle_request(data):
                self.success = False
                self.finished.set()
        self._shutdown()

    def _recv(self):
        return self.new_sock.recv_all(DATA_LEN)

    def _send_pkt(self, spkt, next_=None):
        self.new_sock.send(spkt)

    def _build_pkt(self, path=None):
        data = b"pong " + self.data
        padding = DATA_LEN - len(data)
        return data + bytes(padding)

    def _handle_request(self, spkt):
        expected = b"ping " + self.data
        if not spkt.startswith(expected):
            return False
        # Reverse the packet and send "pong".
        logging.debug('%s: ping received, sending pong.', self.addr.host)
        self._send_pkt(self._build_pkt())
        self.success = True
        self.finished.set()
        return True

    def _shutdown(self):
        self.new_sock.shutdown(0)
        while self.new_sock.recv(DATA_LEN):
            pass
        self.new_sock.close()
        self.sock.close()


class TestSSP(TestClientServerBase):
    """
    End to end packet transmission test.
    For this test a infrastructure must be running.
    """
    NAME = "SSP"

    def _create_server(self, data, finished, addr):
        return SSPServer(self._run_sciond(addr, TestSDType.SERVER), data,
                         finished, addr)

    def _create_client(self, data, finished, src, dst, port):
        return SSPClient(self._run_sciond(src, TestSDType.CLIENT), data,
                         finished, src, dst, port, get_path=False)


def main():
    args, srcs, dsts = setup_main("ssp")
    TestSSP(args.client, args.server, srcs, dsts, local=False,
            max_runs=args.runs).run()


if __name__ == "__main__":
    main_wrapper(main)
