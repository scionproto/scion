#!/usr/bin/python3
# Copyright 2014 ETH Zurich
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
:mod:`end2end_test` --- SCION end2end tests
===========================================
"""
# Stdlib
import logging

# SCION
from lib.main import main_wrapper
from lib.packet.packet_base import PayloadRaw
from lib.thread import kill_self
from lib.types import L4Proto
from test.integration.base_cli_srv import (
    setup_main,
    TestClientBase,
    TestClientServerBase,
    TestServerBase,
)


class E2EClient(TestClientBase):
    """
    Simple ping app.
    """
    def _create_payload(self, spkt):
        data = b"ping " + self.data
        pld_len = self.path.mtu - len(spkt)
        return self._gen_max_pld(data, pld_len)

    def _gen_max_pld(self, data, pld_len):
        padding = pld_len - len(data)
        return PayloadRaw(data + bytes(padding))

    def _handle_response(self, spkt):
        if spkt.l4_hdr.TYPE == L4Proto.SCMP:
            spkt.parse_payload()
        logging.debug("Received:\n%s", spkt)
        if spkt.l4_hdr.TYPE == L4Proto.SCMP:
            logging.error("Received SCMP error")
            kill_self()
            return
        if len(spkt) != self.path.mtu:
            logging.error("Packet length (%sB) != MTU (%sB)",
                          len(spkt), self.path.mtu)
            kill_self()
            return
        payload = spkt.get_payload()
        pong = self._gen_max_pld(b"pong " + self.data, len(payload))
        if payload == pong:
            logging.debug('%s:%d: pong received.', self.src.host,
                          self.sock.port)
            self.done = True
        else:
            logging.error(
                "Unexpected payload:\n  Received (%dB): %s\n  "
                "Expected (%dB): %s", len(payload), payload, len(pong), pong)
            kill_self()


class E2EServer(TestServerBase):
    """
    Simple pong app.
    """
    def _verify_request(self, payload):
        expected = b"ping " + self.data
        return payload.pack().startswith(expected)

    def _handle_request(self, spkt):
        # Reverse the packet and send "pong".
        logging.debug('%s:%d: ping received, sending pong.',
                      self.dst.host, self.sock.port)
        self.ping_received = True
        spkt.reverse()
        spkt.set_payload(self._create_payload(spkt))
        next_hop, port = self.sd.get_first_hop(spkt)
        assert next_hop is not None
        logging.debug("Replying with (via %s:%s):\n%s", next_hop, port, spkt)
        self.sd.send(spkt, next_hop, port)

    def _create_payload(self, spkt):
        old_pld = spkt.get_payload()
        data = b"pong " + self.data
        padding = len(old_pld) - len(data)
        return PayloadRaw(data + bytes(padding))


class TestEnd2End(TestClientServerBase):
    """
    End to end packet transmission test.
    For this test a infrastructure must be running.
    """
    def __init__(self, client, server, sources, destinations, local=True):
        super().__init__(client, server, sources, destinations)
        self.src = client
        self.dst = server
        self.client_name = "E2E Client"
        self.server_name = "E2E Server"
        self.thread_name = "E2E.MainThread"

    def _create_data(self):
        return ("%s<->%s" % (self.src, self.dst)).encode("UTF-8")

    def _create_server(self, addr, data):
        return E2EServer(addr, data)

    def _create_client(self, src, dst, port, data):
        return E2EClient(src, dst, port, data, True)


def main():
    args, srcs, dsts = setup_main()
    TestEnd2End(args.client, args.server, srcs, dsts).run()


if __name__ == "__main__":
    main_wrapper(main)
