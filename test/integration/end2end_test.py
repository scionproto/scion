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
from lib.packet.path_mgmt.rev_info import RevocationInfo
from lib.packet.scmp.types import SCMPClass, SCMPPathClass
from lib.types import L4Proto
from test.integration.base_cli_srv import (
    ResponseRV,
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
        pld_len = self.path.mtu - spkt.cmn_hdr.hdr_len - len(spkt.l4_hdr)
        return self._gen_max_pld(data, pld_len)

    def _gen_max_pld(self, data, pld_len):
        padding = pld_len - len(data)
        return PayloadRaw(data + bytes(padding))

    def _handle_response(self, spkt):
        if spkt.l4_hdr.TYPE == L4Proto.SCMP:
            return self._handle_scmp(spkt)
        logging.debug("Received:\n%s", spkt)
        if len(spkt) != self.path.mtu:
            logging.error("Packet length (%sB) != MTU (%sB)",
                          len(spkt), self.path.mtu)
            return ResponseRV.FAILURE
        payload = spkt.get_payload()
        pong = self._gen_max_pld(b"pong " + self.data, len(payload))
        if payload == pong:
            logging.debug('%s:%d: pong received.', self.addr.host,
                          self.sock.port)
            return ResponseRV.SUCCESS
        logging.error(
            "Unexpected payload:\n  Received (%dB): %s\n  "
            "Expected (%dB): %s", len(payload), payload, len(pong), pong)
        return False

    def _handle_scmp(self, spkt):
        scmp_hdr = spkt.l4_hdr
        spkt.parse_payload()
        if (scmp_hdr.class_ == SCMPClass.PATH and
                scmp_hdr.type == SCMPPathClass.REVOKED_IF):
            scmp_pld = spkt.get_payload()
            rev_info = RevocationInfo.from_raw(scmp_pld.info.rev_info)
            logging.info("Received revocation for IF %d." % rev_info.p.ifID)
            self.sd.handle_revocation(rev_info, None)
            return ResponseRV.RETRY
        else:
            logging.error("Received SCMP error:\n%s", spkt)
            return ResponseRV.FAILURE


class E2EServer(TestServerBase):
    """
    Simple pong app.
    """
    def _handle_request(self, spkt):
        expected = b"ping " + self.data
        raw_pld = spkt.get_payload().pack()
        if not raw_pld.startswith(expected):
            return False
        # Reverse the packet and send "pong".
        logging.debug('%s:%d: ping received, sending pong.',
                      self.addr.host, self.sock.port)
        spkt.reverse()
        spkt.set_payload(self._create_payload(spkt))
        self._send_pkt(spkt)
        self.success = True
        self.finished.set()
        return True

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
    NAME = "End2End"

    def _create_server(self, data, finished, addr):
        return E2EServer(self._run_sciond(addr), data, finished, addr)

    def _create_client(self, data, finished, src, dst, port):
        return E2EClient(self._run_sciond(src), data, finished, src, dst, port,
                         retries=self.retries)


def main():
    args, srcs, dsts = setup_main("end2end")
    TestEnd2End(args.client, args.server, srcs, dsts, max_runs=args.runs,
                retries=args.retries).run()


if __name__ == "__main__":
    main_wrapper(main)
