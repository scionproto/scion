#!/usr/bin/python3
# Copyright 2017 ETH Zurich
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
:mod:`scmp_auth_end2end_test` --- SCION SCMP Auth end2end tests
===========================================
"""
# Stdlib
import logging

import time

import lib.app.sciond as lib_sciond
from lib.drkey.auth_scmp.protocol import get_sciond_params, set_scmp_auth_mac, verify_scmp_packet
from lib.errors import SCIONVerificationError
from lib.main import main_wrapper
from lib.packet.packet_base import PayloadRaw
from lib.packet.path_mgmt.rev_info import RevocationInfo
from lib.packet.scion import build_base_hdrs, SCIONL4Packet
from lib.packet.scmp.types import SCMPClass, SCMPPathClass
from lib.packet.spse.scmp_auth.ext_drkey import SCMPAuthDRKeyDirections, SCMPAuthDRKeyExtn
from lib.thread import kill_self
from lib.types import L4Proto
from integration.base_cli_srv import (
    ResponseRV,
    setup_main,
    TestClientBase,
    TestClientServerBase,
    TestServerBase,
    API_TOUT
)


class E2EClient(TestClientBase):
    """
    Simple ping app.
    """
    def _build_pkt(self, path=None):
        cmn_hdr, addr_hdr = build_base_hdrs(self.dst, self.addr)
        l4_hdr = self._create_l4_hdr()
        extn = SCMPAuthDRKeyExtn.from_values(SCMPAuthDRKeyDirections.HOST_TO_HOST)
        if path is None:
            path = self.path_meta.fwd_path()
        spkt = SCIONL4Packet.from_values(
            cmn_hdr, addr_hdr, path, [extn], l4_hdr)
        spkt.set_payload(self._create_payload(spkt))
        spkt.update()
        drkey = _try_sciond_api(spkt, self._connector)
        set_scmp_auth_mac(spkt, drkey)
        return spkt

    def _create_payload(self, spkt):
        data = b"ping " + self.data
        pld_len = (self.path_meta.p.mtu - spkt.cmn_hdr.hdr_len -
                   len(spkt.l4_hdr) - len(spkt.ext_hdrs[0]))
        return self._gen_max_pld(data, pld_len)

    def _gen_max_pld(self, data, pld_len):
        padding = pld_len - len(data)
        return PayloadRaw(data + bytes(padding))

    def _handle_response(self, spkt):
        if spkt.l4_hdr.TYPE == L4Proto.SCMP:
            return self._handle_scmp(spkt)
        logging.debug("Received:\n%s", spkt)
        if len(spkt) != self.path_meta.p.mtu:
            logging.error("Packet length (%sB) != MTU (%sB)",
                          len(spkt), self.path_meta.p.mtu)
            return ResponseRV.FAILURE
        payload = spkt.get_payload()
        pong = self._gen_max_pld(b"pong " + self.data, len(payload))
        drkey = _try_sciond_api(spkt, self._connector)
        if payload == pong:
            logging.debug('%s:%d: pong received.', self.addr.host, self.sock.port)
            try:
                verify_scmp_packet(spkt, drkey)
            except SCIONVerificationError as e:
                logging.error("Verification failed: %s", e)
                return False
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
            lib_sciond.send_rev_notification(
                rev_info, connector=self._connector)
            return ResponseRV.RETRY
        else:
            logging.error("Received SCMP error:\n%s", spkt)
            return ResponseRV.FAILURE

    def _test_as_request_reply(self):
        try:
            entries = lib_sciond.get_as_info(connector=self._connector)
        except lib_sciond.SCIONDLibError as e:
            logging.error("An error occured: %s" % e)
            return False
        for entry in entries:
            if entry.isd_as() == self.addr.isd_as:
                logging.debug("Received correct AS reply.")
                return True
        logging.error("Wrong AS Reply received.")
        return False

    def run(self):
        """
        Tests AS request/reply functionality before entering the sending loop.
        """
        if not self._test_as_request_reply():
            self._shutdown()
            kill_self()
        super().run()


class E2EServer(TestServerBase):
    """
    Simple pong app.
    """
    def _handle_request(self, spkt):
        logging.debug("received on server")
        expected = b"ping " + self.data
        raw_pld = spkt.get_payload().pack()
        if not raw_pld.startswith(expected):
            return False

        drkey = _try_sciond_api(spkt, self._connector)
        try:
            verify_scmp_packet(spkt, drkey)
        except SCIONVerificationError as e:
            logging.warning("Verification failed: %s", e)
            return False

        # Reverse the packet and send "pong".
        logging.debug('%s:%d: ping received, sending pong.',
                      self.addr.host, self.sock.port)
        spkt.reverse()
        spkt.set_payload(self._create_payload(spkt))
        spkt.update()
        drkey = _try_sciond_api(spkt, self._connector)
        set_scmp_auth_mac(spkt, drkey)

        self._send_pkt(spkt)
        self.success = True
        self.finished.set()
        return True

    def _create_payload(self, spkt):
        old_pld = spkt.get_payload()
        data = b"pong " + self.data
        padding = len(old_pld) - len(data)
        return PayloadRaw(data + bytes(padding))


def _try_sciond_api(spkt, connector):

    start = time.time()
    while time.time() - start < API_TOUT:
        try:
            drkey, _ = lib_sciond.get_protocol_drkey(
                get_sciond_params(spkt), connector=connector)
        except lib_sciond.SCIONDConnectionError as e:
            logging.error("Connection to SCIOND failed: %s " % e)
            break
        except lib_sciond.SCIONDLibError as e:
            logging.error("Error during protocol DRKey request: %s" % e)
            continue
        return drkey
    logging.critical("Unable to get protocol DRKey from local api.")
    kill_self()


class TestEnd2End(TestClientServerBase):
    """
    End to end packet transmission test.
    For this test a infrastructure must be running.
    """
    NAME = "End2End"

    def _create_server(self, data, finished, addr):
        return E2EServer(data, finished, addr)

    def _create_client(self, data, finished, src, dst, port):
        return E2EClient(data, finished, src, dst, port, retries=self.retries)


def main():
    args, srcs, dsts = setup_main("end2end")
    TestEnd2End(args.client, args.server, srcs, dsts, max_runs=args.runs,
                retries=args.retries).run()


if __name__ == "__main__":
    main_wrapper(main)
