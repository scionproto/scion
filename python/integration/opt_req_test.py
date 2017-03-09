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
import time

import lib.app.sciond as lib_sciond
from lib.drkey.opt.protocol import get_sciond_params
from lib.main import main_wrapper
from lib.packet.packet_base import PayloadRaw
from lib.packet.path_mgmt.rev_info import RevocationInfo
from lib.packet.scmp.types import SCMPClass, SCMPPathClass
from lib.thread import kill_self
from lib.types import L4Proto
from integration.base_cli_srv import (
    ResponseRV,
    setup_main,
    TestClientBase,
    TestClientServerBase,
    TestServerBase,
    API_TOUT)


class E2EClient(TestClientBase):
    """
    Simple ping app.
    """
    def _create_payload(self, spkt):
        path = [i.isd_as() for i in self.path_meta.iter_ifs()]
        drkey, misc = _try_sciond_api(
            get_sciond_params(self.addr, self.dst, path), self._connector)
        data = drkey.drkey + b" " + self.data
        pld_len = self.path_meta.p.mtu - spkt.cmn_hdr.hdr_len - len(spkt.l4_hdr)
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
        drkey, misc = _try_sciond_api(
            get_sciond_params(self.dst, self.addr), self._connector)
        logging.debug(drkey)
        logging.debug(misc)
        pong = self._gen_max_pld(drkey.drkey + b" " + self.data, len(payload))
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
        drkey, misc = _try_sciond_api(
            get_sciond_params(spkt.addrs.src, self.addr), connector=self._connector)
        logging.debug(drkey)
        expected = drkey.drkey + b" " + self.data
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
        drkey, misc = _try_sciond_api(
            get_sciond_params(self.addr, spkt.addrs.dst), connector=self._connector)
        logging.debug(drkey)
        data = drkey.drkey + b" " + self.data
        padding = len(old_pld) - len(data)
        return PayloadRaw(data + bytes(padding))


def _try_sciond_api(params, connector):

    start = time.time()
    while time.time() - start < API_TOUT:
        try:
            drkey, misc = lib_sciond.get_protocol_drkey(params, connector=connector)
        except lib_sciond.SCIONDConnectionError as e:
            logging.error("Connection to SCIOND failed: %s " % e)
            break
        except lib_sciond.SCIONDLibError as e:
            logging.error("Error during protocol DRKey request: %s" % e)
            continue
        return drkey, misc
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
