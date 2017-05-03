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
:mod:`cli_srv_spse_test` --- SCION client-server test with an SPS extension
======================================================================
"""
# Stdlib
import logging

# SCION
from lib.main import main_wrapper
from lib.packet.packet_base import PayloadRaw
from lib.packet.spse.defines import SPSELengths, SPSESecModes
from lib.packet.spse.extn import SCIONPacketSecurityExtn
from lib.packet.spse.scmp_auth.defines import (
    SCMPAuthDirections,
    SCMPAuthLengths,
)
from lib.packet.spse.scmp_auth.extn import (
    SCMPAuthDRKeyExtn,
    SCMPAuthHashTreeExtn,
)
from lib.util import hex_str
from test.integration.base_cli_srv import (
    setup_main,
    TestClientBase,
    TestClientServerBase,
    TestServerBase,
)

SECMODES = range(SPSESecModes.AES_CMAC, SPSESecModes.GCM_AES128 + 1)
H = 2


class ExtClient(TestClientBase):
    """
    Extension test client app.
    """
    def _create_extensions(self):
        # Extensions
        exts = []
        for mode in SECMODES:
            meta = bytes(range(0, SPSELengths.META[mode]))
            auth = bytes(range(0, SPSELengths.AUTH[mode]))
            exts.append(SCIONPacketSecurityExtn.from_values(mode, meta, auth))

        exts.append(SCMPAuthDRKeyExtn.from_values(SCMPAuthDirections.AS_TO_AS))
        order = bytes(range(0, 3))
        sign = bytes(range(0, SCMPAuthLengths.SIGNATURE))
        hashes = bytes(range(0, H * SCMPAuthLengths.HASH))
        exts.append(SCMPAuthHashTreeExtn.from_values(H, order, sign, hashes))

        return exts

    def _handle_response(self, spkt):
        logging.debug('Received response:\n%s', spkt)

        for i, mode in enumerate(SECMODES):
            ext = spkt.ext_hdrs[i]
            if not isinstance(ext, SCIONPacketSecurityExtn):
                logging.error("Extension #%s is not SPSE:\n%s", i, ext)
                return False
            if not ext.sec_mode == mode:
                logging.error("Wrong mode %s. Expected %s", ext.sec_mode, mode)
                return False
            expected = bytes(range(0, SPSELengths.META[mode]))
            if not ext.metadata == expected:
                logging.error("Wrong metadata: %s. Expected %s",
                              hex_str(ext.metadata), hex_str(expected))
                return False
            expected = bytes(range(0, SPSELengths.AUTH[mode]))
            if not ext.authenticator == expected:
                logging.error("Wrong authenticator: %s. Expected %s",
                              hex_str(ext.authenticator), hex_str(expected))
                return False
        i = SECMODES[-1] + 1
        ext = spkt.ext_hdrs[i]
        if not isinstance(ext, SCMPAuthDRKeyExtn):
            logging.error("Extension #%s is not SCMPAuthDRKeyExtn:\n%s", i, ext)
            return False
        if not ext.direction == SCMPAuthDirections.AS_TO_AS:
            logging.error("Wrong direction %s. Expected %s", ext.direction,
                          SCMPAuthDirections.AS_TO_AS)
            return False
        if not ext.mac == bytes(SCMPAuthLengths.MAC):
            logging.error("Wrong MAC %s. Expected %s", ext.mac,
                          bytes(SCMPAuthLengths.MAC))
            return False
        i += 1
        ext = spkt.ext_hdrs[i]
        if not isinstance(ext, SCMPAuthHashTreeExtn):
            logging.error(
                "Extension #%s is not SCMPAuthHashTreeExtn:\n%s", i, ext)
            return False
        if not ext.height == H:
            logging.error("Wrong height %s. Expected %s", ext.height, H)
            return False
        if not ext.order == bytes(range(0, 3)):
            logging.error("Wrong order %s. Expected %s", ext.order,
                          bytes(range(0, 3)))
            return False
        if not ext.signature == bytes(range(0, SCMPAuthLengths.SIGNATURE)):
            logging.error("Wrong signature %s. Expected %s", ext.signature,
                          bytes(range(0, SCMPAuthLengths.SIGNATURE)))
            return False
        if not ext.hashes == bytes(range(0, H * SCMPAuthLengths.HASH)):
            logging.error("Wrong hashes %s. Expected %s", ext.signature,
                          bytes(range(0, H * SCMPAuthLengths.HASH)))
            return False
        self.success = True
        self.finished.set()
        return True


class ExtServer(TestServerBase):
    """
    Extension test server app.
    """

    def _handle_request(self, spkt):
        if spkt.get_payload() != PayloadRaw(self.data):
            logging.error("Payload verification failed:\n%s", spkt)
            return False
        logging.debug('SRV: request received, sending response.')
        spkt.reverse()
        spkt.set_payload(PayloadRaw(b"response"))
        self._send_pkt(spkt)
        self.success = True
        self.finished.set()
        return True


class TestClientServerExtension(TestClientServerBase):
    """
    End to end packet transmission test with extension.
    For this test a infrastructure must be running.
    """
    NAME = "CliSrvSPSE"

    def _create_server(self, data, finished, addr):
        return ExtServer(data, finished, addr)

    def _create_client(self, data, finished, src, dst, port):
        return ExtClient(data, finished, src, dst, port)


def main():
    args, srcs, dsts = setup_main("cli_srv_spse_test")
    TestClientServerExtension(args.client, args.server, srcs, dsts, local=False,
                              max_runs=args.runs).run()


if __name__ == "__main__":
    main_wrapper(main)
