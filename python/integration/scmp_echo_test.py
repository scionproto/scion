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
:mod:`scmp_echo_test` --- SCMP Echo test
========================================
"""
# Stdlib
import logging
import sys

# SCION
from lib.main import main_wrapper
from lib.packet.host_addr import haddr_parse_interface
from lib.packet.scion_addr import SCIONAddr, ISD_AS
from lib.packet.scmp.ext import SCMPExt
from lib.packet.scmp.info import SCMPInfoEcho
from lib.packet.scmp.payload import SCMPPayload
from lib.packet.scmp.hdr import SCMPHeader
from lib.packet.scmp.types import SCMPClass, SCMPGeneralClass
from lib.types import L4Proto
from integration.base_cli_srv import (
    setup_main,
    TestClientBase,
    ResponseRV
)


class SCMPEchoClient(TestClientBase):
    """
    SCMP Echo client app
    """
    def _create_extensions(self):
        return [SCMPExt.from_values(False, False)]

    def _create_l4_hdr(self):
        return SCMPHeader.from_values(
            self.addr, self.dst, SCMPClass.GENERAL,
            SCMPGeneralClass.ECHO_REQUEST)

    def _create_payload(self, _):
        self.info = SCMPInfoEcho.from_values()
        return SCMPPayload.from_values(self.info)

    def _handle_response(self, spkt):
        spkt.parse_payload()
        l4 = spkt.l4_hdr
        pld = spkt.get_payload()
        if (l4.TYPE == L4Proto.SCMP and
                l4.class_ == SCMPClass.GENERAL and
                l4.type == SCMPGeneralClass.ECHO_REPLY and
                pld.info.id == self.info.id and
                pld.info.seq == self.info.seq):
            logging.debug("Success!\n%s", spkt)
            return ResponseRV.SUCCESS
        else:
            logging.error("Failure:\n%s", spkt)
            return ResponseRV.FAILURE


def main():
    args = setup_main("scmp_echo_test")
    if args.run_server:
        sys.exit(1)
        logging.critical("Test cannot run as server")

    src = SCIONAddr.from_values(ISD_AS(args.src_ia), haddr_parse_interface(args.client))
    dst = SCIONAddr.from_values(ISD_AS(args.dst_ia), haddr_parse_interface(args.server))
    SCMPEchoClient(args.data.encode("utf-8"), src, dst, dport=int(args.port)).run()


if __name__ == "__main__":
    main_wrapper(main)
