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

# SCION
from lib.main import main_wrapper
from lib.packet.scmp.ext import SCMPExt
from lib.packet.scmp.info import SCMPInfoEcho
from lib.packet.scmp.payload import SCMPPayload
from lib.packet.scmp.hdr import SCMPHeader
from lib.packet.scmp.types import SCMPClass, SCMPGeneralClass
from lib.types import L4Proto
from integration.base_cli_srv import (
    setup_main,
    TestClientBase,
    TestClientServerBase,
    TestServerBase,
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


class SCMPEchoServer(TestServerBase):
    """
    SCMP Echo server app
    Since SCMP Echo is handled directly by the dispatcher, do nothing
    """
    def _handle_request(self, spkt):
        pass

    def run(self):
        self.success = True


class TestSCMPEcho(TestClientServerBase):
    """
    End to end packet transmission test.
    For this test a infrastructure must be running.
    """
    NAME = "SCMPEcho"

    def __init__(self, client, server, sources, destinations, local=True):
        super().__init__(client, server, sources, destinations)
        self.src = client
        self.dst = server
        self.client_name = "E2E Client"
        self.server_name = "E2E Server"
        self.thread_name = "E2E.MainThread"

    def _create_server(self, data, finished, addr):
        return SCMPEchoServer(data, finished, addr)

    def _create_client(self, data, finished, src, dst, port):
        return SCMPEchoClient(data, finished, src, dst, port)


def main():
    args, srcs, dsts = setup_main("scmp_echo_test")
    TestSCMPEcho(args.client, args.server, srcs, dsts).run()


if __name__ == "__main__":
    main_wrapper(main)
