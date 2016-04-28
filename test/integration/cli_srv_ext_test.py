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
:mod:`cli_srv_ext_test` --- SCION client-server test with an extension
======================================================================
"""
# Stdlib
import logging

# SCION
from lib.main import main_wrapper
from lib.packet.ext.traceroute import TracerouteExt
from lib.packet.ext.path_transport import (
    PathTransportExt,
    PathTransOFPath,
    PathTransType,
)
from lib.packet.packet_base import PayloadRaw
from test.integration.base_cli_srv import (
    setup_main,
    TestClientBase,
    TestClientServerBase,
    TestServerBase,
)


class ExtClient(TestClientBase):
    """
    Extension test client app.
    """
    def _create_extensions(self):
        # Determine number of border routers on path in single direction
        routers_no = (self.path.get_as_hops() - 1) * 2
        # Number of router for round-trip (return path is symmetric)
        routers_no *= 2

        # Extensions
        exts = []
        # Create empty Traceroute extensions with allocated space
        exts.append(TracerouteExt.from_values(routers_no))
        # Create PathTransportExtension
        # One with data-plane path.
        of_path = PathTransOFPath.from_values(self.src, self.dst, self.path)
        exts.append(PathTransportExt.from_values(
            PathTransType.OF_PATH, of_path))
        # And another PathTransportExtension with control-plane path.
        if (self.sd.up_segments() or
                self.sd.core_segments() or
                self.sd.down_segments()):
            seg = (self.sd.up_segments() +
                   self.sd.core_segments() +
                   self.sd.down_segments())[0]
            # FIXME(PSz): remove the following line when PathTransportExt can
            # handle long paths.
            seg.remove_crypto()
            exts.append(PathTransportExt.from_values(
                PathTransType.PCB_PATH, seg))
        return exts

    def _handle_response(self, spkt):
        self.done = True
        logging.debug('CLI: Received response:\n%s', spkt)
        logging.debug("CLI: leaving.")


class ExtServer(TestServerBase):
    """
    Extension test server app.
    """
    def _verify_request(self, payload):
        return payload == PayloadRaw(b"request to server")

    def _handle_request(self, spkt):
        logging.debug('SRV: request received, sending response.')
        # Reverse the packet
        spkt.reverse()
        # Setting payload
        spkt.set_payload(PayloadRaw(b"response"))
        # Determine first hop (i.e., local address of border router)
        (next_hop, port) = self.sd.get_first_hop(spkt)
        assert next_hop is not None
        # Send packet to first hop (it is sent through SCIONDaemon)
        self.sd.send(spkt, next_hop, port)
        logging.debug("SRV: Leaving server.")


class TestClientServerExtension(TestClientServerBase):
    """
    End to end packet transmission test with extension.
    For this test a infrastructure must be running.
    """
    def __init__(self, client, server, sources, destinations, local):
        super().__init__(client, server, sources, destinations, local)
        self.client_name = "Ext Client"
        self.server_name = "Ext Server"
        self.thread_name = "CliSrvExt.MainThread"

    def _create_data(self):
        return b"request to server"

    def _create_server(self, addr, data):
        return ExtServer(addr, data)

    def _create_client(self, src, dst, port, data):
        return ExtClient(src, dst, port, data)


def main():
    args, srcs, dsts = setup_main()
    TestClientServerExtension(args.client, args.server, srcs, dsts, False).run()


if __name__ == "__main__":
    main_wrapper(main)
