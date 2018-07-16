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

# XXX After removing the traceroute as an extension, this test always succeeds
# if packets are received by the client

# Stdlib
import logging

# SCION
from lib.main import main_wrapper
from lib.packet.ext.path_transport import (
    PathTransportExt,
    PathTransOFPath,
    PathTransType,
)
from lib.packet.host_addr import haddr_parse_interface
from lib.packet.packet_base import PayloadRaw
from lib.packet.scion_addr import SCIONAddr, ISD_AS
from integration.base_cli_srv import (
    setup_main,
    TestClientBase,
    TestServerBase,
)


class ExtClient(TestClientBase):
    """
    Extension test client app.
    """
    def _create_extensions(self):
        # Determine number of border routers on path in single direction
        fwd_path = self.path_meta.fwd_path()
        routers_no = (fwd_path.get_as_hops() - 1) * 2
        # Number of router for round-trip (return path is symmetric)
        routers_no *= 2

        # Extensions
        exts = []
        # Create PathTransportExtension
        # One with data-plane path.
        of_path = PathTransOFPath.from_values(self.addr, self.dst, fwd_path)
        exts.append(PathTransportExt.from_values(
            PathTransType.OF_PATH, of_path))
        return exts

    def _handle_response(self, spkt):
        logging.debug('Received response:\n%s', spkt)
        self.success = True
        self.finished = True
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
        self.finished = True
        return True


def main():
    args = setup_main("cli_srv_ext_test")
    if args.run_server:
        dst = SCIONAddr.from_values(ISD_AS(args.dst_ia), haddr_parse_interface(args.server))
        ExtServer(args.data.encode('utf-8'), dst, port=int(args.port)).run()
    else:
        src = SCIONAddr.from_values(ISD_AS(args.src_ia), haddr_parse_interface(args.client))
        dst = SCIONAddr.from_values(ISD_AS(args.dst_ia), haddr_parse_interface(args.server))
        ExtClient(args.data.encode('utf-8'), src, dst, dport=int(args.port),
                  retries=args.retries).run()


if __name__ == "__main__":
    main_wrapper(main)
