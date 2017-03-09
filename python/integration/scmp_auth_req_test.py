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
:mod:`scmp_auth_req_est` --- SCION SCMP Auth DRKey request tests
=======================================================
"""

# Stdlib
import logging
import random
import threading

# SCION
import lib.app.sciond as lib_sciond
from lib.drkey.drkey_mgmt import DRKeyProtocolRequest, DRKeyProtocolReply
from lib.drkey.types import DRKeyProtocols, DRKeyProtoKeyType
from lib.drkey.util import drkey_time
from lib.main import main_wrapper
from lib.packet.path import SCIONPath
from lib.packet.scion import SCIONL4Packet, build_base_hdrs
from lib.packet.scion_addr import SCIONAddr
from lib.types import ServiceType
from integration.base_cli_srv import (
    get_sciond_api_addr,
    setup_main,
    TestClientBase,
    TestClientServerBase,
)


class TestSCMPAuthClient(TestClientBase):
    def __init__(self, finished, addr, dst):
        # We need the lib sciond here already.
        connector = lib_sciond.init(get_sciond_api_addr(addr))
        cs_info = lib_sciond.get_service_info(
            [ServiceType.CS], connector=connector)[ServiceType.CS]
        cs = cs_info.host_info(0)
        cs_addr = SCIONAddr.from_values(addr.isd_as, cs.ipv4() or cs.ipv6())
        self.other_as = dst.isd_as
        super().__init__("", finished, addr, cs_addr, cs.p.port)

    def _get_path(self, api):
        pass  # No path required. All queries go to local CS

    def _build_pkt(self):
        cmn_hdr, addr_hdr = build_base_hdrs(self.dst, self.addr)
        l4_hdr = self._create_l4_hdr()
        spkt = SCIONL4Packet.from_values(
            cmn_hdr, addr_hdr, SCIONPath(), [], l4_hdr)
        spkt.set_payload(self._create_payload(spkt))
        spkt.update()
        return spkt

    def _create_payload(self, _):
        params = DRKeyProtocolRequest.Params()
        params.timestamp = drkey_time()
        params.src_ia = self.other_as
        params.dst_ia = self.addr.isd_as
        params.dst_host = self.addr.host
        params.protocol = DRKeyProtocols.SCMP_AUTH
        params.request_type = DRKeyProtoKeyType.AS_TO_HOST
        params.request_id = self.request_id = random.randint(0, 4000)
        return DRKeyProtocolRequest.from_values(params)

    def _handle_response(self, spkt):
        rep = spkt.parse_payload()
        logging.debug("Got:\n%s", spkt)
        assert isinstance(rep, DRKeyProtocolReply)

        if not rep.p.reqID == self.request_id:
            logging.error("Non matching request ids. Expected: %s Received: %s",
                          self.request_id, rep.p.reqID)
            return False

        if not len(rep.p.drkey) == 16:
            logging.error("Wrong size drkey. len: %s", len(rep.p.drkey))
            return False

        logging.debug("SCMPAuth DRKey request success")
        self.success = True
        self.finished.set()
        return True


class TestSCMPAuthReq(TestClientServerBase):
    NAME = "SCMPAuthReqTest"

    def _run_test(self, addr, dst):
        logging.info("Testing: %s", addr)
        finished = threading.Event()
        client = self._create_client(finished, addr, dst)
        client.run()
        if client.success:
            return True
        logging.error("Client success? %s", client.success)
        return False

    def _create_client(self, finished, addr, dst):
        return TestSCMPAuthClient(finished, addr, dst)


def main():
    args, srcs, dsts = setup_main("scmpauthreq")
    TestSCMPAuthReq(args.client, args.server, srcs, dsts, max_runs=args.runs).run()


if __name__ == "__main__":
    main_wrapper(main)
