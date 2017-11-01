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
:mod:`cert_req_est` --- SCION certificate request tests
=======================================================
"""

# Stdlib
import logging
import threading

# SCION
import lib.app.sciond as lib_sciond
from lib.main import main_wrapper
from lib.packet.ctrl_pld import CtrlPayload
from lib.packet.cert_mgmt import CertChainRequest, CertMgmt, TRCRequest
from lib.packet.path import SCIONPath
from lib.packet.scion import SCIONL4Packet, build_base_hdrs
from lib.packet.scion_addr import SCIONAddr
from lib.types import ServiceType
from integration.base_cli_srv import (
    get_sciond_api_addr,
    setup_main,
    ResponseRV,
    TestClientBase,
    TestClientServerBase,
)


class TestCertClient(TestClientBase):
    def __init__(self, finished, addr, dst_ia):
        # We need the lib sciond here already.
        connector = lib_sciond.init(get_sciond_api_addr(addr))
        cs_info = lib_sciond.get_service_info(
            [ServiceType.CS], connector=connector)[ServiceType.CS]
        cs = cs_info.host_info(0)
        cs_addr = SCIONAddr.from_values(addr.isd_as, cs.ipv4() or cs.ipv6())
        self.cert = None
        super().__init__("", finished, addr, cs_addr, cs.p.port, retries=2)
        self.dst_ia = dst_ia

    def _get_path(self, api, flush=None):
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
        if not self.cert:
            return CtrlPayload(CertMgmt(CertChainRequest.from_values(self.dst_ia, 0)))
        return CtrlPayload(CertMgmt(TRCRequest.from_values(self.dst_ia, 0)))

    def _handle_response(self, spkt):
        cpld = spkt.parse_payload()
        cmgt = cpld.union
        pld = cmgt.union
        logging.debug("Got:\n%s", spkt)
        if not self.cert:
            if (self.dst_ia, 0) == pld.chain.get_leaf_isd_as_ver():
                logging.debug("Cert query success")
                self.cert = pld.chain
                return ResponseRV.CONTINUE
            logging.error("Cert query failed")
            return ResponseRV.FAILURE
        if (self.dst_ia[0], 0) == pld.trc.get_isd_ver():
            self.cert.verify(str(self.dst_ia), pld.trc)
            logging.debug("TRC query success")
            self.success = True
            self.finished.set()
            return ResponseRV.SUCCESS
        logging.error("TRC query failed")
        return ResponseRV.FAILURE


class TestCertReq(TestClientServerBase):
    NAME = "CertReqTest"

    def _run_test(self, src, dst):
        logging.info("Testing: %s -> %s", src.isd_as, dst.isd_as)
        finished = threading.Event()
        client = self._create_client(finished, src, dst.isd_as)
        client.run()
        if client.success:
            return True
        logging.error("Client success? %s", client.success)
        return False

    def _create_client(self, finished, addr, dst_ia):
        return TestCertClient(finished, addr, dst_ia)


def main():
    args, srcs, dsts = setup_main("certreq")
    TestCertReq(args.client, args.server, srcs, dsts, max_runs=args.runs).run()


if __name__ == "__main__":
    main_wrapper(main)
