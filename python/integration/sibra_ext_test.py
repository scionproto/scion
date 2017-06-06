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
======================================================================
"""
# Stdlib
import logging
import time

# SCION
from lib.defines import PATH_FLAG_SIBRA, SIBRA_MAX_IDX
from lib.main import main_wrapper
from lib.packet.ext_util import find_ext_hdr
from lib.packet.packet_base import PayloadRaw
from lib.packet.path import SCIONPath
from lib.sibra.ext.info import ResvInfoEphemeral
from lib.sibra.ext.ephemeral import SibraExtEphemeral
from lib.sibra.util import BWSnapshot
from lib.types import ExtensionClass
from integration.base_cli_srv import (
    setup_main,
    TestClientBase,
    TestClientServerBase,
    TestServerBase,
)

RESV_LEN = 8.0
RUN_TIME = 8.0
RENEWAL_THRESHOLD = 5.0


class SibraClient(TestClientBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bw_cls = BWSnapshot(1000 * 1024, 2000 * 1024).to_classes().ceil()
        self.block = None
        self.setup_ts = 0
        self.setup_tries = 3
        self.eph_id = SibraExtEphemeral.mk_path_id(self.addr.isd_as)

    def _get_path(self, _):
        self._get_path_direct(flags=(PATH_FLAG_SIBRA,))
        assert self.path
        logging.debug("Interfaces: %s", ", ".join(
            ["%s:%s" % ifentry for ifentry in self.iflist]))

    def _get_iflist(self):
        for _, _, iflist in self.path:
            self.iflist.extend(iflist)

    def run(self):
        # FIXME(kormat): once sibra supports on-path pairs, this should be
        # removed.
        if len(set(self.iflist)) != len(self.iflist):
            logging.info("Skipping on-path pair")
            self.success = "skip"
            self.finished.set()
            return
        super().run()

    def _handle_setup(self):
        if self.setup_tries <= 0:
            logging.error("Unable to setup connection")
            self.success = False
            self.finished.set()
            return False
        self.setup_tries -= 1
        return True

    def _handle_use(self):
        if time.time() - self.setup_ts >= RUN_TIME:
            self.success = True
            self.finished.set()
            return False
        time.sleep(0.2)
        return True

    def _build_pkt(self, _=None):
        return super()._build_pkt(path=SCIONPath())

    def _create_extensions(self):
        if not self.setup_ts:
            return self._create_setup_ext()
        return self._create_use_ext()

    def _create_setup_ext(self):
        steady_ids = []
        blocks = []
        for id_, block, _ in self.path:
            steady_ids.append(id_)
            blocks.append(block)
        resv_req = ResvInfoEphemeral.from_values(
            time.time() + RESV_LEN, bw_cls=self.bw_cls)
        return [SibraExtEphemeral.setup_from_values(
            resv_req, self.eph_id, steady_ids, blocks)]

    def _create_use_ext(self):
        ids = [self.eph_id]
        path_lens = []
        for id_, block, _ in self.path:
            ids.append(id_)
            path_lens.append(block.num_hops)
        req_info = None
        now = time.time()
        if self.block.info.exp_ts() - now <= RENEWAL_THRESHOLD:
            logging.debug("Renewal needed, current block expiring soon: %s",
                          self.block.info)
            req_info = self._create_renewal_req()
        return [SibraExtEphemeral.use_from_values(
            ids, path_lens, self.block, req_info=req_info)]

    def _create_renewal_req(self):
        idx = (self.block.info.index + 1) % SIBRA_MAX_IDX
        return ResvInfoEphemeral.from_values(
            time.time() + RESV_LEN, bw_cls=self.bw_cls, index=idx)

    def _handle_response(self, spkt):
        logging.debug("Received:\n%s", spkt)
        if not self.setup_ts:
            self._handle_setup()
        elif not self._handle_use():
            return True
        ext = self.get_ext(spkt)
        if not ext.req_block:
            return True
        if ext.accepted:
            self.block = ext.req_block
            if not self.setup_ts:
                self.setup_ts = time.time()
        else:
            self.bw_cls = ext.get_min_offer()
        return True

    def get_ext(self, spkt):
        return find_ext_hdr(spkt, ExtensionClass.HOP_BY_HOP,
                            SibraExtEphemeral.EXT_TYPE)


class SibraServer(TestServerBase):
    def run(self):
        self.count = 0
        super().run()
        logging.debug("Finished (received %d packets)", self.count)

    def _handle_request(self, spkt):
        logging.debug("Received:\n%s", spkt)
        spkt.reverse()
        pld = PayloadRaw(("pong %d" % self.count).encode("ascii"))
        spkt.set_payload(pld)
        self._send_pkt(spkt)
        self.count += 1
        self.success = True
        return True


class SIBRATest(TestClientServerBase):
    NAME = "SIBRA"

    def _check_result(self, client, server):
        if client.success == "skip":
            return True
        return super()._check_result(client, server)

    def _create_server(self, data, finished, addr):
        return SibraServer(data, finished, addr)

    def _create_client(self, data, finished, src, dst, port):
        return SibraClient(data, finished, src, dst, port)


def main():
    args, srcs, dsts = setup_main("sibra_ext_test")
    if args.wait:
        logging.info("Waiting %ss", args.wait)
        time.sleep(args.wait)
    SIBRATest(args.client, args.server, srcs, dsts, local=False,
              max_runs=args.runs).run()


if __name__ == "__main__":
    main_wrapper(main)
