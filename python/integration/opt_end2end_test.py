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
:mod:`end2end_test` --- SCION OPT end2end tests
===========================================
"""
# Stdlib
import logging
import binascii

# SCION
import time

import lib.app.sciond as lib_sciond
from lib.crypto.symcrypto import sha256
from lib.drkey.opt.protocol import get_sciond_params, verify_pvf, find_opt_extn
from lib.drkey.util import drkey_time
from lib.errors import SCIONVerificationError
from lib.main import main_wrapper
from lib.packet.opt.opt_ext import SCIONOriginValidationPathTraceExtn
from lib.packet.packet_base import PayloadRaw
from lib.packet.path_mgmt.rev_info import RevocationInfo
from lib.packet.scion import build_base_hdrs, SCIONL4Packet
from lib.packet.scmp.types import SCMPClass, SCMPPathClass
from lib.packet.opt.defines import OPTLengths, OPTMode
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

    def _build_pkt(self, path=None):
        cmn_hdr, addr_hdr = build_base_hdrs(self.dst, self.addr)
        l4_hdr = self._create_l4_hdr()
        path_meta = [i.isd_as() for i in self.path_meta.iter_ifs()]

        extn = SCIONOriginValidationPathTraceExtn.\
            from_values(0,
                        0,
                        bytes(OPTLengths.TIMESTAMP),
                        bytes(OPTLengths.DATAHASH),
                        bytes(OPTLengths.SESSIONID),
                        bytes(OPTLengths.PVF),
                        [bytes(OPTLengths.OVs)]*len(path_meta)
                        )

        if path is None:
            path = self.path_meta.fwd_path()
        spkt = SCIONL4Packet.from_values(
            cmn_hdr, addr_hdr, path, [extn], l4_hdr)
        payload = self._create_payload(spkt)
        spkt.set_payload(payload)
        spkt.update()

        drkey, misc = _try_sciond_api(spkt, self._connector, path_meta)
        for k in misc.drkeys:
            logging.debug(binascii.hexlify(k.drkey))
        extn.timestamp = drkey_time().to_bytes(4, 'big')
        extn.datahash = sha256(payload.pack())[:16]
        logging.debug(binascii.hexlify(extn.datahash))
        extn.init_pvf(drkey.drkey)
        if misc.drkeys:
            extn.OVs = extn.create_ovs_from_path(misc.drkeys)

        logging.debug("Computed path %s", path_meta)
        logging.debug("misc.drkeys:")
        for k in misc.drkeys:
            logging.debug("key: %s", k)

        return spkt

    def _create_payload(self, spkt):
        path = [i.isd_as() for i in self.path_meta.iter_ifs()]
        drkey, misc = _try_sciond_api(
            spkt, self._connector, path)
        data = drkey.drkey + b" " + self.data
        pld_len = self.path_meta.p.mtu - spkt.cmn_hdr.hdr_len_bytes() - \
            len(spkt.l4_hdr) - len(spkt.ext_hdrs[0])
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
        drkey, misc = _try_sciond_api(spkt, self._connector, path=None)
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
        drkey, misc = _try_sciond_api(spkt, self._connector, None)
        logging.debug(drkey)
        expected = drkey.drkey + b" " + self.data
        raw_pld = spkt.get_payload().pack()
        if not raw_pld.startswith(expected):
            return False

        src_ia = spkt.l4_hdr._src.isd_as
        d_path_entries = _try_sciond_path_api(src_ia, self._connector)
        d_path_entry = d_path_entries[0]
        d_path_meta = d_path_entry.path()
        computed_path = [i.isd_as() for i in d_path_meta.iter_ifs()]

        # Reverse the packet and send "pong".
        logging.debug('%s:%d: ping received, sending pong.',
                      self.addr.host, self.sock.port)
        spkt.reverse()
        extn = find_opt_extn(spkt)
        extn.path_index = 0
        spkt.update()
        spkt.set_payload(self._create_payload(spkt))

        client_server_key = drkey
        drkey, misc = _try_sciond_api(spkt, self._connector, computed_path)

        # Verfiy received PVF before sending answer
        router_server_keys = misc.drkeys.copy()
        router_server_keys.reverse()
        try:
            verify_pvf(spkt, client_server_key, router_server_keys)
        except SCIONVerificationError as e:
            logging.warning("Verification failed: %s", e)
            return False

        # Init response
        extn.sessionID = bytes([0]*16)
        extn.init_pvf(drkey.drkey)
        spkt.update()

        logging.debug("Computed path %s", computed_path)
        logging.debug("misc.drkeys:")
        for k in misc.drkeys:
            logging.debug("key: %s", k)
        if misc.drkeys:
            extn.OVs = extn.create_ovs_from_path(misc.drkeys)
        logging.debug("Raw packet header sent: {}".format(binascii.hexlify(extn.pack())))
        self._send_pkt(spkt)
        self.success = True
        self.finished.set()
        return True

    def _create_payload(self, spkt):
        old_pld = spkt.get_payload()
        drkey, misc = _try_sciond_api(spkt, self._connector, None)
        logging.debug(drkey)
        data = drkey.drkey + b" " + self.data
        padding = len(old_pld) - len(data)
        return PayloadRaw(data + bytes(padding))


def _try_sciond_api(spkt, connector, path):
    start = time.time()
    while time.time() - start < API_TOUT:
        try:
            request_parameters = get_sciond_params(spkt, mode=OPTMode.OPT, path=path)
            drkey, misc = lib_sciond.get_protocol_drkey(
                request_parameters,
                connector=connector)
        except lib_sciond.SCIONDConnectionError as e:
            logging.error("Connection to SCIOND failed: %s " % e)
            break
        except lib_sciond.SCIONDLibError as e:
            logging.error("Error during protocol DRKey request: %s" % e)
            continue
        return drkey, misc
    logging.critical("Unable to get protocol DRKey from local api.")
    kill_self()


def _try_sciond_path_api(dst_ia, connector, flush=False):
    flags = lib_sciond.PathRequestFlags(flush=flush)
    start = time.time()
    while time.time() - start < API_TOUT:
        try:
            path_entries = lib_sciond.get_paths(
                dst_ia, flags=flags, connector=connector)
        except lib_sciond.SCIONDConnectionError as e:
            logging.error("Connection to SCIOND failed: %s " % e)
            break
        except lib_sciond.SCIONDLibError as e:
            logging.error("Error during path lookup: %s" % e)
            continue
        return path_entries
    logging.critical("Unable to get path from local api.")
    kill_self()


class TestEnd2End(TestClientServerBase):
    """
    End to end packet transmission test.
    For this test a infrastructure must be running.
    """
    NAME = "OPT_End2End"

    def _create_server(self, data, finished, addr):
        return E2EServer(data, finished, addr)

    def _create_client(self, data, finished, src, dst, port):
        return E2EClient(data, finished, src, dst, port, retries=self.retries)


def main():
    args, srcs, dsts = setup_main("OPT_End2End")
    TestEnd2End(args.client, args.server, srcs, dsts, max_runs=args.runs,
                retries=args.retries).run()


if __name__ == "__main__":
    main_wrapper(main)
