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
import argparse
import logging
import socket

import lib.app.sciond as lib_sciond
import time

import sys
from integration.base_cli_srv import (
    ResponseRV,
    setup_main,
    TestClientBase,
    TestClientServerBase,
    TestServerBase, API_TOUT)
from lib.crypto.symcrypto import sha256
from lib.drkey.opt.protocol import get_sciond_params
from lib.drkey.util import drkey_time
from lib.main import main_wrapper
from lib.packet.opt.defines import OPTLengths, OPTMode
from lib.packet.opt.opt_ext import SCIONOriginValidationPathTraceExtn
from lib.packet.opt.ov_ext import SCIONOriginValidationExtn
from lib.packet.opt.pt_ext import SCIONPathTraceExtn
from lib.packet.packet_base import PayloadRaw
from lib.packet.path_mgmt.rev_info import RevocationInfo
from lib.packet.scion import build_base_hdrs, SCIONL4Packet
from lib.packet.scmp.types import SCMPClass, SCMPPathClass
from lib.thread import kill_self
from lib.types import L4Proto

OPT_MODE = -1  # -1 means OPT not enabled, valid OPT modes are in [0, 1, 2]

PACKETS_NO = 1000
MTU = 1300
packets_received = 0
start_time = None
end_time = None


class E2EClient(TestClientBase):
    """
    Simple ping app.
    """

    cached_pkt = None

    def run(self):
        # Tests AS request/reply functionality before entering the sending loop.
        if not self._test_as_request_reply():
            self._shutdown()
            kill_self()
        global start_time
        start_time = time.time()
        packets_sent = 0
        while packets_sent < PACKETS_NO:
            self._send()
            packets_sent += 1
            # spkt = self._recv()
            # self._handle_response(spkt)
        self._stop(success=True)
        self._shutdown()

    def _send(self):
        self._send_pkt(self._build_pkt(), self.first_hop)

    def _send_pkt(self, spkt, next_=None):
        if not next_:
            try:
                fh_info = lib_sciond.get_overlay_dest(
                    spkt, connector=self._connector)
            except lib_sciond.SCIONDLibError as e:
                logging.error("Error getting first hop: %s" % e)
                kill_self()
            next_hop = fh_info.ipv4() or fh_info.ipv6()
            port = fh_info.p.port
        else:
            next_hop, port = next_
        assert next_hop is not None
        self.sock.send(spkt.pack(), (next_hop, port))

    def _build_pkt(self, path=None):
        if self.cached_pkt:
            return self.cached_pkt
        cmn_hdr, addr_hdr = build_base_hdrs(self.dst, self.addr)
        l4_hdr = self._create_l4_hdr()

        if path is None:
            path = self.path_meta.fwd_path()
        extns = []
        if OPT_MODE != -1:
            print("Creating OPT header")
            path_meta = [i.isd_as() for i in self.path_meta.iter_ifs()]
            if OPT_MODE == OPTMode.OPT:
                extn = SCIONOriginValidationPathTraceExtn. \
                    from_values(OPTMode.OPT,
                                0,
                                bytes(OPTLengths.TIMESTAMP),
                                bytes(OPTLengths.DATAHASH),
                                bytes(OPTLengths.SESSIONID),
                                bytes(OPTLengths.PVF),
                                [bytes(OPTLengths.OVs)] * len(path_meta)
                                )
            elif OPT_MODE == OPTMode.PATH_TRACE_ONLY:
                extn = SCIONPathTraceExtn. \
                    from_values(OPTMode.PATH_TRACE_ONLY,
                                bytes(OPTLengths.TIMESTAMP),
                                bytes(OPTLengths.DATAHASH),
                                bytes(OPTLengths.SESSIONID),
                                bytes(OPTLengths.PVF)
                                )
            elif OPT_MODE == OPTMode.ORIGIN_VALIDATION_ONLY:
                extn = SCIONOriginValidationExtn. \
                    from_values(OPTMode.ORIGIN_VALIDATION_ONLY,
                                0,
                                bytes(OPTLengths.TIMESTAMP),
                                bytes(OPTLengths.DATAHASH),
                                bytes(OPTLengths.SESSIONID),
                                [bytes(OPTLengths.OVs)] * len(path_meta)
                                )
            else:
                logging.error("Invalid OPT mode: %s" % OPT_MODE)
                kill_self()
            extns = [extn]
        spkt = SCIONL4Packet.from_values(
            cmn_hdr, addr_hdr, path, extns, l4_hdr)
        payload = self._create_payload(spkt)
        spkt.set_payload(payload)
        # update extns
        if OPT_MODE != -1:
            print("Updating OPT header")
            path_meta = [i.isd_as() for i in self.path_meta.iter_ifs()]
            drkey, misc = _try_sciond_api(spkt, self._connector, path_meta)
            extn.timestamp = drkey_time().to_bytes(4, 'big')
            extn.datahash = sha256(payload.pack())[:16]
            if OPT_MODE != 2:
                extn.init_pvf(drkey.drkey)
            if OPT_MODE != 1:
                if misc.drkeys:
                    extn.OVs = extn.create_ovs_from_path(misc.drkeys)
        spkt.update()

        self.cached_pkt = spkt
        return spkt

    def _create_payload(self, spkt):
        data = self.data
        self.path_meta.p.mtu = MTU
        pld_max_len = self.path_meta.p.mtu - spkt.cmn_hdr.hdr_len_bytes() - \
            len(spkt.l4_hdr)
        return self._gen_max_pld(data, pld_max_len)

    def _gen_max_pld(self, data, pld_len):
        padding = pld_len - len(data)
        return PayloadRaw(data + bytes(padding))

    def _handle_response(self, spkt):
        if spkt.l4_hdr.TYPE == L4Proto.SCMP:
            return self._handle_scmp(spkt)
        # logging.debug("Received:\n%s", spkt)
        if len(spkt) != self.path_meta.p.mtu:
            logging.error("Packet length (%sB) != MTU (%sB)",
                          len(spkt), self.path_meta.p.mtu)
            return ResponseRV.FAILURE
        payload = spkt.get_payload()
        pong = self._gen_max_pld(self.data, len(payload))
        if payload == pong:
            # logging.debug('%s:%d: pong received.', self.addr.host,
            #               self.sock.port)
            return ResponseRV.SUCCESS
        logging.error(
            "Unexpected payload:\n  Received (%dB): %s\n  "
            "Expected (%dB): %s", len(payload), payload, len(pong), pong)
        return ResponseRV.FAILURE

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


class E2EServer(TestServerBase):
    """
    Simple pong app.
    """

    def run(self):
        timeout = 1
        self.sock.settimeout(timeout)
        global packets_received
        while packets_received < PACKETS_NO:
            try:
                packet = self.sock.recv()[0]
            except socket.timeout:
                print("Timed out after {} packets".format(packets_received))
                logging.error("Timed out after %d packets", packets_received)
                # Account for the timeout interval itself (do not penalize for timing out)
                global start_time
                start_time += timeout
                break
            packets_received += 1
            SCIONL4Packet(packet)  # gets a spkt from raw
        global end_time
        end_time = time.time()
        self.success = True
        self.finished.set()
        self._shutdown()

    def _send_pkt(self, spkt, next_=None):
        if not next_:
            try:
                fh_info = lib_sciond.get_overlay_dest(
                    spkt, connector=self._connector)
            except lib_sciond.SCIONDLibError as e:
                logging.error("Error getting first hop: %s" % e)
                kill_self()
            next_hop = fh_info.ipv4() or fh_info.ipv6()
            port = fh_info.p.port
        else:
            next_hop, port = next_
        assert next_hop is not None
        self.sock.send(spkt.pack(), (next_hop, port))

    def _handle_request(self, spkt):
        expected = self.data
        raw_pld = spkt.get_payload().pack()
        if not raw_pld.startswith(expected):
            return False

        # Reverse the packet and send "pong".
        logging.debug('%s:%d: ping received, sending pong.',
                      self.addr.host, self.sock.port)
        spkt.reverse()
        spkt.set_payload(self._create_payload(spkt))
        # And update or strip extension header here
        self._send_pkt(spkt)
        return True

    def _create_payload(self, spkt):
        old_pld = spkt.get_payload()
        data = self.data
        padding = len(old_pld) - len(data)
        return PayloadRaw(data + bytes(padding))


def _try_sciond_api(spkt, connector, path):
    start = time.time()
    while time.time() - start < API_TOUT:
        try:
            request_parameters = get_sciond_params(spkt, mode=OPT_MODE, path=path)
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


class TestBandwitdh(TestClientServerBase):
    """
    Bandwidth test.
    For this test a infrastructure must be running.
    """
    NAME = "OPT_Bandwidth_test"

    def _create_server(self, data, finished, addr):
        return E2EServer(data, finished, addr)

    def _create_client(self, data, finished, src, dst, port):
        return E2EClient(data, finished, src, dst, port, retries=self.retries)


def main():
    args, srcs, dsts = setup_main("OPT_Bandwidth_test")
    TestBandwitdh(args.client, args.server, srcs, dsts, max_runs=args.runs,
                  retries=args.retries).run()
    duration = end_time - start_time
    lost = PACKETS_NO - packets_received
    rate = 100 * (lost / PACKETS_NO)
    print("\nReported results:\nGoodput: %.2fMBps Pkts received: %d Pkts lost: %d "
          "Loss rate: %.2f%%" %
          ((packets_received * MTU) / duration / 1e6, packets_received, lost, rate))


if __name__ == "__main__":
    # SCION infrastructure must be started
    # Run with 'PYTHONPATH=.:python python3
    # python/integration/opt_modes_bandwidth_test.py 1-11 1-12 -p 2 --packets 1000 --mtu 1300'
    # extract OPT BW test arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--pmode', help='OPT protocol mode')
    parser.add_argument('--packets', type=int, help='# of packets to send for the bandwidth test')
    parser.add_argument('--mtu', type=int, help='Number of packets to send for the bandwidth test')
    bw_args, other_args = parser.parse_known_args()
    print("\nStarted bandwidth test:\n")
    if bw_args.pmode:
        OPT_MODE = int(bw_args.pmode)
        print("OPT_MODE set to " + str(OPT_MODE))
    else:
        print("OPT disabled")
    if bw_args.packets:
        PACKETS_NO = bw_args.packets
        print("Sending {} packets".format(PACKETS_NO))
    if bw_args.mtu:
        MTU = bw_args.mtu
        print("Packet size: {}".format(MTU))
    logging.disable(logging.CRITICAL)
    print("Disabled logging")
    # pass remaining arguments untouched
    sys.argv = [sys.argv[0]] + other_args
    main_wrapper(main)
