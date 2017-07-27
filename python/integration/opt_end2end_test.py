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
import base64
import logging
import binascii
from binascii import hexlify as hx
import socket

import cryptography.fernet as encryption

# SCION
import time

import lib.app.sciond as lib_sciond
import proto.drkey_mgmt_capnp as P
from lib.crypto.symcrypto import sha256
from lib.drkey.opt.protocol import (get_sciond_params,
                                    verify_pvf,
                                    find_opt_extn,
                                    get_sciond_params_src,
                                    generate_intermediate_pvfs,
                                    generate_sessionID,
                                    generate_pvf)
from lib.drkey.util import drkey_time
from lib.errors import SCIONVerificationError
from lib.main import main_wrapper
from lib.packet.opt.opt_ext import SCIONOriginValidationPathTraceExtn
from lib.packet.packet_base import PayloadRaw
from lib.packet.path_mgmt.rev_info import RevocationInfo
from lib.packet.scion import build_base_hdrs, SCIONL4Packet
from lib.packet.scion_udp import SCIONUDPHeader
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

    key_exchange_format = P.OPTKeyExchange
    sent_keys = {}

    def _build_pkt(self, path=None):
        cmn_hdr, addr_hdr = build_base_hdrs(self.dst, self.addr)
        if path is None:
            path = self.path_meta.fwd_path()
        path_meta = [i.isd_as() for i in self.path_meta.iter_ifs()]
        path_index = 0
        extn = SCIONOriginValidationPathTraceExtn. \
            from_values(OPTMode.OPT,
                        path_index,
                        bytes(OPTLengths.TIMESTAMP),
                        bytes(OPTLengths.DATAHASH),
                        bytes(OPTLengths.SESSIONID),
                        bytes(OPTLengths.PVF),
                        [bytes(OPTLengths.OVs)] * (len(path_meta) + 1)
                        )
        l4_hdr = self._create_l4_hdr()

        spkt = SCIONL4Packet.from_values(
            cmn_hdr, addr_hdr, path, [extn], l4_hdr)
        spkt.update()

        extn.sessionID = generate_sessionID(spkt)
        dst_isd_as = str(spkt.addrs.dst.isd_as)
        try:  # check if we already have exchanged keys
            dst_addr = str(spkt.addrs.dst.host.addr)
            drkey, misc = self.sent_keys[(dst_isd_as, dst_addr, str(path_meta), extn.sessionID)]
        except KeyError:  # exchange keys
            drkey, misc = _try_sciond_api(spkt, self._connector, path_meta)
            # create encrypted payload
            safe_key = base64.urlsafe_b64encode(drkey.drkey + drkey.drkey)
            cryptor = encryption.Fernet(safe_key)
            key_exchange_bytes = self.key_exchange_format.new_message()
            key_exchange_bytes.keys.drkeys = list(misc.p.drkeys)
            key_exchange_bytes.info.sessionID = extn.sessionID
            key_exchange_bytes.info.path = [isd_as.int() for isd_as in path_meta]
            key_exchange_bytes = key_exchange_bytes.to_bytes()

            # create combined payload
            data = [str(self.addr.isd_as).encode('utf-8'), cryptor.encrypt(key_exchange_bytes)]
            # send keys
            spkt.set_payload(PayloadRaw(b'OPT key exchange: ' + b''.join(data)))
            spkt.ext_hdrs = []
            spkt.update()
            self._send_pkt(spkt)

            max_retries = 10
            retries = 0
            self.sock.settimeout(API_TOUT)
            # retry until we get an ack or max_retries is reached
            while retries < max_retries:
                try:
                    ack = self.sock.recv()[0]
                    # print("Received ACK after {} retries: {}".format(retries, not not ack))
                    resp = SCIONL4Packet(ack)
                    print(resp.get_payload().pack()[:16].decode('utf-8')+"d")
                    print(hx(b''))
                    break
                except socket.timeout:
                    retries += 1
            # store succesfully exchanged keys
            dst_addr = str(spkt.addrs.dst.host.addr)
            self.sent_keys[(dst_isd_as, dst_addr, str(path_meta), extn.sessionID)] = (drkey, misc)

        # add OPT extension
        spkt.ext_hdrs = [extn]
        # set payload of OPT packet
        payload = self._create_payload(spkt)
        spkt.set_payload(payload)

        # finalize OPT extension
        for k in misc.drkeys:
            logging.debug(binascii.hexlify(k.drkey))
        extn.timestamp = drkey_time().to_bytes(4, 'big')
        extn.datahash = sha256(payload.pack())[:16]
        logging.debug(binascii.hexlify(extn.datahash))
        extn.init_pvf(drkey.drkey)
        if misc.drkeys:
            ias_keylist = [(sndkey.src_ia.int(), sndkey.drkey) for sndkey in misc.drkeys]
            pvfs = generate_intermediate_pvfs(spkt, (drkey.src_ia.int(), drkey.drkey),
                                              ias_keylist)
            opvs = extn.create_opvs_from_path(misc.drkeys, drkey, pvfs)
            extn.OVs = opvs

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
        extns_len = 0
        for extn in spkt.ext_hdrs:
            extns_len += len(extn)
        pld_len = self.path_meta.p.mtu - spkt.cmn_hdr.hdr_len_bytes() - \
            len(spkt.l4_hdr) - extns_len
        return self._gen_max_pld(data, pld_len)

    def _gen_max_pld(self, data, pld_len):
        padding = pld_len - len(data)
        return PayloadRaw(data + bytes(padding))

    def _handle_response(self, spkt):
        if spkt.l4_hdr.TYPE == L4Proto.SCMP:
            return self._handle_scmp(spkt)
        logging.debug("Received:\n%s", spkt)
        if len(spkt) != self.path_meta.p.mtu:
            logging.info("Packet length (%sB) != MTU (%sB)", len(spkt), self.path_meta.p.mtu)
            # return ResponseRV.FAILURE
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
        if (scmp_hdr.class_ == SCMPClass.PATH and scmp_hdr.type == SCMPPathClass.REVOKED_IF):
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
        Tests AS request/reply functionality and exchange keys before entering the sending loop.
        """
        if not self._test_as_request_reply():
            self._shutdown()
            kill_self()
        # sciond works as expected
        super().run()


class E2EServer(TestServerBase):
    """
    Simple pong app.
    """

    rcv_keys = {}
    drkey_misc_format = P.MiscOPTRep
    key_exchange_format = P.OPTKeyExchange

    def _handle_request(self, spkt):
        raw_pld = spkt.get_payload().pack()

        src_addr = spkt.addrs.src
        src_port = spkt.l4_hdr.src_port
        src_isd_as = str(spkt.addrs.src.isd_as)
        extn = find_opt_extn(spkt)

        key_exch_tag = b'OPT key exchange: '
        if raw_pld.startswith(key_exch_tag):  # get keys from key exchange
            # decrypt encrypted payload
            drkey, _ = _try_sciond_api_src(spkt, self._connector)
            safe_key = base64.urlsafe_b64encode(drkey.drkey + drkey.drkey)
            cryptor = encryption.Fernet(safe_key)
            misc_keys = cryptor.decrypt(raw_pld[len(key_exch_tag) + 4:])
            # get exchanged keys
            key_exchanged = self.key_exchange_format.from_bytes(misc_keys)
            rmisc = key_exchanged.keys.drkeys
            rinfo = key_exchanged.info
            rpath = list(rinfo.path)
            rmisc = list(rmisc)
            rsessionID = rinfo.sessionID
            # store exchanged keys
            src_host_addr = str(spkt.addrs.src.host.addr)
            rcv_key_entry = (drkey, list(zip(rpath, rmisc)))
            self.rcv_keys[(src_isd_as, src_host_addr, rsessionID)] = rcv_key_entry

            # send ack
            spkt.reverse()
            spkt.ext_hdrs = []
            spkt.update()
            ack = spkt
            self._send_pkt(ack)
            spkt.reverse()
        else:
            # check we received the expected payload
            drkey, misc = _try_sciond_api(spkt, self._connector, None)
            logging.debug(drkey)
            expected = drkey.drkey + b" " + self.data
            if not raw_pld.startswith(expected):
                return False

        if not extn:  # packet has not OPT extension, we are done
            return True

        src_ia = spkt.l4_hdr._src.isd_as
        # get a path back to source from ps (could be different from the one source took)
        d_path_entries = _try_sciond_path_api(src_ia, self._connector)
        d_path_entry = d_path_entries[0]
        d_path_meta = d_path_entry.path()
        computed_path = [i.isd_as() for i in d_path_meta.iter_ifs()]

        # Reverse the packet and send "pong".
        logging.debug('%s:%d: ping received, sending pong.',
                      self.addr.host, self.sock.port)

        # Verify received PVF before sending answer
        try:
            client_server_key, client_router_ias_keys = self.rcv_keys[
                (src_isd_as, str(spkt.addrs.src.host.addr), extn.sessionID)]
            client_router_keys = []
            if client_router_ias_keys:  # There are intermediate ASes
                _, client_router_keys = zip(*client_router_ias_keys)
        except KeyError:
            # wait for keys, drop packet we cannot validate
            return True
        try:
            verify_pvf(spkt, client_server_key, client_router_keys)
        except SCIONVerificationError as e:
            logging.warning("Verification failed: %s", e)
            return False
        # Verify OPVs
        ia_drkey = (client_server_key.src_ia.int(), client_server_key.drkey)
        pvfs = generate_intermediate_pvfs(spkt, ia_drkey,
                                          client_router_ias_keys)
        opvs = extn.create_opvs_from_path(client_router_keys[:-1], client_server_key, pvfs)
        if extn.OVs[extn.ov_count - 1] != opvs[-1]:
            # destination OV check failed
            logging.warning("OV val failed, got {}, wanted {}".format(opvs[-1],
                                                                      extn.OVs[extn.ov_count - 1]))
            return False

        # Init response
        path_index = 0  # reset OPT path index
        new_extn = SCIONOriginValidationPathTraceExtn. \
            from_values(OPTMode.OPT,
                        path_index,
                        bytes(OPTLengths.TIMESTAMP),
                        bytes(OPTLengths.DATAHASH),
                        bytes(OPTLengths.SESSIONID),
                        bytes(OPTLengths.PVF),
                        [bytes(OPTLengths.OVs)] * (len((computed_path)) + 1)
                        )
        cmn_hdr, addr_hdr = build_base_hdrs(src_addr, self.addr)
        l4_hdr = SCIONUDPHeader.from_values(self.addr, self.sock.port, src_addr, src_port)
        spkt = SCIONL4Packet.from_values(
            cmn_hdr, addr_hdr, d_path_meta.fwd_path(), [new_extn], l4_hdr)
        spkt.update()
        drkey, misc = _try_sciond_api(spkt, self._connector, computed_path)

        payload = self._create_payload(spkt, d_path_meta.p.mtu)
        spkt.set_payload(payload)

        timestamp = drkey_time().to_bytes(4, 'big')
        new_extn.timestamp = timestamp
        datahash = sha256(payload.pack())[:16]
        new_extn.datahash = datahash
        sessionID = generate_sessionID(spkt)
        new_extn.sessionID = sessionID
        PVF = generate_pvf(drkey, datahash)
        new_extn.PVF = PVF
        OVs = []

        logging.debug("Computed path %s", computed_path)
        logging.debug("misc.drkeys:")
        for k in misc.drkeys:
            logging.debug("key: %s", k)
        if misc.drkeys:
            ias_keylist = [(sndkey.src_ia.int(), sndkey.drkey) for sndkey in misc.drkeys]
            pvfs = generate_intermediate_pvfs(spkt, (drkey.src_ia.int(), drkey.drkey),
                                              ias_keylist)
            opvs = new_extn.create_opvs_from_path(misc.drkeys, drkey, pvfs)
            OVs = opvs
        new_extn.OVs = OVs

        logging.debug("Raw packet header sent: {}".format(binascii.hexlify(extn.pack())))
        self._send_pkt(spkt)
        self.success = True
        self.finished.set()
        return True

    def _create_payload(self, spkt, mtu):
        drkey, misc = _try_sciond_api(spkt, self._connector, None)
        logging.debug(drkey)
        data = drkey.drkey + b" " + self.data
        extns_len = 0
        for extn in spkt.ext_hdrs:
            extns_len += len(extn)
        pld_len = mtu - spkt.cmn_hdr.hdr_len_bytes() - len(spkt.l4_hdr) - extns_len
        return self._gen_max_pld(data, pld_len)

    def _gen_max_pld(self, data, pld_len):
        padding = pld_len - len(data)
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


def _try_sciond_api_src(spkt, connector):
    start = time.time()
    while time.time() - start < API_TOUT:
        try:
            request_parameters = get_sciond_params_src(spkt)
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
    TestEnd2End(args.client, args.server, srcs, dsts, local=False, max_runs=args.runs,
                retries=args.retries).run()


if __name__ == "__main__":
    main_wrapper(main)
