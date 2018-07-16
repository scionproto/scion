#!/usr/bin/python3
# Copyright 2016 ETH Zurich
# Copyright 2018 ETH Zurich, Anapaya Systems
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
:mod:`base_cli_srv` --- Base classes for single packet end2end testing
======================================================================
"""
# Stdlib
import argparse
import logging
import os
import socket
import time
import sys
from abc import ABCMeta, abstractmethod

# SCION
import lib.app.sciond as lib_sciond
from lib.defines import (
    DEFAULT6_CLIENT,
    DEFAULT6_SERVER,
    GEN_PATH,
    OVERLAY_FILE,
    SCIOND_API_SOCKDIR,
    SCION_UDP_EH_DATA_PORT
)
from lib.log import init_logging
from lib.packet.packet_base import PayloadRaw
from lib.packet.scion import SCIONL4Packet, build_base_hdrs
from lib.packet.scion_udp import SCIONUDPHeader
from lib.socket import ReliableSocket
from lib.thread import kill_self
from lib.util import (
    handle_signals,
    read_file,
)

API_TOUT = 15
READY_SIGNAL = "Listening ia="


class ResponseRV:
    FAILURE = 0
    SUCCESS = 1
    RETRY = 2
    CONTINUE = 3
    RETRY_NOW = 4


class TestBase(object, metaclass=ABCMeta):
    def __init__(self, data, addr, timeout=1.0, api_addr=None, port=0):
        self.api_addr = api_addr or get_sciond_api_addr(addr)
        self.data = data
        self.finished = False
        self.addr = addr
        self._timeout = timeout
        self.port = port
        self.sock = self._create_socket(addr)
        assert self.sock
        self.success = None
        self._connector = lib_sciond.init(self.api_addr)

    @abstractmethod
    def run(self):
        raise NotImplementedError

    def _create_socket(self, addr):
        sock = ReliableSocket(reg=(addr, self.port, True, None))
        sock.settimeout(self._timeout)
        return sock

    def _recv(self):
        try:
            packet = self.sock.recv()[0]
        except socket.timeout:
            return None
        except Exception as e:
            logging.critical("Error receiving packet: %s" % e)
            sys.exit(1)
        return SCIONL4Packet(packet)

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
        logging.debug("Sending (via %s:%s):\n%s", next_hop, port, spkt)
        self.sock.send(spkt.pack(), (next_hop, port))

    def _shutdown(self):
        self.sock.close()
        if not self.success:
            sys.exit(1)


class TestClientBase(TestBase):
    """
    Base client app
    """
    def __init__(self, data, addr, dst, dport, api=True,
                 timeout=3.0, retries=0, api_addr=None):
        self.dst = dst
        self.dport = dport
        self.api = api
        self.path_meta = None
        self.first_hop = None
        self.retries = retries
        self._req_id = 0
        super().__init__(data, addr, timeout, api_addr)
        self._get_path(api)

    def _get_path(self, api, flush=False):
        """Request path via SCIOND API."""
        path_entries = self._try_sciond_api(flush)
        logging.debug("Path entries (%s) from SCIOND:\n%s", len(path_entries),
                      "\n".join([str(entry) for entry in path_entries]))
        path_entry = path_entries[0]
        self.path_meta = path_entry.path()
        fh_info = path_entry.first_hop()
        fh_addr = fh_info.ipv4() or fh_info.ipv6()
        if not fh_addr:
            fh_addr = self.dst.host
        port = fh_info.p.port or SCION_UDP_EH_DATA_PORT
        self.first_hop = (fh_addr, port)
        return self.path_meta is not None

    def _try_sciond_api(self, flush=False):
        flags = lib_sciond.PathRequestFlags(refresh=flush)
        start = time.time()
        while time.time() - start < API_TOUT:
            try:
                path_entries = lib_sciond.get_paths(
                    self.dst.isd_as, flags=flags, connector=self._connector)
            except lib_sciond.SCIONDConnectionError as e:
                logging.error("Connection to SCIOND failed: %s " % e)
                break
            except lib_sciond.SCIONDLibError as e:
                logging.error("Error during path lookup: %s" % e)
                continue
            return path_entries
        logging.critical("Unable to get path from local api.")
        kill_self()

    def run(self):
        while not self.finished:
            self._send()
            start = time.time()
            spkt = self._recv()
            recv_dur = time.time() - start
            if not spkt:
                logging.info("Timeout waiting for response.")
                self._retry_or_stop(flush=True)
                continue
            r_code = self._handle_response(spkt)
            if r_code in [ResponseRV.FAILURE, ResponseRV.SUCCESS]:
                self._stop(success=bool(r_code))
            elif r_code == ResponseRV.CONTINUE:
                continue
            elif r_code == ResponseRV.RETRY_NOW:
                self._retry_or_stop()
            else:
                # Rate limit retries to 1 request per second.
                self._retry_or_stop(1.0 - recv_dur)
        self._shutdown()

    def _retry_or_stop(self, delay=0.0, flush=False):
        if delay < 0:
            delay = 0
        if self.retries:
            now = time.time()
            self.path_meta = None
            while True:
                if self._get_path(self.api, flush=flush):
                    break
                if time.time() - now > 5.0:
                    logging.error("Could not find paths for 5s, giving up")
                    self._stop(False)
                    return
                time.sleep(0.5)
            self.retries -= 1
            logging.info(
                "Retrying in %.1f s... (%d retries remaining, flush=%s)." %
                (delay, self.retries, flush))
            time.sleep(delay)
        else:
            self._stop()

    def _stop(self, success=False):
        self.success = success
        self.finished = True

    def _send(self):
        self._send_pkt(self._build_pkt(), self.first_hop)
        logging.debug("Path meta: %s" % self.path_meta)

    def _build_pkt(self, path=None):
        cmn_hdr, addr_hdr = build_base_hdrs(self.dst, self.addr)
        l4_hdr = self._create_l4_hdr()
        extensions = self._create_extensions()
        if path is None:
            path = self.path_meta.fwd_path()
        spkt = SCIONL4Packet.from_values(
            cmn_hdr, addr_hdr, path, extensions, l4_hdr)
        spkt.set_payload(self._create_payload(spkt))
        spkt.update()
        return spkt

    def _get_next_hop(self, spkt):
        fh_info = lib_sciond.get_overlay_dest(spkt, connector=self._connector)
        return fh_info.ipv4() or fh_info.ipv6(), fh_info.p.port

    def _create_payload(self, spkt):
        return PayloadRaw(self.data)

    def _create_l4_hdr(self):
        return SCIONUDPHeader.from_values(
            self.addr, self.sock.port, self.dst, self.dport)

    def _create_extensions(self):
        return []

    @abstractmethod
    def _handle_response(self, spkt):
        raise NotImplementedError


class TestServerBase(TestBase):
    """
    Base server app
    """
    def run(self):
        if hasattr(self.sock, 'port'):
            print("Port=%s" % self.sock.port)
        print("%s%s" % (READY_SIGNAL, self.addr.isd_as))
        sys.stdout.flush()
        while not self.finished:
            spkt = self._recv()
            if spkt is not None and not self._handle_request(spkt):
                self.success = False
                self.finished = True
        self._shutdown()

    @abstractmethod
    def _handle_request(self, spkt):
        raise NotImplementedError


def get_sciond_api_addr(addr):
    return os.path.join(SCIOND_API_SOCKDIR, "sd%s.sock" % addr.isd_as.file_fmt())


def get_overlay():
    file_path = os.path.join(GEN_PATH, OVERLAY_FILE)
    return read_file(file_path).strip()


def setup_main(name, parser=None):
    handle_signals()
    parser = parser or argparse.ArgumentParser()
    parser.add_argument('-l', '--loglevel', default=logging.DEBUG,
                        help='Console logging level (Default: %(default)s)')
    parser.add_argument('-c', '--client', help='Client address')
    parser.add_argument('-s', '--server', help='Server address')
    parser.add_argument('-m', '--mininet', action='store_true',
                        help="Running under mininet")
    parser.add_argument("--retries", type=int, default=0,
                        help="Number of retries before giving up.")
    parser.add_argument('--run_server', action='store_true', default=False,
                        help="Run as server")
    parser.add_argument('--data', default=None, help="Data for client / server split run")
    parser.add_argument('--port', default=0, help="Port for client / server split run")
    parser.add_argument('src_ia', nargs='?', help='Src isd-as')
    parser.add_argument('dst_ia', help='Dst isd-as')
    args = parser.parse_args()
    init_logging(None, file_level=logging.NOTSET, console_level=args.loglevel)

    overlay = get_overlay()
    if "IPv6" in overlay:
        if not args.client:
            args.client = DEFAULT6_CLIENT
        if not args.server:
            args.server = DEFAULT6_SERVER
    else:
        if not args.client:
            args.client = "169.254.0.2" if args.mininet else "127.0.0.2"
        if not args.server:
            args.server = "169.254.0.3" if args.mininet else "127.0.0.3"

    if not args.data:
        args.data = 'data'

    return args
