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
:mod:`sim_ping_pong` --- Ping Pong application
==============================================
"""
# Stdlib
import logging

# SCION
from lib.packet.packet_base import PayloadRaw
from lib.packet.scion import SCIONL4Packet, build_base_hdrs
from lib.packet.scion_addr import SCIONAddr
from lib.packet.scion_udp import SCIONUDPHeader
from lib.types import PathMgmtType as PMT
from lib.util import SCIONTime

# SCION Simulator
from simulator.application.sim_app import SCIONSimApplication


class SimPingApp(SCIONSimApplication):
    """
    Simulator Ping application
    """
    _APP_PORT = 5600
    PING_INTERVAL = 40
    SUCCESS = 0
    REVOCATION = 1
    TIMEOUT = 2

    def __init__(self, host, dst_addr, dst_ad, dst_isd, max_ping_pongs):
        """
        Initialize the ping application

        :param host: The host on which ping application is to be run
        :type host: SCIONSimHost
        :param dst_addr: The destination address to which ping is sent
        :type dst_addr: IPv4Address
        :param dst_ad: The destination ad to which ping is sent
        :type dst_ad: int
        :param dst_isd: The destination isd to which ping is sent
        :type dst_isd: int
        :param max_ping_pongs: Number of ping pongs to send
        :type max_ping_pongs: int
        """
        super().__init__(host, SimPingApp._APP_PORT)
        self._addr = host.addr
        self.dst_addr = dst_addr
        self.dst_ad = dst_ad
        self.dst_isd = dst_isd
        self.max_ping_pongs = max_ping_pongs
        self.num_ping_pongs = 0
        self.pong_recv_status = []
        self.ping_send_time = []

    def run(self):
        """
        Run ping application at start_time
        """
        self.simulator.add_event(self.start_time, cb=self.send_ping)

    def handle_packet(self, packet, sender):
        """
        Handling incoming packet and send pong reply

        :param packet: The packet data
        :type packet: bytes
        :param sender: The sender of the packet
        """
        pkt = SCIONL4Packet(packet)
        payload = pkt.get_payload()
        if payload == PayloadRaw(b"pong"):
            self.receive_pong(self.SUCCESS)
        else:
            pld_type = pkt.parse_payload().PAYLOAD_TYPE
            if pld_type != PMT.REVOCATION:
                logging.error("Unsupported packet Received")
                return
            self.receive_pong(self.REVOCATION)

    def send_ping(self):
        """
        Finds path to destination from host and adds application callback
        """
        logging.info("Sending ping")
        self.app_cb = self._do_send_ping
        self.get_paths_via_api(self.dst_isd, self.dst_ad)

    def _do_send_ping(self, paths_hops):
        """
        Callback function which is called after path is found out by host

        :param paths_hops: Path information
        :type paths_hops: list
        """
        curr_time = SCIONTime.get_time()
        self.ping_send_time.append(curr_time)
        if len(paths_hops) == 0:
            self.receive_pong(self.TIMEOUT)
            return
        (path, _) = paths_hops[0]

        dst = SCIONAddr.from_values(self.dst_isd, self.dst_ad, self.dst_addr)
        cmn_hdr, addr_hdr = build_base_hdrs(self._addr, dst)
        payload = PayloadRaw(b"ping")
        udp_hdr = SCIONUDPHeader.from_values(
            self._addr, SimPingApp._APP_PORT, dst, SimPongApp._APP_PORT,
            payload)
        spkt = SCIONL4Packet.from_values(cmn_hdr, addr_hdr, path, [], udp_hdr,
                                         payload)
        (next_hop, port) = self.host.get_first_hop(spkt)
        if next_hop is None:
            logging.error("Next hop is None for Interface %d",
                          spkt.path.get_fwd_if())
            return
        logging.info("Sending packet: %s\nFirst hop: %s:%s",
                     spkt, next_hop, port)
        self.host.send(spkt, next_hop, port)

    def receive_pong(self, status):
        """
        Received a response to the ping packet

        :param status: Status of the reply for ping
        :type status: int
        """
        self.num_ping_pongs += 1
        self.pong_recv_status.append(status)
        if status == 0:
            logging.info('%s: pong received', self.addr)
        else:
            logging.info("No path found")
        logging.info('ping-pong count:%d', self.num_ping_pongs)
        if self.num_ping_pongs >= self.max_ping_pongs:
            self.simulator.terminate()
        else:
            self.simulator.add_event(self.PING_INTERVAL, cb=self.send_ping)


class SimPongApp(SCIONSimApplication):
    """
    Simulator Pong application
    """
    _APP_PORT = 5601

    def __init__(self, host):
        """
        Initialize the pong application

        :param host: The host on which pong application is to be run
        :type host: SCIONSimHost
        """
        super().__init__(host, SimPongApp._APP_PORT)

    def run(self):
        """
        Nothing to be run at start
        """
        pass

    def handle_packet(self, packet, sender):
        """
        Upon receiving ping packet, replies with pong

        :param packet: The packet data
        :type packet: bytes
        :param sender: The sender of the packet
        """
        spkt = SCIONL4Packet(packet)
        payload = spkt.get_payload()
        if payload == PayloadRaw(b"ping"):
            # Reverse the packet and send "pong"
            logging.info('%s: ping received, sending pong.', self.addr)
            spkt.reverse()
            spkt.set_payload(PayloadRaw(b"pong"))
            (next_hop, port) = self.host.get_first_hop(spkt)
            assert next_hop is not None
            self.host.send(spkt, next_hop, port)
