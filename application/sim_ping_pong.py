"""
sim_ping_pong.py

Copyright 2015 ETH Zurich

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from application.sim_app import SCIONSimApplication
from lib.packet.scion import SCIONPacket
from lib.packet.scion_addr import SCIONAddr
import logging
from simulator.simulator import schedule, terminate

class SimPingApp(SCIONSimApplication):
    """
    The Sim Ping application
    addr: SCIONAddr
    """
    _APP_PORT = 5600
    def __init__(self, host, dst_addr, dst_ad, dst_isd):
        SCIONSimApplication.__init__(self, host, SimPingApp._APP_PORT)
        self._addr = host.addr
        self.pong_received = False
        self.dst_isd = dst_isd
        self.dst_ad = dst_ad
        self.dst_addr = dst_addr

    def run(self):
        """
        Run ping application at start_time
        """
        schedule(self.start_time, cb=self.send_ping)

    def handle_packet(self, packet, sender):
        """
        Handling incoming packet
        Send pong reply
        """
        if SCIONPacket(packet).payload == b"pong":
            logging.info('%s: pong received', self.addr)
            self.pong_received = True
            terminate()

    def send_ping(self):
        """
        Finds path to destination from host and sends ping
        """
        logging.info("Sending ping")
        self.app_cb = self._do_send_ping
        self.get_paths_via_api(self.dst_isd, self.dst_ad)

    def _do_send_ping(self, paths_hops):
        """
        Callback function which is called after path is found out by host
        """
        (path, hop) = paths_hops[0]

        dst = SCIONAddr.from_values(self.dst_isd, self.dst_ad, self.dst_addr)
        spkt = SCIONPacket.from_values(src=self._addr,
            dst=dst, payload=b"ping", path=path)
        (next_hop, port) = self.host.get_first_hop(spkt)
        assert next_hop == hop

        logging.info("Sending packet: %s\nFirst hop: %s:%s", 
            spkt, next_hop, port)
        self.host.send(spkt, next_hop, port)

class SimPongApp(SCIONSimApplication):
    """
    The Sim Pong application
    """
    _APP_PORT = 5601

    def __init__(self, host):
        SCIONSimApplication.__init__(self, host, SimPongApp._APP_PORT)
        self.ping_received = False

    def run(self):
        """
        Nothing to be run at start
        """
        pass

    def handle_packet(self, packet, sender):
        """
        Upon receiving ping packet, replies with pong 
        """
        spkt = SCIONPacket(packet)
        if spkt.payload == b"ping":
            # Reverse the packet and send "pong"
            logging.info('%s: ping received, sending pong.', self.addr)
            self.ping_received = True
            spkt.hdr.reverse()
            spkt.payload = b"pong"
            (next_hop, port) = self.host.get_first_hop(spkt)
            self.host.send(spkt, next_hop, port)
