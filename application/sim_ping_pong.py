"""
end2end_test.py

Copyright 2014 ETH Zurich

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
from lib.packet.host_addr import IPv4HostAddr
from lib.packet.path import (PathType, CorePath, PeerPath, CrossOverPath,
                             EmptyPath, PathBase)
from lib.packet.scion import SCIONPacket
from lib.simulator import schedule, terminate
import logging
import sys
import struct

class SimPingApp(SCIONSimApplication):
    _APP_PORT = 5600
    def __init__(self, host, dst_addr, dst_ad, dst_isd):
        SCIONSimApplication.__init__(self, host, SimPingApp._APP_PORT)
        self.pong_received = False
        self.dst_isd = dst_isd
        self.dst_ad = dst_ad
        self.dst_addr = dst_addr
        
    def run(self):
        schedule (self.start_time, cb=self.send_ping)

    def handle_packet(self, packet, sender):
        if SCIONPacket(packet).payload == b"pong":
            logging.info('%s: pong received', self.addr)
            self.pong_received = True
            terminate()

    def send_ping(self):
        self.app_cb = self._do_send_ping
        self.get_paths_via_api (self.dst_isd, self.dst_ad)

    def _do_send_ping(self, paths_hops):
        (path, hop) = paths_hops[0]

        spkt = SCIONPacket.from_values(src=IPv4HostAddr(self.addr), dst=IPv4HostAddr(self.dst_addr), payload=b"ping", path=path)
        (next_hop, port) = self.host.get_first_hop(spkt)
        assert next_hop == hop

        logging.info("Sending packet: %s\nFirst hop: %s:%s", spkt, next_hop, port)
        self.host.send(spkt, next_hop, port)

class SimPongApp(SCIONSimApplication):
    _APP_PORT = 5601

    def __init__(self, host):
        SCIONSimApplication.__init__(self, host, SimPongApp._APP_PORT)
        self.ping_received = False

    def run(self):
        pass

    def handle_packet(self, packet, sender):
        spkt = SCIONPacket(packet)
        if spkt.payload == b"ping":
            # Reverse the packet and send "pong"
            logging.info('%s: ping received, sending pong.', self.addr)
            self.ping_received = True
            spkt.hdr.reverse()
            spkt.payload = b"pong"
            (next_hop, port) = self.host.get_first_hop(spkt)
            self.host.send(spkt, next_hop, port)
