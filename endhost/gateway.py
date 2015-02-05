"""
gateway.py

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
import sys
import struct
import threading
import logging
from subprocess import call 
from pytun import TunTapDevice, IFF_TUN, IFF_NO_PI
from infrastructure.scion_elem import SCION_UDP_PORT, BUFLEN
from endhost.sciond import SCIONDaemon
from lib.packet.host_addr import IPv4HostAddr
from lib.packet.scion import SCIONPacket

# dictionary of destinations that should be reached via SCION
SCION_HOSTS={
        "192.168.5.105":(11,5), #"IP":(ISD,AD)
        }

class SCIONGateway(SCIONDaemon):
    """
    Basic SCION Gateway based on TUN device. It "hijacks" traffic destinated to
    an IP listed in SCION_HOSTS and sends it over SCION network.
    """

    def __init__(self, addr, topo_file, scion_hosts):
        """
        Create a new SCIONGateway instance.

        :param addr: the address of the gateway. 
        :type addr: :class:`HostAddr`
        :param topo_file: the name of the topology file.
        :type topo_file: str
        :param config_file: the name of the configuration file.
        :type config_file: str
        :param scion_hosts: the dictionary of SCION-enabled hosts.
        :type config_file: dictionary

        :returns: the newly-created SCIONGateway instance
        :rtype: SCIONGateway
        """
        SCIONDaemon.__init__(self, addr, topo_file)
        self.scion_hosts = scion_hosts
        self._tun_dev = TunTapDevice(flags=IFF_TUN|IFF_NO_PI)
        self._tun_dev.up()
        self.init_routing()

    def run(self):
        """
        Starts the Gateway.
        """
        threading.Thread(target=self.handle_ip_packets).start()
        SCIONDaemon.run(self)

    def handle_ip_packets(self):
        """
        Receives packets from TUN device, checks whether destination supports
        SCION and (if so) sends the packets through SCION network.
        """
        while True:
            raw_packet = self._tun_dev.read(self._tun_dev.mtu)
            ip_dst="%d.%d.%d.%d" % struct.unpack("BBBB", raw_packet[16:20])
            logging.info("From TUN")

            if ip_dst in self.scion_hosts:
                logging.info("Packet to SCION-enabled EH: %s", ip_dst)
                scion_addr = self.scion_hosts[ip_dst]
                paths = self.get_paths(scion_addr[0], scion_addr[1])
                #TODO instead calling get_paths() consider cache of fullpaths
                if paths: 
                    dst = IPv4HostAddr(ip_dst)
                    spkt = SCIONPacket.from_values(self.addr, dst, raw_packet,
                        paths[0])
                    (next_hop, port) = self.get_first_hop(spkt)
                    self.send(spkt, next_hop, port)
                    logging.info("Sending packet: %s\nFirst hop: %s:%s", spkt,
                        next_hop, port)
                else:
                    logging.warning("No path to: %s", scion_addr)
            else:
                    logging.warning("Sent to TUN device but dst not supported.")

    def handle_data_packet(self, spkt):
        """
        Decapsulates incoming SCION data packet, and sends them to a TUN device.
        """
        logging.info("Writing to device")
        self._tun_dev.write(spkt.payload)
    
    def init_routing(self):
        """
        Initiates routing rules, that redirects SCION-supported traffic to TUN
        device. 
        """
        for i in self.scion_hosts.keys():
            if i != str(self.addr):
                cmd = "/sbin/ip route add %s dev %s" % (i, self._tun_dev.name)
                call(cmd, shell=True)
                logging.info(cmd)
    
    def clean(self):
        """
        Closes open descriptors (it also removes routing entries created by
        self.init_routing()).
        """
        self._tun_dev.close()
        SCIONDaemon.clean(self)


def main():
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) != 3:
        logging.error("run: %s addr topology_file " % sys.argv[0])
        sys.exit()
    sgw=SCIONGateway(IPv4HostAddr(sys.argv[1]), sys.argv[2], SCION_HOSTS)
    try:
        sgw.run()
    except KeyboardInterrupt:
        sgw.clean()
        sys.exit(0)


if __name__ == "__main__":
    main()
