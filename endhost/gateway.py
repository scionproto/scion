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
:mod:`gateway` --- Reference SCION Gateway based on TUN/TAP device
==================================================================
"""
# Stdlib
import logging
import struct
import sys
import threading
from ipaddress import IPv4Address
from subprocess import call

# External packages
from pytun import TunTapDevice, IFF_TUN, IFF_NO_PI

# SCION
from endhost.sciond import SCIONDaemon
from lib.defines import SCION_UDP_EH_DATA_PORT
from lib.log import init_logging
from lib.packet.packet_base import PayloadRaw
from lib.packet.scion import SCIONBasePacket, build_base_hdrs
from lib.packet.scion_addr import SCIONAddr
from lib.socket import UDPSocket
from lib.thread import thread_safety_net
from lib.types import AddrType


# Dictionary of destinations that should be reached via SCION.
# Format : "IP" : (ISD, AD)
SCION_HOSTS = {"192.168.5.105": (2, 26), }


class SCIONGateway(object):
    """
    Basic SCION Gateway based on TUN device. It "hijacks" traffic destinated to
    an IP listed in SCION_HOSTS and sends it over SCION network.

    :ivar scion_hosts: the dictionary of SCION-enabled hosts.
    :vartype scion_hosts: dict
    :ivar _tun_dev: TUN device .
    :vartype _tun_dev: :class:`TunTapDevice`
    """

    def __init__(self, addr, topo_file, scion_hosts):
        """
        Create a new SCIONGateway instance.

        :param addr: the address of the gateway.
        :type addr: :class:`ipaddress.IPv4Address`
        :param topo_file: the name of the topology file.
        :type topo_file: str
        :param config_file: the name of the configuration file.
        :type config_file: str
        :param scion_hosts: the dictionary of SCION-enabled hosts.
        :type scion_hosts: dict

        :returns: the newly-created SCIONGateway instance
        :rtype: :class:`SCIONGateway`
        """
        self.sd = SCIONDaemon.start(addr, topo_file)
        self._data_sock = UDPSocket(
            bind=(str(addr), SCION_UDP_EH_DATA_PORT), addr_type=AddrType.IPV4)
        self.scion_hosts = scion_hosts
        self._tun_dev = TunTapDevice(flags=IFF_TUN | IFF_NO_PI)
        self._tun_dev.up()
        self.init_routing()

    def run(self):
        """
        Start the Gateway.
        """
        threading.Thread(
            target=thread_safety_net, args=(self.handle_ip_packets,),
            name="SCIONGateway.handle_ip_packets",
            daemon=True).start()
        while True:
            packet, _ = self._data_sock.recv()
            self.handle_scion_packet(SCIONBasePacket(packet))

    def handle_ip_packets(self):
        """
        Receive packets from TUN device, check whether destination supports
        SCION and (if so) send the packets through SCION network.
        """
        while True:
            raw_packet = self._tun_dev.read(self._tun_dev.mtu)
            ip_dst = "%d.%d.%d.%d" % struct.unpack("BBBB", raw_packet[16:20])
            logging.info("From TUN")

            if ip_dst in self.scion_hosts:
                logging.info("Packet to SCION-enabled EH: %s", ip_dst)
                scion_addr = self.scion_hosts[ip_dst]
                paths = self.sd.get_paths(scion_addr[0], scion_addr[1])
                # TODO: instead calling get_paths() consider cache of fullpaths
                if paths:
                    dst = SCIONAddr.from_values(scion_addr[0], scion_addr[1],
                                                IPv4Address(ip_dst))
                    cmn_hdr, addr_hdr = build_base_hdrs(self.sd.addr, dst)
                    spkt = SCIONBasePacket.from_values(
                        cmn_hdr, addr_hdr, paths[0],
                        payload=PayloadRaw(raw_packet))
                    (next_hop, port) = self.sd.get_first_hop(spkt)
                    if next_hop is None:
                        logging.error("Next hop is None for Interface %d",
                                      spkt.path.get_fwd_if())
                    else:
                        logging.info("Sending packet: %s\nFirst hop: %s:%s",
                                     spkt, next_hop, port)
                        self.sd.send(spkt, next_hop, port)
                else:
                    logging.warning("No path to: %s", scion_addr)
            else:
                logging.warning("Received by TUN device but dst not supported.")

    def handle_scion_packet(self, spkt):
        """
        Decapsulate incoming SCION data packet, and send them to a TUN device.

        :param spkt: the SCION packet to forward.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        """
        logging.info("Writing to device")
        self._tun_dev.write(spkt.get_payload())

    def init_routing(self):
        """
        Initiate routing rules, that redirects SCION-supported traffic to TUN
        device.
        """
        for ip in self.scion_hosts.keys():
            if ip != str(self.sd.addr.host_addr):
                cmd = "/sbin/ip route add %s dev %s" % (ip, self._tun_dev.name)
                call(cmd, shell=True)
                logging.info(cmd)

    def clean(self):
        """
        Close open descriptors (also remove routing entries created by
        self.init_routing()).
        """
        self._tun_dev.close()
        self.sd.clean()


def main():
    """
    Main function.
    """
    init_logging()
    if len(sys.argv) != 3:
        logging.error("run: %s addr topology_file", sys.argv[0])
        sys.exit()
    # FIXME(kormat): make IP-version agnostic
    sgw = SCIONGateway(IPv4Address(sys.argv[1]), sys.argv[2], SCION_HOSTS)
    try:
        sgw.run()
    except KeyboardInterrupt:
        sgw.clean()
        sys.exit(0)


if __name__ == "__main__":
    main()
