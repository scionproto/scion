# Copyright 2014 ETH Zurich
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
:mod:`make_scion_packet` --- Utility to create a SCION packet
=============================================================
"""
# External packages
from scapy.utils import PcapWriter
from scapy.all import Ether, IP, UDP

# SCION
from lib.packet.scion import SCIONPacket
from lib.packet.path import CorePath
from lib.packet.host_addr import IPv4HostAddr

path = CorePath(
    b"\x80\xa6\x01\x01\x00\x03\x00\x00\x00\x3f\x00\x00\x00\x6e"
    b"\x7d\x55\x00\x1f\x00\x24\x00\xce\x9d\xf0\x20\x00\x00\x0d"
    b"\x00\x47\x32\xa3\x80\xaa\x01\x01\x00\x03\x00\x00\x20\x00"
    b"\x00\x0e\x00\x0a\x49\x93\x00\x29\x00\x2f\x00\x25\xd7\x53"
    b"\x00\x4a\x00\x00\x00\x2a\x44\xc8")
pkt = SCIONPacket.from_values(src=IPv4HostAddr("1.2.3.4"),
                              dst=IPv4HostAddr("5.6.7.8"),
                              payload=b"ABC", path=path)
print(len(pkt.pack()))
pcap = PcapWriter('scion_test_packet.pcap')
e = (Ether(dst="11:22:33:44:55:66", src="aa:bb:cc:dd:ee:ff")/IP() /
     UDP(sport=1234, dport=33333)/pkt.pack())
pcap.write(e)
