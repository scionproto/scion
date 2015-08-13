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

import sys

# SCION
from lib.packet.scion import SCIONPacket

# External packages
from scapy.utils import PcapWriter, rdpcap
from scapy.all import Ether, IP, UDP

pcap = rdpcap(sys.argv[1])
for packet in pcap:
    print(packet)
    payload = packet[0][UDP].load
    spkt = SCIONPacket(payload)
    print(spkt)
