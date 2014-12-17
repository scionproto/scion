from lib.packet.scion import SCIONPacket
from lib.packet.scion import get_addr_from_type
from lib.packet.scion import PacketType
from lib.packet.path import CorePath
from lib.packet.host_addr import IPv4HostAddr
from scapy.utils import PcapWriter
from scapy.all import Ether,IP,UDP

path = CorePath(b"\x80\xa6\x01\x01\x00\x03\x00\x00\x00\x3f\x00\x00\x00\x6e\x7d\x55\x00\x1f\x00\x24\x00\xce\x9d\xf0\x20\x00\x00\x0d\x00\x47\x32\xa3\x80\xaa\x01\x01\x00\x03\x00\x00\x20\x00\x00\x0e\x00\x0a\x49\x93\x00\x29\x00\x2f\x00\x25\xd7\x53\x00\x4a\x00\x00\x00\x2a\x44\xc8")
pkt = SCIONPacket.from_values(src=IPv4HostAddr("1.2.3.4"), dst=IPv4HostAddr("5.6.7.8"), payload=b"ABC", path=path)
#pkt = SCIONPacket.from_values(src = get_addr_from_type(PacketType.BEACON), dst=IPv4HostAddr("5.6.7.8"), payload=b"ABC", path=path)

print len(pkt.pack())

pcap=PcapWriter('scion_test_packet.pcap')
e=Ether(dst="11:22:33:44:55:66",src="aa:bb:cc:dd:ee:ff")/IP()/UDP(sport=1234,dport=33333)/pkt.pack()
pcap.write(e)
