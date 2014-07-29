"""
router.py

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

from lib.packet.host_addr import IPv4HostAddr
from lib.packet.opaque_field import OpaqueField
from lib.packet.opaque_field import OpaqueFieldType as OFT
from lib.packet.scion import SCIONPacket, IFIDRequest, IFIDReply, get_type
from lib.packet.scion import PacketType as PT
from lib.topology import ElementType
from server import ServerBase, SCION_UDP_PORT 
import threading
import time
import socket
import sys
import struct #FIXME remove if Beacon/PCB class is ready

class Router(ServerBase):
    """
    The SCION Router.
    """
    def __init__(self, addr, topo_file, config_file):
        ServerBase.__init__(self, addr, topo_file, config_file)
        self.interface=None
        self.ifid_req_tout=2
        for router_list in self.topology.routers.values():
            for router in router_list:
                if router.addr==self.addr:
                    self.interface=router.interface
                    break
        assert self.interface!=None
        print (self.interface.__dict__)

        self._remote_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._remote_socket.bind((str(self.interface.addr), self.interface.udp_port))
        self._sockets.append(self._remote_socket)
        print("Binded: ",str(self.interface.addr), self.interface.udp_port)

    def run(self):
        threading.Thread(target=self.ifid_loop).start()
        ServerBase.run(self)

    def send(self, packet, dst, dst_port=SCION_UDP_PORT, use_local_socket=True):
        """
        Sends packet to dst (class of that object must implement __str__ which
        returns IPv4 addr) using dst_port and local or remote socket.
        """
        print("sending",dst, dst_port)
        self.handle_extensions(False)
        if use_local_socket:
            ServerBase.send(self, packet, dst, dst_port)
        else:
            self._remote_socket.sendto(packet, (str(dst), dst_port))

    def handle_extensions(self, pre_routing_phase):
        """
        Handles SCION Packet extensions. Handlers can be defined for pre- and
        post-routing.
        """
        if pre_routing_phase:
            pass#use self.pre_ext_handlers
        else:
            pass#use self.post_ext_handlers
        #TODO define extension handlers

    def ifid_loop(self):
        """
        Initial synchronization with neighboring router to qualify interface as
        initialized.
        """
        while True:
            ifid_req=IFIDRequest.from_values(self.interface.addr, self.interface.if_id)
            dst=self.interface.to_addr
            self.send(ifid_req.pack(), dst, self.interface.to_udp_port, False)
            print('IFID_REQ sent to',dst,self.interface.to_udp_port, len(ifid_req.pack()))
            time.sleep(self.ifid_req_tout)
            if self.interface.initialized:
                print('Port initialized, leaving ifid_loop()')
                break


    def process_ifid_rep(self,packet):
        """
        After receiving IFID_REP interface is initialized and all beacon server
        are informed. 
        """
        print('IFID_REP received', len(packet))
        ifid_rep=IFIDReply(packet)
        #TODO multiple BSs scenario
        bs = self.topology.servers[ElementType.BEACON_SERVER]
        ifid_rep.hdr.dst=bs.addr
        self.send(ifid_rep.pack(), bs.addr)
        print('IFID_REP sent to BeaconServer',len(ifid_rep.pack()),' addr:',str(bs.addr),SCION_UDP_PORT)
        self.interface.initialized=True
        
    def process_ifid_req(self,packet):
        """
        After receiving IFID_REQ from neighboring router, IFID_REP is sent back.
        """
        print('IFID_REQ received:', len(packet))
        p=IFIDRequest(packet)
        dst=self.interface.to_addr
        ifid_rep=IFIDReply.from_values(dst,self.interface.if_id,p.request_id)
        print (ifid_rep, len(ifid_rep.pack()))
        self.send(ifid_rep.pack(), dst, self.interface.to_udp_port, False)
        print('IFID_REP sent:',len(ifid_rep.pack()))
    
    #TODO these two functions should go to (future) Beacon class
    def get_interface(self,packet):
        return struct.unpack("H",packet[16+13:16+15])[0]
    def set_interface(self,packet):
        return packet[:29]+struct.pack("H",self.interface.if_id)+packet[31:]


    def process_pcb(self, packet, from_bs):
        """
        Depending on scenario: a) sends PCB to all beacon servers, or b) to
        neighboring router.
        """
        if not self.interface.initialized:
            print("Interface not initialized")
            return
        if from_bs:
            if self.interface.if_id != self.get_interface(packet):
                print("Wrong interface set by BS")
                return
            dst=self.interface.to_addr
            self.send(packet, dst,  self.interface.to_udp_port, False)
        else:
            #TODO: Multiple BS scenario
            packet=self.set_interface(packet)
            bs = self.topology.servers[ElementType.BEACON_SERVER]
            self.send(packet, bs.addr)

    #TODO
    def verify_of(self,spkt):
        """
        Verifies authentication of current opaque field.
        """
        return True

    def normal_forward(self, spkt, from_local_ad, ptype):
        """
        Process normal forwarding.
        """
        if not self.verify_of(spkt):
            return
        if spkt.hdr.is_on_up_path():
            iface=spkt.hdr.get_current_of().ingress_if
        else:
            iface=spkt.hdr.get_current_of().egress_if
        if from_local_ad:
            if iface==self.interface.if_id:
                dst=self.interface.to_addr
                spkt.hdr.increase_of(1)
                self.send(spkt.pack(), dst, self.interface.to_udp_port, False)
            else:
                print("interface mismatch", iface, self.interface.if_id)
        else:
            #TODO: redesing Certificate Servers
            dst = None
            if ptype in [PT.CERT_REQ, PT.ROT_REQ, PT.CERT_REP, PT.ROT_REP]:
                dst = self.topology.servers[ElementType.CERTIFICATE_SERVER].addr
            elif iface:
                dst = self.ifid2addr[iface]
            elif ptype in [PT.PATH_REG, PT.PATH_REQ, PT.PATH_REP]:
                dst = self.topology.servers[ElementType.PATH_SERVER].addr
            else:
                dst = spkt.hdr.dst_addr 
            self.send(spkt.pack(), dst)
        print("normal_forward()")

    def crossover_forward(self, spkt, from_local_ad, ptype, info):
        """
        Process crossover forwarding.
        """
        print("crossover_forward()")
        if info == OFT.TDC_XOVR:
            if self.verify_of(spkt):
                spkt.hdr.increase_of(1)
                print("send() here, find next hop0",spkt)
                of=spkt.hdr.get_relative_of(1)
                dst = self.ifid2addr[of.egress_if]
                self.send(spkt.pack(), dst)
            else:
                print("Mac verification failed")

        elif info == OFT.NON_TDC_XOVR:
            spkt.hdr.increase_of(2)#TODO PSz:verify if 2 is always correct value
            of=spkt.hdr.get_relative_of(2)
            dst = self.ifid2addr[of.egress_if]
            self.send(spkt.pack(), dst)
            print("send() here, find next hop1",dst,spkt)

        elif info == OFT.INPATH_XOVR:
            if self.verify_of(spkt):
                is_regular = True 
                while is_regular:
                    spkt.hdr.increase_of(2)
                    is_regular=spkt.hdr.get_current_of().is_regular()
                spkt.hdr.common_hdr.timestamp=spkt.hdr.common_hdr.current_of
                if self.verify_of(spkt):
                    print("send() here, find next hop2")

        elif info == OFT.INTRATD_PEER:
            if spkt.hdr.is_on_up_path():
                spkt.hdr.increase_of(1)
            if self.verify_of(spkt):
                if not spkt.hdr.is_on_up_path():
                    spkt.hdr.increase_of(2)
                dst = self.ifid2addr[spkt.hdr.get_current_of().ingress_if]
                print("send() here, next:",dst)
                self.send(spkt.pack(), dst)

        elif info == OFT.INTERTD_PEER:
            print("TODO: implement INTERTD_PEER")

        else:
            print("Unknown case", info)

    def forward_packet(self, spkt, from_local_ad, ptype):
        """
        Basing on current opaque field forwards packet.
        """
        while not spkt.hdr.get_current_of().is_regular():
            spkt.hdr.common_hdr.timestamp = spkt.hdr.common_hdr.current_of
            #TODO PSz: revise, that condition is quite strange
            if ptype not in [PT.PATH_REP, PT.CERT_REP, PT.ROT_REP] and \
                    spkt.hdr.get_current_of()==spkt.hdr.path.get_of(0):
                spkt.hdr.set_uppath()
            else:
                spkt.hdr.set_downpath()
            print("increase 0")
            spkt.hdr.increase_of(1)

        while (spkt.hdr.get_current_of().is_continue()):
            print("increase 1")
            spkt.hdr.increase_of(1)

        ts_info = spkt.hdr.get_timestamp().get_info()
        ts=spkt.hdr.common_hdr.timestamp
        if not spkt.hdr.is_on_up_path() and ts_info==OFT.INTRATD_PEER and\
                spkt.hdr.common_hdr.current_of == ts + OpaqueField.LEN:
            print("increase 2")
            spkt.hdr.increase_of(1)

        if spkt.hdr.get_current_of().is_xovr():
            self.crossover_forward(spkt, from_local_ad, ptype, ts_info)
        else:
            self.normal_forward(spkt, from_local_ad, ptype)
    
    def write_to_egress_iface(self, spkt, from_local_ad):
        """
        Forwards packet to neighboring router. 
        """
        if spkt.hdr.is_on_up_path():
            iface=spkt.hdr.get_current_of().ingress_if
        else:
            iface=spkt.hdr.get_current_of().egress_if

        ts_info = spkt.hdr.get_timestamp().get_info()
        spkt.hdr.increase_of(1)
        if ts_info == OFT.INTRATD_PEER:
            of1_info=spkt.hdr.get_relative_of(1).get_info()
            of2_info=spkt.hdr.get_current_of().get_info()
            if (of1_info==OFT.INTRATD_PEER and spkt.hdr.is_on_up_path()) or\
                (of2_info==0x20 and not spkt.hdr.is_on_up_path()):#Stride??
                spkt.hdr.increase_of(1)

        if self.interface.if_id != iface:#DEBUG
            print("Wrong interface!")
            return

        dst=self.interface.to_addr
        print("sending to dst6",str(dst))
        self.send(spkt.pack(), self.interface.to_addr, self.interface.to_udp_port, False)

    def process_packet(self, spkt, from_local_ad, ptype):
        """
        Inspects current opaque fields and decides on forwarding type.
        """
        if spkt.hdr.get_current_of()!=spkt.hdr.path.get_of(0) and\
                ptype == PT.DATA and from_local_ad:
            of_info=spkt.hdr.get_current_of().get_info()
            if of_info == OFT.TDC_XOVR:
                spkt.hdr.common_hdr.timestamp = spkt.hdr.common_hdr.current_of
                spkt.hdr.set_downpath()
                spkt.hdr.increase_of(1)
            elif of_info == OFT.NON_TDC_XOVR:
                spkt.hdr.common_hdr.timestamp = spkt.hdr.common_hdr.current_of
                spkt.hdr.set_downpath()
                spkt.hdr.increase_of(2)
            self.write_to_egress_iface(spkt, from_local_ad)
        else:
            self.forward_packet(spkt, from_local_ad, ptype)

    def handle_request(self, packet, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.
        """
        from_local_ad=from_local_socket
        spkt=SCIONPacket(packet)
        ptype=get_type(spkt)
        self.handle_extensions(True)
        if ptype==PT.IFID_REQ and not from_local_ad:
            self.process_ifid_req(packet)
        elif ptype==PT.IFID_REP and not from_local_ad:
            self.process_ifid_rep(packet)
        elif ptype==PT.BEACON:
            self.process_pcb(packet, from_local_ad)
        else: 
            if ptype==PT.DATA:
                print("DATA type:",ptype,spkt.hdr.common_hdr)
            self.process_packet(spkt, from_local_ad,ptype)

def main():
    if len(sys.argv)!=4:
        print("run: %s IP topo_file conf_file" %sys.argv[0])
        sys.exit()
    er=Router(IPv4HostAddr(sys.argv[1]), sys.argv[2], sys.argv[3])
    er.run()

if __name__ == "__main__":
    main()

