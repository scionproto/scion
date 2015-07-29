#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>

#include <rte_common.h>
#include <rte_vect.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>


#define DPDK_WAN_PORT 0
#define DPDK_LOCAL_PORT 1

#define INGRESS_IF(HOF) ( ntohl (HOF->ingress_egress_if) >> (12 + 8) ) //12bit is  egress if and 8 bit gap between uint32 and 24bit field 
#define EGRESS_IF(HOF) ( (ntohl (HOF->ingress_egress_if) >> 8) & 0x000fff )

#include "scion.h"

typedef struct
{
  uint32_t addr;		//IP address of an edge router
  uint16_t udp_port;		//UDP port 
  uint8_t dpdk_port;		//Phicical port (NIC)
  uint16_t scion_ifid;
  uint8_t is_local_port;
} NextHop;


#define MAX_NUM_ROUTER 16
#define MAX_NUM_BEACON_SERVERS 1 
NextHop iflist[MAX_NUM_ROUTER];
uint32_t beacon_servers[MAX_NUM_BEACON_SERVERS];
uint32_t certificate_servers[10];


// Todo: read from topology file.
#define TO_ADDR IPv4(2, 2, 2, 2)
#define TO_PORT 33040

void
scion_init ()
{
//fill interface list
  //TODO read topology configuration

  iflist[0].addr = IPv4 (1, 1, 1, 1);
  iflist[0].udp_port = 33040;
  iflist[0].scion_ifid = 111;
  iflist[0].dpdk_port = 0;
  iflist[0].is_local_port = 0;

  iflist[1].addr = IPv4 (2, 2, 2, 2);
  iflist[1].udp_port = 33040;
  iflist[1].scion_ifid = 286;
  iflist[1].dpdk_port = 1;
  iflist[1].is_local_port = 1;

  //iflist[2].addr = IPv4 (3, 3, 3, 3);
  //iflist[2].udp_port = 33040;
  //iflist[2].dpdk_port = 6;
  //iflist[2].scion_ifid = 287;
  //iflist[2].is_local_port = 1;

  beacon_servers[0] = IPv4 (7, 7, 7, 7);
  certificate_servers[0] = IPv4 (8, 8, 8, 8);

}


int l2fwd_send_packet (struct rte_mbuf *m, uint8_t port);

uint8_t get_type(SCIONHeader *hdr) {
  SCIONAddr *src = (SCIONAddr *)(&hdr->srcAddr);
  SCIONAddr *dst = (SCIONAddr *)(&hdr->dstAddr);

  int b1 = src->host_addr[3] == BEACON_PACKET || 
        src->host_addr[3] == PATH_MGMT_PACKET || 
        src->host_addr[3] == CERT_CHAIN_REP_PACKET || 
        src->host_addr[3] == TRC_REP_PACKET;
  int b2 = dst->host_addr[3] == PATH_MGMT_PACKET ||
        dst->host_addr[3] == TRC_REQ_PACKET || 
        dst->host_addr[3] == TRC_REQ_LOCAL_PACKET || 
        dst->host_addr[3] == CERT_CHAIN_REQ_PACKET || 
        dst->host_addr[3] == CERT_CHAIN_REQ_LOCAL_PACKET || 
        dst->host_addr[3] == IFID_PKT_PACKET;


  if (src->host_addr[0] == 10 && src->host_addr[1] == 224 
    && src->host_addr[2] == 0 && b1) 
    return src->host_addr[3];
  else if (dst->host_addr[0] == 10 && dst->host_addr[1] == 224 
           && dst->host_addr[2] == 0 && b2)
    return dst->host_addr[3];
  else return DATA_PACKET;
  return &hdr->srcAddr;
}

uint8_t
is_on_up_path (InfoOpaqueField * currOF)
{
  //printf("type=%x\n",currOF->type );
  if ((currOF->type & 0x1) == 1)
    {				//low bit of type field is used for uppath/downpath flag
      return 1;
    }
  return 0;
}

uint8_t
is_reqular (HopOpaqueField * currOF)
{
  //printf("type=%x\n",currOF->type );
  if ((currOF->type & (1<<5) ) == 0)
    {			
      return 0;
    }
  return 1;
}


void
normal_forward (struct rte_mbuf *m, uint32_t from_local_ad)
{
  struct ether_hdr *eth_hdr;
  struct ipv4_hdr *ipv4_hdr;
  struct udp_hdr *udp_hdr;
  SCIONHeader *scion_hdr;
  SCIONCommonHeader *sch;
  HopOpaqueField *hof;
  InfoOpaqueField *iof;

  printf("normal forward\n");
  ipv4_hdr =
    (struct ipv4_hdr *) (rte_pktmbuf_mtod (m, unsigned char *) +
			 sizeof (struct ether_hdr));
  udp_hdr =
    (struct udp_hdr *) (rte_pktmbuf_mtod (m, unsigned char *) +
			sizeof (struct ether_hdr) + sizeof (struct ipv4_hdr));
  scion_hdr =
    (SCIONHeader *) (rte_pktmbuf_mtod (m, unsigned char *) +
		     sizeof (struct ether_hdr) + sizeof (struct ipv4_hdr) +
		     sizeof (struct udp_hdr));
  sch = &(scion_hdr->commonHeader);
  hof = (HopOpaqueField *) ((unsigned char *) sch + sch->currentOF);	// currentOF is an offset from common header
  iof = (InfoOpaqueField *) ((unsigned char *) sch + sch->currentIOF);	// currentOF is an offset from common header


  printf("Index %d, InEggress %04x\n",sch->currentOF, ntohl(hof->ingress_egress_if));
  uint16_t ingress_if = ntohl (hof->ingress_egress_if) >> (12 + 8);	//12bit is  egress if and 8 bit gap between uint32 and 24bit field 
  uint16_t egress_if = (ntohl (hof->ingress_egress_if) >> 8) & 0x000fff;
  printf("Ingress %d, Egress %d\n",ingress_if, egress_if );
  //unsigned char *dump;
  //int i;
  //dump=hof;
  //for(i=0;i<8;i++) printf("%x",dump[i]);
  //printf("\n");

  //Get next scion egress interface
  uint16_t next_ifid = 0xff;
  if (is_on_up_path (iof) )
    {
      next_ifid = ingress_if;
    }
  else
    {
      next_ifid = egress_if;
    }

  if (from_local_ad)
    {
      //Send this SCION packet to the neighbor AD

      //Increment index of OF
      sch->currentOF += sizeof (HopOpaqueField);

      //send_single_packet(m, DPDK_WAN_PORT);
  	printf("send packet to neighbor AD\n");
      l2fwd_send_packet (m, DPDK_WAN_PORT);
    }
  else
    {
      //Send this SCION packet to the egress router in this AD
      uint8_t egress_dpdk_port = 0xff;
      int i;
	printf("send packet to egress router\n");

      // Convert Egress ID to IP adress of the edge router

	printf("next ifid %d", next_ifid);

      if (next_ifid != 0)
	{
	  for (i = 0; i < MAX_NUM_ROUTER; i++)
	    {
	      if (iflist[i].scion_ifid == next_ifid)
		{
		  break;
		}
	    }
	  //Specify output dpdk port.
	  egress_dpdk_port = iflist[i].dpdk_port;
	  //Update destination IP address and UDP port number
	  ipv4_hdr->dst_addr = iflist[i].addr;
	  udp_hdr->dst_port = iflist[i].udp_port;
	  //}else if (ptype ==  PATH_MGMT or ptype == PT.PATH_MGMT){  // TODO handle path mgmt packet
	}
      else
	{
	printf("send to host\n");
	  // last opaque field on the path, send the packet to the dstestination host

	  //update destination IP address to the end hostadress
	  rte_memcpy ((void*)&ipv4_hdr->dst_addr,
		      (void *)&scion_hdr->dstAddr + SCION_ISD_LEN + SCION_AD_LEN,
		      SCION_HOST_ADDR_LEN);
	}
      //send_single_packet(m, egress_dpdk_port);
      printf("DPDK port = %d\n", egress_dpdk_port);

      l2fwd_send_packet (m, egress_dpdk_port);
    }
}

void
crossover_forward (struct rte_mbuf *m, uint32_t from_local_ad)
{
  printf ("not implemented\n");


  struct ether_hdr *eth_hdr;
  struct ipv4_hdr *ipv4_hdr;
  struct udp_hdr *udp_hdr;
  SCIONHeader *scion_hdr;
  SCIONCommonHeader *sch;
  HopOpaqueField *hof;
  InfoOpaqueField *iof;

  ipv4_hdr =
    (struct ipv4_hdr *) (rte_pktmbuf_mtod (m, unsigned char *) +
			 sizeof (struct ether_hdr));
  udp_hdr =
    (struct udp_hdr *) (rte_pktmbuf_mtod (m, unsigned char *) +
			sizeof (struct ether_hdr) + sizeof (struct ipv4_hdr));
  scion_hdr =
    (SCIONHeader *) (rte_pktmbuf_mtod (m, unsigned char *) +
		     sizeof (struct ether_hdr) + sizeof (struct ipv4_hdr) +
		     sizeof (struct udp_hdr));
  sch = &(scion_hdr->commonHeader);
  hof = (HopOpaqueField *) ((unsigned char *) sch + sch->currentOF);	// currentOF is an offset from common header
  iof = (InfoOpaqueField *) ((unsigned char *) sch + sch->currentIOF);	// currentOF is an offset from common header

  uint8_t info = iof->type >> 1;	//info is MSB 7bits

  if (info == TDC_XOVR)
    {
	////C++ code
      //if (is_on_up_path(iof))
      //prev_hof = spkt.hdr.get_relative_of(-1);
      //if (verify_of(curr_hof, prev_hof, timestamp)) {
      //spkt.hdr.increase_of(1);
      //CommonOpaqueField *next_iof = spkt.hdr.get_current_of();
      //CommonOpaqueField *opaque_field = spkt.hdr.get_relative_of(1);
      //if (next_iof->up_flag)  // TODO replace by get_first_hop
      //    next_hop.addr = 
      //      ifid2addr[opaque_field->ingress_if].to_string();
      //else next_hop.addr = 
      //       ifid2addr[opaque_field->egress_if].to_string();
      //LOG(DEBUG) << "send() here, find next hop0.";
      //send(spkt, next_hop);
      // }
      // else {
      // LOG(ERROR) << "Mac verification failed.";
      // }

	if(is_on_up_path(iof)){
      		sch->currentOF += sizeof (HopOpaqueField);

		InfoOpaqueField *next_iof = (InfoOpaqueField *) ((unsigned char *) sch + sch->currentOF);


		uint16_t ingress_if = ntohl (hof->ingress_egress_if) >> (12 + 8);	//12bit is  egress if and 8 bit gap between uint32 and 24bit field 
		uint16_t egress_if = (ntohl (hof->ingress_egress_if) >> 8) & 0x000fff;
  		uint16_t next_ifid = 0xff;
		if (is_on_up_path (iof))	// 0 for DEBUG
		{
			next_ifid = ingress_if;
		}
		else
		{
			next_ifid = egress_if;
		}
		

		if (next_ifid != 0)
		{
			uint8_t egress_dpdk_port = 0xff;
			int i;
			for (i = 0; i < MAX_NUM_ROUTER; i++)
			{
				if (iflist[i].scion_ifid == next_ifid)
				{
					break;
				}
			}
			//Specify output dpdk port.
			egress_dpdk_port = iflist[i].dpdk_port;
			//Update destination IP address and UDP port number
			ipv4_hdr->dst_addr = iflist[i].addr;
			udp_hdr->dst_port = iflist[i].udp_port;
      		
			l2fwd_send_packet (m, egress_dpdk_port);
		}



	}

    }
  else if (info == NON_TDC_XOVR)
    {
	////C++ code
      //prev_hof = spkt.hdr.get_relative_of(1);
      //if (verify_of(curr_hof, prev_hof, timestamp)) {
      //    spkt.hdr.increase_of(2);
      //    CommonOpaqueField *opaque_field = spkt.hdr.get_relative_of(2);
      //    next_hop.addr = 
      //        ifid2addr[opaque_field->egress_if].to_string();
      //    LOG(DEBUG) << "send() here, find next hop1";
      //    send(spkt, next_hop);
      // }

	    sch->currentOF += sizeof (HopOpaqueField)*2;
	    uint16_t egress_if = (ntohl (hof->ingress_egress_if) >> 8) & 0x000fff;
	uint16_t next_ifid=egress_if;
	    if (next_ifid != 0)
	    {
		    uint8_t egress_dpdk_port = 0xff;
		    int i;
		    for (i = 0; i < MAX_NUM_ROUTER; i++)
		    {
			    if (iflist[i].scion_ifid == next_ifid)
			    {
				    break;
			    }
		    }
		    //Specify output dpdk port.
		    egress_dpdk_port = iflist[i].dpdk_port;
		    //Update destination IP address and UDP port number
		    ipv4_hdr->dst_addr = iflist[i].addr;
		    udp_hdr->dst_port = iflist[i].udp_port;
	    
		    l2fwd_send_packet (m, egress_dpdk_port);
	    }

    }
  else if (info == INPATH_XOVR)
    {
	////C++ code
      //if (verify_of(curr_hof, prev_hof, timestamp)) {
      //    bool is_regular = true;
      //   while (is_regular) {
      //       spkt.hdr.increase_of(2);
      //       is_regular = spkt.hdr.get_current_of()->is_regular();
      //   }
      //   spkt.hdr.common_hdr.curr_iof_p = spkt.hdr.common_hdr.curr_of_p;    
      //   LOG(DEBUG) << "TODO send() here, find next hop2";
      //}
	uint8_t is_regular=1;
	while(is_regular){
	    sch->currentOF += sizeof (HopOpaqueField)*2;
	    HopOpaqueField *hof = (HopOpaqueField *) ((unsigned char *) sch + sch->currentOF);
	    is_regular=is_reqular(hof);
	}
	sch->currentIOF = sch->currentOF;

    }
  else if (info == INTRATD_PEER || info == INTERTD_PEER)
    {
	////C++ code
      //spkt.hdr.increase_of(1);
      //prev_hof = spkt.hdr.get_relative_of(1);
      //if (verify_of(curr_hof, prev_hof, timestamp)) {
      //    next_hop.addr = 
      //        ifid2addr[spkt.hdr.get_current_of()->ingress_if].to_string();
      //    LOG(DEBUG) << "send() here, next: " << next_hop.to_string();
      //    send(spkt, next_hop);
      //}

	    sch->currentOF += sizeof (HopOpaqueField);
	    uint16_t ingress_if = ntohl (hof->ingress_egress_if) >> (12 + 8);	//12bit is  egress if and 8 bit gap between uint32 and 24bit field 
	uint16_t next_ifid=ingress_if;
	    if (next_ifid != 0)
	    {
		    uint8_t egress_dpdk_port = 0xff;
		    int i;
		    for (i = 0; i < MAX_NUM_ROUTER; i++)
		    {
			    if (iflist[i].scion_ifid == next_ifid)
			    {
				    break;
			    }
		    }
		    //Specify output dpdk port.
		    egress_dpdk_port = iflist[i].dpdk_port;
		    //Update destination IP address and UDP port number
		    ipv4_hdr->dst_addr = iflist[i].addr;
		    udp_hdr->dst_port = iflist[i].udp_port;
	    
		    l2fwd_send_packet (m, egress_dpdk_port);
	    }



    }
  else
    {
      //LOG(WARNING) << "Unknown case " << info;
    }


}

void
forward_packet (struct rte_mbuf *m, uint32_t from_local_ad, uint8_t ptype)
{
  // TODO check Info opack field
  // TODO check type is PEER

  //TODO check xover of nomal
  //crossover_forward(m,from_local_ad);

  normal_forward (m, from_local_ad);
}

//void
//process_scion_packet (struct rte_mbuf *m, uint32_t from_local_ad)
//{

  //TODO check it is first path

 // forward_packet (m, from_local_ad);
//}

void
process_ifid_request (struct rte_mbuf *m) {
  struct ether_hdr *eth_hdr;
  struct ipv4_hdr *ipv4_hdr;
  struct udp_hdr *udp_hdr;
  IFIDHeader *ifid_hdr;

  printf("process ifid request\n");
  ipv4_hdr =
    (struct ipv4_hdr *) (rte_pktmbuf_mtod (m, unsigned char *) +
       sizeof (struct ether_hdr));
  udp_hdr =
    (struct udp_hdr *) (rte_pktmbuf_mtod (m, unsigned char *) +
      sizeof (struct ether_hdr) + sizeof (struct ipv4_hdr));
  ifid_hdr =
    (IFIDHeader *) (rte_pktmbuf_mtod (m, unsigned char *) +
         sizeof (struct ether_hdr) + sizeof (struct ipv4_hdr) +
         sizeof (struct udp_hdr));

  ifid_hdr->reply_id = iflist[0].scion_ifid;  // complete with current interface (self.interface.if_id)

  int i;
  for (i = 0; i < MAX_NUM_BEACON_SERVERS; i++) {
    ipv4_hdr->dst_addr = beacon_servers[i];
    udp_hdr->dst_port = SCION_UDP_PORT;
    l2fwd_send_packet(m, DPDK_WAN_PORT);
  }
}

void
process_pcb (struct rte_mbuf *m, uint8_t from_bs) {
  struct ether_hdr *eth_hdr;
  struct ipv4_hdr *ipv4_hdr;
  struct udp_hdr *udp_hdr;
  PathConstructionBeacon *pcb;
  // SCIONCommonHeader *sch;
  // HopOpaqueField *hof;
  // InfoOpaqueField *iof;

printf("process pcb\n");

  ipv4_hdr =
    (struct ipv4_hdr *) (rte_pktmbuf_mtod (m, unsigned char *) +
       sizeof (struct ether_hdr));
  udp_hdr =
    (struct udp_hdr *) (rte_pktmbuf_mtod (m, unsigned char *) +
      sizeof (struct ether_hdr) + sizeof (struct ipv4_hdr));
  pcb =
    (PathConstructionBeacon *) (rte_pktmbuf_mtod (m, unsigned char *) +
         sizeof (struct ether_hdr) + sizeof (struct ipv4_hdr) +
         sizeof (struct udp_hdr));

  if (from_bs) {
    uint8_t last_pcbm_index = sizeof(pcb->payload.ads) / sizeof(ADMarking) - 1;
    HopOpaqueField *last_hof = &(pcb->payload).ads[last_pcbm_index].pcbm.hof;

    if (iflist[0].scion_ifid != EGRESS_IF(last_hof)) {
      // Wrong interface set by BS.
      return;
    }

    ipv4_hdr->dst_addr = TO_ADDR; 
    udp_hdr->dst_port = TO_PORT; 
    l2fwd_send_packet(m, DPDK_WAN_PORT); // replace with remote socket?

  }
  else {
    pcb->payload.if_id = iflist[0].scion_ifid;
    ipv4_hdr->dst_addr = beacon_servers[0];
    udp_hdr->dst_port = SCION_UDP_PORT;
    l2fwd_send_packet(m, DPDK_WAN_PORT);
  }
}

void 
relay_cert_server_packet (struct rte_mbuf *m, uint8_t from_local_socket) {
  struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *) (rte_pktmbuf_mtod (m, unsigned char *) +
       sizeof (struct ether_hdr));
 
	if(from_local_socket){
		ipv4_hdr->dst_addr = iflist[0].addr;
    		l2fwd_send_packet(m, DPDK_WAN_PORT);
	}else{
		ipv4_hdr->dst_addr = certificate_servers[0];
    		l2fwd_send_packet(m, DPDK_LOCAL_PORT);
	}
}

void write_to_egress_iface(struct rte_mbuf *m){
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ipv4_hdr;
	struct udp_hdr *udp_hdr;
	SCIONHeader *scion_hdr;
	SCIONCommonHeader *sch;
	HopOpaqueField *hof;
	InfoOpaqueField *iof;

	ipv4_hdr =
		(struct ipv4_hdr *) (rte_pktmbuf_mtod (m, unsigned char *) +
				sizeof (struct ether_hdr));
	udp_hdr =
		(struct udp_hdr *) (rte_pktmbuf_mtod (m, unsigned char *) +
				sizeof (struct ether_hdr) + sizeof (struct ipv4_hdr));
	scion_hdr =
		(SCIONHeader *) (rte_pktmbuf_mtod (m, unsigned char *) +
				sizeof (struct ether_hdr) + sizeof (struct ipv4_hdr) +
				sizeof (struct udp_hdr));
	sch = &(scion_hdr->commonHeader);
	hof = (HopOpaqueField *) ((unsigned char *) sch + sch->currentOF);	// currentOF is an offset from common header
	iof = (InfoOpaqueField *) ((unsigned char *) sch + sch->currentIOF);	// currentOF is an offset from common header


	uint8_t info = hof->type ;
	if (info == TDC_XOVR){
		sch->currentIOF = sch->currentOF;
		sch->currentOF += sizeof (HopOpaqueField);
	}else if( info == NON_TDC_XOVR){
		sch->currentIOF = sch->currentOF;
		sch->currentOF += sizeof (HopOpaqueField)*2;
	}

	sch->currentOF += sizeof (HopOpaqueField);

	hof = (HopOpaqueField *) ((unsigned char *) sch + sch->currentOF);	// currentOF is an offset from common header
	
	info = hof->type ;
	if( info == INTRATD_PEER || info == INTERTD_PEER){
		if(is_on_up_path(iof)){
			HopOpaqueField *previous_hof = (HopOpaqueField *) ((unsigned char *) sch + sch->currentOF);
			uint8_t previous_info = previous_hof->type;
			if( previous_info == INTRATD_PEER || previous_info == INTERTD_PEER){
				sch->currentOF += sizeof (HopOpaqueField);
				
}
		}else{
			
			hof = (HopOpaqueField *) ((unsigned char *) sch + sch->currentOF);
			if(hof->type ==LAST_OF){
				sch->currentOF += sizeof (HopOpaqueField);
			}
		}
	}
 
    l2fwd_send_packet(m, DPDK_WAN_PORT);
}

void 
process_packet (struct rte_mbuf *m, uint8_t from_local_socket, uint8_t ptype) {
  printf("process packet\n");

  if (from_local_socket) 
    write_to_egress_iface(m);
  else
    forward_packet(m, from_local_socket, ptype);
}

void
handle_request (struct rte_mbuf *m, uint8_t from_local_socket, uint32_t ptype)
{
  struct ether_hdr *eth_hdr;
  struct ipv4_hdr *ipv4_hdr;
  struct udp_hdr *udp_hdr;
  SCIONHeader *scion_hdr;

  printf("handle_request\n");

  eth_hdr = rte_pktmbuf_mtod (m, struct ether_hdr *);

  //if (m->ol_flags & PKT_RX_IPV4_HDR || eth_hdr->ether_type == 30040)
  //if (m->ol_flags & PKT_RX_IPV4_HDR )
  if (m->ol_flags & PKT_RX_IPV4_HDR || eth_hdr->ether_type == ntohs(0x0800))
    {
	printf("test %x\n",eth_hdr->ether_type);
      ipv4_hdr =
	(struct ipv4_hdr *) (rte_pktmbuf_mtod (m, unsigned char *) +
			     sizeof (struct ether_hdr));
      udp_hdr =
	(struct udp_hdr *) (rte_pktmbuf_mtod (m, unsigned char *) +
			    sizeof (struct ether_hdr) +
			    sizeof (struct ipv4_hdr));

      scion_hdr =
	(SCIONHeader *) (rte_pktmbuf_mtod (m, unsigned char *) +
			 sizeof (struct ether_hdr) +
			 sizeof (struct ipv4_hdr) + sizeof (struct udp_hdr));

      //Pratyaksh
      uint8_t ptype = get_type(scion_hdr);
      if (ptype == IFID_PKT_PACKET && !from_local_socket) {
        process_ifid_request(m);
      }
      else if (ptype == BEACON_PACKET)
        process_pcb(m, from_local_socket);
      else if (ptype == CERT_CHAIN_REQ_PACKET || ptype == CERT_CHAIN_REP_PACKET
               || ptype == TRC_REQ_PACKET || ptype == TRC_REP_PACKET)
        relay_cert_server_packet(m, from_local_socket);

      else if (ptype == DATA_PACKET)
        process_packet(m, from_local_socket, ptype);
      else{
	printf("%d %d ?????\n",ptype, DATA_PACKET);
      }

    }
}
