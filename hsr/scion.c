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

#include "scion.h"

#define INGRESS_IF(HOF)                                                        \
  (ntohl(HOF->ingress_egress_if) >>                                            \
   (12 +                                                                       \
    8)) // 12bit is  egress if and 8 bit gap between uint32 and 24bit field
#define EGRESS_IF(HOF) ((ntohl(HOF->ingress_egress_if) >> 8) & 0x000fff)

typedef struct {
  uint32_t addr;     // IP address of an edge router
  uint16_t udp_port; // UDP port
  uint8_t dpdk_port; // Phicical port (NIC)
  uint16_t scion_ifid;
} NextHop;

#define MAX_NUM_ROUTER 16
#define MAX_NUM_BEACON_SERVERS 1
#define MAX_IFID 2<<12
NextHop iflist[MAX_IFID];
uint32_t neighbor_ad_ifid;
uint32_t beacon_servers[MAX_NUM_BEACON_SERVERS];
uint32_t certificate_servers[10];
uint32_t path_servers[10];

// Todo: read from topology file.

uint32_t my_ifid; // the current router's IFID

void scion_init() {
  // fill interface list
  // TODO read topology configuration

  // egress port (neighbor AD's router)
  neighbor_ad_ifid = 111;
  iflist[111].addr = IPv4(1, 1, 1, 1);
  iflist[111].udp_port = 33040;
  iflist[111].dpdk_port = DPDK_EGRESS_PORT;

  // local port (other egress router in this AD)
  iflist[280].addr = IPv4(2, 2, 2, 2);
  iflist[280].udp_port = 33040;
  iflist[280].dpdk_port = DPDK_LOCAL_PORT;

  iflist[281].addr = IPv4(3, 3, 3, 3);
  iflist[281].udp_port = 33040;
  iflist[281].dpdk_port = DPDK_LOCAL_PORT;

  beacon_servers[0] = IPv4(7, 7, 7, 7);
  certificate_servers[0] = IPv4(8, 8, 8, 8);
  path_servers[0] = IPv4(8, 8, 8, 8);

  my_ifid = 333;
}

int l2fwd_send_packet(struct rte_mbuf *m, uint8_t port);


// send a packet to neighbor AD router
static inline int send_egress(struct rte_mbuf *m) {
  struct ipv4_hdr *ipv4_hdr;
  struct udp_hdr *udp_hdr;
  ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
      struct ether_hdr));
  udp_hdr = (struct udp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                                   struct ether_hdr) +
                               sizeof(struct ipv4_hdr));

  // Specify output dpdk port.
  uint8_t dpdk_port = iflist[neighbor_ad_ifid].dpdk_port;
  // Update destination IP address and UDP port number
  ipv4_hdr->dst_addr = iflist[neighbor_ad_ifid].addr;
  

  //assume port is the same, so the next line is not required
  //udp_hdr->dst_port = iflist[neighbor_ad_ifid].udp_port;

  l2fwd_send_packet(m, DPDK_EGRESS_PORT);
}

// send a packet to the edge router that has next_ifid in this AD
static inline int send_local(struct rte_mbuf *m, uint32_t next_ifid) {
  struct ipv4_hdr *ipv4_hdr;
  struct udp_hdr *udp_hdr;
  ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
      struct ether_hdr));
  udp_hdr = (struct udp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                                   struct ether_hdr) +
                               sizeof(struct ipv4_hdr));

  if (next_ifid != 0) {
    uint8_t dpdk_port;
    // Specify output dpdk port.
    dpdk_port = iflist[next_ifid].dpdk_port;
    // Update destination IP address and UDP port number
    ipv4_hdr->dst_addr = iflist[next_ifid].addr;

    //assume port is the same, so the next line is not required
    //udp_hdr->dst_port = iflist[next_ifid].udp_port;

    printf("dpdk_port=%d\n",dpdk_port);
    l2fwd_send_packet(m, dpdk_port);
    return 1;
  }
  return -1;
}

static inline uint8_t get_type(SCIONHeader *hdr) {
  SCIONAddr *src = (SCIONAddr *)(&hdr->srcAddr);
  SCIONAddr *dst = (SCIONAddr *)(&hdr->dstAddr);


  if(src->host_addr[0] == 10) return DATA_PACKET;
  if(src->host_addr[1] == 224) return DATA_PACKET;
  if(src->host_addr[2] == 0) return DATA_PACKET;

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

  if (b1)
    return src->host_addr[3];
  else if (b2)
    return dst->host_addr[3];
  else
    return DATA_PACKET;
  return &hdr->srcAddr;
}

//TODO Optimization
static inline uint8_t is_on_up_path(InfoOpaqueField *currOF) {
  if ((currOF->type & 0x1) ==
      1) { // low bit of type field is used for uppath/downpath flag
    return 1;
  }
  return 0;
}
//TODO Optimization
static inline uint8_t is_last_path_of(SCIONCommonHeader *sch) {
  uint8_t offset = SCION_COMMON_HEADER_LEN + sizeof(HopOpaqueField);
  return sch->currentOF == offset + sch->headerLen;
}
//TODO Optimization
static inline uint8_t is_regular(HopOpaqueField *currOF) {
  if ((currOF->type & (1 << 6)) == 0) {
    return 0;
  }
  return 1;
}

//TODO Optimization
static inline uint8_t is_continue(HopOpaqueField *currOF) {
  if ((currOF->type & (1 << 5)) == 0) {
    return 0;
  }
  return 1;
}
static inline uint8_t is_xovr(HopOpaqueField *currOF) {
  if ((currOF->type & (1 << 4)) == 0) {
    return 0;
  }
  return 1;
}

static inline uint8_t verify_of(HopOpaqueField *hof, HopOpaqueField *prev_hof,
                                uint32_t ts) {
  // not implemented
  return 1;
}

static inline void normal_forward(struct rte_mbuf *m, uint32_t from_local_ad,
                                  uint32_t ptype) {
  struct ether_hdr *eth_hdr;
  SCIONHeader *scion_hdr;
  SCIONCommonHeader *sch;
  HopOpaqueField *hof;
  HopOpaqueField *prev_hof;
  InfoOpaqueField *iof;

  // printf("normal forward\n");
  scion_hdr = (SCIONHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                                  struct ether_hdr) +
                              sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
  sch = &(scion_hdr->commonHeader);
  hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF +
                           SCION_COMMON_HEADER_LEN); // currentOF is an offset
                                                     // from
                                                     // common header
  iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF +
                            SCION_COMMON_HEADER_LEN); // currentOF is an offset
                                                      // from
                                                      // common header

  // printf("Ingress %d, Egress %d\n", INGRESS_IF(hof), EGRESS_IF(hof));
  // unsigned char *dump;
  // int i;
  // dump=iof;
  // for(i=0;i<8;i++) printf("%x",dump[i]);
  // printf("\n");

  // Get next scion egress interface
  uint16_t next_ifid;
  if (is_on_up_path(iof)) {
    prev_hof = hof + 1;
    next_ifid = INGRESS_IF(hof);
  } else {
    prev_hof = hof - 1;
    next_ifid = EGRESS_IF(hof);
  }

  // verify MAC
  if (verify_of(hof, prev_hof, iof->timestamp) == 0)
    return;

  if (from_local_ad) {
    // Send this SCION packet to the neighbor AD

    // Increment index of OF
    sch->currentOF += sizeof(HopOpaqueField);

    // printf("send packet to neighbor AD\n");
    send_egress(m);
  } else {
    // from neighbor AD
    if (ptype == PATH_MGMT_PACKET) {
      struct ipv4_hdr *ipv4_hdr;
      struct udp_hdr *udp_hdr;
      ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(
          m, unsigned char *)+sizeof(struct ether_hdr));
      ipv4_hdr->dst_addr = path_servers[0];

    } else {

      // Send this SCION packet to the egress router in this AD
      // printf("send packet to egress router\n");
      // Convert Egress ID to IP adress of the edge router
      printf("next ifid %d\n", next_ifid);

      int ret = send_local(m, next_ifid);
      // send_local returns -1 when the specified ifid is not found in iflist.
      if (ret < 0) {
        // send to host
        struct ipv4_hdr *ipv4_hdr;
        struct udp_hdr *udp_hdr;
        ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(
            m, unsigned char *)+sizeof(struct ether_hdr));
        udp_hdr =
            (struct udp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                                   struct ether_hdr) +
                               sizeof(struct ipv4_hdr));

        printf("send to host\n");
        // last opaque field on the path, send the packet to the dstestination
        // host

        // update destination IP address to the end hostadress
        rte_memcpy((void *)&ipv4_hdr->dst_addr,
                   (void *)&scion_hdr->dstAddr + SCION_ISD_AD_LEN,
                   SCION_HOST_ADDR_LEN);

        l2fwd_send_packet(m, DPDK_LOCAL_PORT);
      }
    }
  }
}

static inline void crossover_forward(struct rte_mbuf *m,
                                     uint32_t from_local_ad) {
  // printf("not implemented\n");

  struct ether_hdr *eth_hdr;
  struct ipv4_hdr *ipv4_hdr;
  struct udp_hdr *udp_hdr;
  SCIONHeader *scion_hdr;
  SCIONCommonHeader *sch;
  HopOpaqueField *hof;
  HopOpaqueField *prev_hof;
  InfoOpaqueField *iof;

  ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
      struct ether_hdr));
  udp_hdr = (struct udp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                                   struct ether_hdr) +
                               sizeof(struct ipv4_hdr));
  scion_hdr = (SCIONHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                                  struct ether_hdr) +
                              sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
  sch = &(scion_hdr->commonHeader);
  hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF +
                           SCION_COMMON_HEADER_LEN);
  iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF +
                            SCION_COMMON_HEADER_LEN);

  uint8_t info = iof->type >> 1; // info is MSB 7bits

  if (info == TDC_XOVR) {
    ////C++ code
    // if (is_on_up_path(iof))
    // prev_hof = spkt.hdr.get_relative_of(-1);
    // if (verify_of(curr_hof, prev_hof, timestamp)) {
    // spkt.hdr.increase_of(1);
    // CommonOpaqueField *next_iof = spkt.hdr.get_current_of();
    // CommonOpaqueField *opaque_field = spkt.hdr.get_relative_of(1);
    // if (next_iof->up_flag)  // TODO replace by get_first_hop
    //    next_hop.addr =
    //      ifid2addr[opaque_field->ingress_if].to_string();
    // else next_hop.addr =
    //       ifid2addr[opaque_field->egress_if].to_string();
    // LOG(DEBUG) << "send() here, find next hop0.";
    // send(spkt, next_hop);
    // }
    // else {
    // LOG(ERROR) << "Mac verification failed.";
    // }

    if (is_on_up_path(iof)) {
      prev_hof = hof - 1;
    }
    if (verify_of(hof, prev_hof, iof->timestamp) == 0) {
      return;
    }
    sch->currentOF += sizeof(HopOpaqueField);

    InfoOpaqueField *next_iof =
        (InfoOpaqueField *)((unsigned char *)sch + sch->currentOF +
                            SCION_COMMON_HEADER_LEN);

    if (is_on_up_path(iof)) {
      send_local(m, INGRESS_IF(hof));
    } else {
      send_local(m, EGRESS_IF(hof));
    }


  } else if (info == NON_TDC_XOVR) {
    ////C++ code
    // prev_hof = spkt.hdr.get_relative_of(1);
    // if (verify_of(curr_hof, prev_hof, timestamp)) {
    //    spkt.hdr.increase_of(2);
    //    CommonOpaqueField *opaque_field = spkt.hdr.get_relative_of(2);
    //    next_hop.addr =
    //        ifid2addr[opaque_field->egress_if].to_string();
    //    LOG(DEBUG) << "send() here, find next hop1";
    //    send(spkt, next_hop);
    // }
    prev_hof = hof + 1;
    if (verify_of(hof, prev_hof, iof->timestamp) == 0) {
      return;
    }

    sch->currentOF += sizeof(HopOpaqueField) * 2;
    send_local(m, EGRESS_IF(hof));

  } else if (info == INPATH_XOVR) {
    ////C++ code
    // if (verify_of(curr_hof, prev_hof, timestamp)) {
    //    bool is_regular = true;
    //   while (is_regular) {
    //       spkt.hdr.increase_of(2);
    //       is_regular = spkt.hdr.get_current_of()->is_regular();
    //   }
    //   spkt.hdr.common_hdr.curr_iof_p = spkt.hdr.common_hdr.curr_of_p;
    //   LOG(DEBUG) << "TODO send() here, find next hop2";
    //}
    if (verify_of(hof, NULL, iof->timestamp) == 0) {
      return;
    }

    uint8_t is_regular_ = 1;
    while (is_regular_) {
      sch->currentOF += sizeof(HopOpaqueField) * 2;
      HopOpaqueField *hof =
          (HopOpaqueField *)((unsigned char *)sch + sch->currentOF +
                             SCION_COMMON_HEADER_LEN);
      is_regular_ = is_regular(hof);
    }
    sch->currentIOF = sch->currentOF;

  } else if (info == INTRATD_PEER || info == INTERTD_PEER) {
    ////C++ code
    // spkt.hdr.increase_of(1);
    // prev_hof = spkt.hdr.get_relative_of(1);
    // if (verify_of(curr_hof, prev_hof, timestamp)) {
    //    next_hop.addr =
    //        ifid2addr[spkt.hdr.get_current_of()->ingress_if].to_string();
    //    LOG(DEBUG) << "send() here, next: " << next_hop.to_string();
    //    send(spkt, next_hop);
    //}
    prev_hof = hof + 1;
    if (verify_of(hof, prev_hof, iof->timestamp) == 0) {
      return;
    }

    sch->currentOF += sizeof(HopOpaqueField);
    send_local(m, INGRESS_IF(hof));

  } else {
    // LOG(WARNING) << "Unknown case " << info;
  }
}

static inline void forward_packet(struct rte_mbuf *m, uint32_t from_local_ad,
                                  uint32_t ptype) {

  // C++ code
  /*
 bool new_segment = false;
        while (!spkt.hdr.get_current_of()->is_regular()) {
            spkt.hdr.common_hdr.curr_iof_p = spkt.hdr.common_hdr.curr_of_p;
            spkt.hdr.increase_of(1);
            new_segment = true;
        }

        while (spkt.hdr.get_current_of()->is_continue())
            spkt.hdr.increase_of(1);

        int info = spkt.hdr.get_current_iof()->info;
        int curr_iof_p = spkt.hdr.common_hdr.curr_iof_p;
        // Case: peer path and first opaque field of a down path. We need to
        // increase opaque field pointer as that first opaque field is used for
        // MAC verification only.
        if (!spkt.hdr.is_on_up_path() &&
                (info == OpaqueFieldType::INTRATD_PEER
                    || info == OpaqueFieldType::INTERTD_PEER) &&
                spkt.hdr.common_hdr.curr_of_p == curr_iof_p + OpaqueField::LEN)
            spkt.hdr.increase_of(1);

        if (spkt.hdr.get_current_of()->info == OpaqueFieldType::LAST_OF
            && !spkt.hdr.is_last_path_of() && !new_segment)
            crossover_forward(spkt, next_hop, from_local_ad, info);
        else
            normal_forward(spkt, next_hop, from_local_ad, ptype);
*/
  SCIONHeader *scion_hdr;
  SCIONCommonHeader *sch;
  HopOpaqueField *hof;
  InfoOpaqueField *iof;
  scion_hdr = (SCIONHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                                  struct ether_hdr) +
                              sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
  sch = &(scion_hdr->commonHeader);
  hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF +
                           SCION_COMMON_HEADER_LEN);
  iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF +
                            SCION_COMMON_HEADER_LEN);

  uint8_t new_segment = 0;
  while (is_regular(hof)) {
    sch->currentIOF = sch->currentOF;
    sch->currentOF += sizeof(HopOpaqueField);
    new_segment = 1;
  }

  while (is_continue(hof)) {
    sch->currentOF += sizeof(HopOpaqueField);
  }

  int info = iof->type;
  int curr_iof_p = sch->currentIOF;

  if (!is_on_up_path(iof) && (info == INTRATD_PEER || info == INTERTD_PEER) &&
      sch->currentOF == curr_iof_p + sizeof(HopOpaqueField))
    sch->currentOF += sizeof(HopOpaqueField);

  hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF +
                           SCION_COMMON_HEADER_LEN);
  if (hof->type == LAST_OF && is_last_path_of(sch) && !new_segment)
    crossover_forward(m, from_local_ad);
  else
    normal_forward(m, from_local_ad, ptype);
}

static inline void process_ifid_request(struct rte_mbuf *m) {
  struct ether_hdr *eth_hdr;
  struct ipv4_hdr *ipv4_hdr;
  struct udp_hdr *udp_hdr;
  IFIDHeader *ifid_hdr;

  // printf("process ifid request\n");
  ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
      struct ether_hdr));
  udp_hdr = (struct udp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                                   struct ether_hdr) +
                               sizeof(struct ipv4_hdr));
  ifid_hdr = (IFIDHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                                struct ether_hdr) +
                            sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));

  ifid_hdr->reply_id =
      my_ifid; // complete with current interface (self.interface.if_id)

  int i;
  for (i = 0; i < MAX_NUM_BEACON_SERVERS; i++) {
    ipv4_hdr->dst_addr = beacon_servers[i];
    udp_hdr->dst_port = SCION_UDP_PORT;
    l2fwd_send_packet(m, DPDK_EGRESS_PORT);
  }
}

static inline void process_pcb(struct rte_mbuf *m, uint8_t from_bs) {
  struct ether_hdr *eth_hdr;
  struct ipv4_hdr *ipv4_hdr;
  struct udp_hdr *udp_hdr;
  PathConstructionBeacon *pcb;

  // printf("process pcb\n");

  ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
      struct ether_hdr));
  udp_hdr = (struct udp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                                   struct ether_hdr) +
                               sizeof(struct ipv4_hdr));
  pcb = (PathConstructionBeacon *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                                       struct ether_hdr) +
                                   sizeof(struct ipv4_hdr) +
                                   sizeof(struct udp_hdr));

  if (from_bs) { // from local beacon server to neighbor router
    uint8_t last_pcbm_index = sizeof(pcb->payload.ads) / sizeof(ADMarking) - 1;
    HopOpaqueField *last_hof = &(pcb->payload).ads[last_pcbm_index].pcbm.hof;

    if (my_ifid != EGRESS_IF(last_hof)) {
      // Wrong interface set by BS.
      return;
    }

    ipv4_hdr->dst_addr = iflist[neighbor_ad_ifid].addr; // neighbor router IP
    udp_hdr->dst_port =
        iflist[neighbor_ad_ifid].udp_port; // neighbor router port
    l2fwd_send_packet(m, DPDK_EGRESS_PORT);

  } else { // from neighbor router to local beacon server
    pcb->payload.if_id = my_ifid;
    ipv4_hdr->dst_addr = beacon_servers[0];
    udp_hdr->dst_port = SCION_UDP_PORT;
    l2fwd_send_packet(m, DPDK_LOCAL_PORT);
  }
}

static inline void relay_cert_server_packet(struct rte_mbuf *m,
                                            uint8_t from_local_socket) {
  struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(
      m, unsigned char *)+sizeof(struct ether_hdr));

  if (from_local_socket) {
    ipv4_hdr->dst_addr = iflist[neighbor_ad_ifid].addr;
    l2fwd_send_packet(m, DPDK_EGRESS_PORT);
  } else {
    ipv4_hdr->dst_addr = certificate_servers[0];
    l2fwd_send_packet(m, DPDK_LOCAL_PORT);
  }
}

static inline void write_to_egress_iface(struct rte_mbuf *m) {
  struct ether_hdr *eth_hdr;
  struct ipv4_hdr *ipv4_hdr;
  struct udp_hdr *udp_hdr;
  SCIONHeader *scion_hdr;
  SCIONCommonHeader *sch;
  HopOpaqueField *hof;
  InfoOpaqueField *iof;

  ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
      struct ether_hdr));
  udp_hdr = (struct udp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                                   struct ether_hdr) +
                               sizeof(struct ipv4_hdr));
  scion_hdr = (SCIONHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                                  struct ether_hdr) +
                              sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
  sch = &(scion_hdr->commonHeader);
  hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF +
                           SCION_COMMON_HEADER_LEN); // currentOF is an offset
                                                     // from
                                                     // common header
  iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF +
                            SCION_COMMON_HEADER_LEN); // currentOF is an offset
                                                      // from
                                                      // common header

  uint8_t info = hof->type;
  if (info == TDC_XOVR) {
    sch->currentIOF = sch->currentOF;
    sch->currentOF += sizeof(HopOpaqueField);
  } else if (info == NON_TDC_XOVR) {
    sch->currentIOF = sch->currentOF;
    sch->currentOF += sizeof(HopOpaqueField) * 2;
  }

  sch->currentOF += sizeof(HopOpaqueField);

  hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF +
                           SCION_COMMON_HEADER_LEN); // currentOF is an offset
                                                     // from
                                                     // common header

  info = hof->type;
  if (info == INTRATD_PEER || info == INTERTD_PEER) {
    if (is_on_up_path(iof)) {
      HopOpaqueField *previous_hof =
          (HopOpaqueField *)((unsigned char *)sch + sch->currentOF +
                             SCION_COMMON_HEADER_LEN);
      uint8_t previous_info = previous_hof->type;
      if (previous_info == INTRATD_PEER || previous_info == INTERTD_PEER) {
        sch->currentOF += sizeof(HopOpaqueField);
      }
    } else {

      hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF +
                               SCION_COMMON_HEADER_LEN);
      if (hof->type == LAST_OF) {
        sch->currentOF += sizeof(HopOpaqueField);
      }
    }
  }

  send_egress(m);
}

static inline void process_packet(struct rte_mbuf *m, uint8_t from_local_socket,
                                  uint32_t ptype) {
  // printf("process packet\n");

  if (from_local_socket)
    write_to_egress_iface(m);
  else
    forward_packet(m, from_local_socket, ptype);
}

void handle_request(struct rte_mbuf *m, uint8_t from_local_socket,
                    uint32_t ptype) {
  struct ether_hdr *eth_hdr;
  SCIONHeader *scion_hdr;

  // printf("handle_request\n");

  eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);

  // if (m->ol_flags & PKT_RX_IPV4_HDR )
  if (m->ol_flags & PKT_RX_IPV4_HDR || eth_hdr->ether_type == ntohs(0x0800)) {
    // printf("test %x\n", eth_hdr->ether_type);

    scion_hdr =
        (SCIONHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                            struct ether_hdr) +
                        sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));

    // Pratyaksh
    uint8_t ptype = get_type(scion_hdr);
    if (ptype == DATA_PACKET)
      process_packet(m, from_local_socket, ptype);
    else if (ptype == IFID_PKT_PACKET && !from_local_socket) {
      process_ifid_request(m);
    } else if (ptype == BEACON_PACKET)
      process_pcb(m, from_local_socket);
    else if (ptype == CERT_CHAIN_REQ_PACKET || ptype == CERT_CHAIN_REP_PACKET ||
             ptype == TRC_REQ_PACKET || ptype == TRC_REP_PACKET)
      relay_cert_server_packet(m, from_local_socket);

    else {
      // printf("%d ?????\n", ptype);
    }
  }
}
