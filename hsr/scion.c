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
#include "libscion.h"
#include "lib/aesni.h"

#define RTE_LOGTYPE_HSR RTE_LOGTYPE_USER2
//#define RTE_LOG_LEVEL RTE_LOG_INFO
#define RTE_LOG_LEVEL RTE_LOG_DEBUG
#define VERIFY_OF

#define INGRESS_IF(HOF)                                                        \
  (ntohl((HOF)->ingress_egress_if) >>                                          \
   (12 +                                                                       \
    8)) // 12bit is  egress if and 8 bit gap between uint32 and 24bit field
#define EGRESS_IF(HOF) ((ntohl((HOF)->ingress_egress_if) >> 8) & 0x000fff)

#define LOCAL_NETWORK_ADDRESS IPv4(10, 56, 0, 0)
#define GET_EDGE_ROUTER_IPADDR(IFID)                                           \
  rte_cpu_to_be_32((LOCAL_NETWORK_ADDRESS | IFID))

#define MAX_NUM_ROUTER 16
#define MAX_NUM_BEACON_SERVERS 1
#define MAX_IFID 2 << 12

/// definition of functions
int l2fwd_send_packet(struct rte_mbuf *m, uint8_t port);

static inline void deliver(struct rte_mbuf *m, uint32_t ptype,
                           uint8_t dpdk_rx_port);
static inline void forward_packet(struct rte_mbuf *m, uint32_t from_local_ad,
                                  uint8_t dpdk_rx_port);
static inline void egress_normal_forward(struct rte_mbuf *m, uint8_t dpdk_rx_port);

static inline void handle_ingress_xovr(struct rte_mbuf *m, uint8_t dpdk_rx_port);
static inline void ingress_shortcut_xovr(struct rte_mbuf *m, uint8_t dpdk_rx_port);
static inline void ingress_peer_xovr(struct rte_mbuf *m, uint8_t dpdk_rx_port);
static inline void ingress_core_xovr(struct rte_mbuf *m, uint8_t dpdk_rx_port);

static inline void handle_egress_xovr(struct rte_mbuf *m, uint8_t dpdk_rx_port);
static inline void egress_shortcut_xovr(struct rte_mbuf *m, uint8_t dpdk_rx_port);
static inline void egress_peer_xovr(struct rte_mbuf *m, uint8_t dpdk_rx_port);
static inline void egress_core_xovr(struct rte_mbuf *m, uint8_t dpdk_rx_port);

uint32_t beacon_servers[MAX_NUM_BEACON_SERVERS];
uint32_t certificate_servers[10];
uint32_t path_servers[10];

struct port_map {
  uint8_t egress;
  uint8_t local;
} port_map[16];

uint32_t neighbor_ad_router_ip[16];

uint32_t my_ifid[16]; // the current router's IFID

struct keystruct rk; // AES-NI key structure

void scion_init() {
  // fill interface list
  // TODO read topology configuration

  beacon_servers[0] = rte_cpu_to_be_32(IPv4(7, 7, 7, 7));
  certificate_servers[0] = rte_cpu_to_be_32(IPv4(8, 8, 8, 8));
  path_servers[0] = rte_cpu_to_be_32(IPv4(9, 9, 9, 9));

  // first router
  neighbor_ad_router_ip[0] = neighbor_ad_router_ip[1] =
      rte_cpu_to_be_32(IPv4(1, 1, 1, 1));
  // DPDK setting

  port_map[0].egress = 0;
  port_map[0].local = 1;
  port_map[1].egress = 0;
  port_map[1].local = 1;
  my_ifid[0] = my_ifid[1] = 123; // ifid of NIC 0 and NIC 1 is 123

  // second router
  
  neighbor_ad_router_ip[2] = neighbor_ad_router_ip[3] =
      rte_cpu_to_be_32(IPv4(1, 1, 1, 1));
  port_map[2].egress = 2;
  port_map[2].local = 3;
  port_map[3].egress = 2;
  port_map[3].local = 3;
  my_ifid[2] = my_ifid[3] = 345; // ifid of NIC 2 and NIC 3 is 345

  // AES-NI key setup
  unsigned char key[] = "0123456789abcdef";
  rk.roundkey = aes_assembly_init(key);
  rk.iv = malloc(16 * sizeof(char));
}

static inline void sync_interface() {
  // not implemented
}

// send a packet to neighbor AD router
static inline int send_egress(struct rte_mbuf *m, uint8_t dpdk_rx_port) {
  struct ipv4_hdr *ipv4_hdr;
  // struct udp_hdr *udp_hdr;
  ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
      struct ether_hdr));
  // udp_hdr = (struct udp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
  //                                 struct ether_hdr) +
  //                             sizeof(struct ipv4_hdr));

  // Specify output dpdk port.
  // Update destination IP address and UDP port number

  ipv4_hdr->dst_addr = neighbor_ad_router_ip[dpdk_rx_port];
  // udp_hdr->dst_port = SCION_UDP_PORT;

  // TODO update IP checksum
  // TODO should we updete destination MAC address?

  RTE_LOG(DEBUG, HSR, "send_egress port=%d\n", port_map[dpdk_rx_port].egress);
  // TODO update destination MAC address
  l2fwd_send_packet(m, port_map[dpdk_rx_port].egress);
}

// send a packet to the edge router that has next_ifid in this AD
static inline int send_ingress(struct rte_mbuf *m, uint32_t next_ifid,
                               uint8_t dpdk_rx_port) {
  struct ipv4_hdr *ipv4_hdr;
  // struct udp_hdr *udp_hdr;
  ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
      struct ether_hdr));
  // udp_hdr = (struct udp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
  //                                 struct ether_hdr) +
  //                             sizeof(struct ipv4_hdr));

  if (next_ifid != 0) {
    // Specify output dpdk port.
    // Update destination IP address and UDP port number
    ipv4_hdr->dst_addr = GET_EDGE_ROUTER_IPADDR(next_ifid);
    // udp_hdr->dst_port = SCION_UDP_PORT;

    // TODO update IP checksum
    // TODO should we updete destination MAC address?

    RTE_LOG(DEBUG, HSR, "egress dpdk_port=%d\n", DPDK_LOCAL_PORT);
    // TODO update destination MAC address
    l2fwd_send_packet(m, port_map[dpdk_rx_port].local);
    return 1;
  }
  return -1;
}

static inline void process_ifid_request(struct rte_mbuf *m, uint8_t dpdk_rx_port) {
  // struct ether_hdr *eth_hdr;
  struct ipv4_hdr *ipv4_hdr;
  // struct udp_hdr *udp_hdr;
  IFIDHeader *ifid_hdr;

  RTE_LOG(DEBUG, HSR, "process ifid request\n");

  ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
      struct ether_hdr));
  // udp_hdr = (struct udp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
  //                                 struct ether_hdr) +
  //                             sizeof(struct ipv4_hdr));
  ifid_hdr = (IFIDHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                                struct ether_hdr) +
                            sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));

  ifid_hdr->reply_id = my_ifid[dpdk_rx_port]; // complete with current interface
                                           // (self.interface.if_id)

  int i;
  for (i = 0; i < MAX_NUM_BEACON_SERVERS; i++) {
    ipv4_hdr->dst_addr = beacon_servers[i];
    // TODO update IP checksum
    // udp_hdr->dst_port = SCION_UDP_PORT;
    // TODO update destination MAC address
    l2fwd_send_packet(m, port_map[dpdk_rx_port].local);
  }
}

static inline void process_pcb(struct rte_mbuf *m, uint8_t from_bs,
                               uint8_t dpdk_rx_port) {
  struct ether_hdr *eth_hdr;
  struct ipv4_hdr *ipv4_hdr;
  struct udp_hdr *udp_hdr;
  PathConstructionBeacon *pcb;

  RTE_LOG(DEBUG, HSR, "process pcb\n");

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

    ipv4_hdr->dst_addr = neighbor_ad_router_ip[dpdk_rx_port];
    // udp_hdr->dst_port = SCION_UDP_PORT; // neighbor router port

    // TODO update IP checksum
    // l2fwd_send_packet(m, DPDK_EGRESS_PORT);
    l2fwd_send_packet(m, port_map[dpdk_rx_port].egress);

  } else { // from neighbor router to local beacon server
    pcb->payload.if_id = my_ifid[dpdk_rx_port];
    ipv4_hdr->dst_addr = beacon_servers[0];
    // udp_hdr->dst_port = SCION_UDP_PORT;

    // TODO update destination MAC address
    l2fwd_send_packet(m, port_map[dpdk_rx_port].local);
  }
}

static inline void relay_cert_server_packet(struct rte_mbuf *m,
                                            uint8_t from_local_socket,
                                            uint8_t dpdk_rx_port) {
  struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(
      m, unsigned char *)+sizeof(struct ether_hdr));

  if (from_local_socket) {
    ipv4_hdr->dst_addr = neighbor_ad_router_ip[dpdk_rx_port];
    // TODO update IP checksum
    // l2fwd_send_packet(m, DPDK_EGRESS_PORT, dpdk_rx_port);
    l2fwd_send_packet(m, port_map[dpdk_rx_port].egress);
  } else {
    ipv4_hdr->dst_addr = certificate_servers[0];
    // TODO update IP checksum
    // TODO update destination MAC address
    l2fwd_send_packet(m, port_map[dpdk_rx_port].local);
  }
}

static inline void process_path_mgmt_packet(struct rte_mbuf *m,
                                            uint8_t from_local_ad,
                                            uint8_t dpdk_rx_port) {
  SCIONHeader *scion_hdr;
  SCIONCommonHeader *sch;
  HopOpaqueField *hof;
  InfoOpaqueField *iof;

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

  if (from_local_ad == 0 && is_last_path_of(sch)) {
    deliver(m, PATH_MGMT_PACKET, dpdk_rx_port);
  } else {
    forward_packet(m, from_local_ad, dpdk_rx_port);
  }
}

static inline void deliver(struct rte_mbuf *m, uint32_t ptype,
                           uint8_t dpdk_rx_port) {
  struct ipv4_hdr *ipv4_hdr;
  struct udp_hdr *udp_hdr;
  SCIONHeader *scion_hdr;

  RTE_LOG(DEBUG, HSR, "deliver\n");
  ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
      struct ether_hdr));
  udp_hdr = (struct udp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                                   struct ether_hdr) +
                               sizeof(struct ipv4_hdr));

  scion_hdr = (SCIONHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                                  struct ether_hdr) +
                              sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));

  // TODO support IPv6
  if (ptype == PATH_MGMT_PACKET) {
    ipv4_hdr->dst_addr = path_servers[0];
    udp_hdr->dst_port = SCION_UDP_PORT;
  } else {
    // update destination IP address to the end hostadress
    rte_memcpy((void *)&ipv4_hdr->dst_addr,
               (void *)&scion_hdr->dstAddr + SCION_ISD_AD_LEN,
               SCION_HOST_ADDR_LEN);

    udp_hdr->dst_port = SCION_UDP_EH_DATA_PORT;
  }

  // TODO update destination MAC address
  l2fwd_send_packet(m, port_map[dpdk_rx_port].local);
}

static inline uint8_t verify_of(HopOpaqueField *hof, HopOpaqueField *prev_hof,
                                uint32_t ts) {

#ifndef VERIFY_OF
  return 1;
#endif

#define MAC_LEN 3

  unsigned char input[16];
  unsigned char mac[16];

  RTE_LOG(DEBUG, HSR, "verify_of\n");

  // setup input vector
  // rte_mov32 ((void*)input, (void *)hof+1); //copy exp_type and
  // ingress/egress IF (4bytes)
  // rte_mov64 ((void*)input+4, (void *)prev_hof+1); //copy previous OF except
  // info field (7bytes)
  // rte_mov32 ((void*)input+11, (void*)&ts);

  rte_memcpy((void *)input, (void *)hof + 1,
             4); // copy exp_type and  ingress/egress IF (4bytes)
  rte_memcpy((void *)input + 4, (void *)prev_hof + 1,
             7); // copy previous OF except info field (7bytes)
  rte_memcpy((void *)input + 11, (void *)&ts, 4);

  // pkcs7_padding
  input[15] = 1;

  // call AES-NI
  // int i;
  // for (i = 0; i < 16; i++)
  //  printf("%02x", input[i]);
  // printf("\n");
  CBCMAC1BLK(rk.roundkey, rk.iv, input, mac);
  // for (i = 0; i < 16; i++)
  //  printf("%02x", mac[i]);
  // printf("\n");

  if (memcmp((void *)hof + 5, &mac,
             MAC_LEN)) { // (void *)hof + 5 is address of mac.
    return 1;
  } else {
    RTE_LOG(WARNING, HSR, "invalid MAC\n");
    // return 0;
    // TODO DEBUG, currently disable MAC check
    return 1;
  }
}

static inline void handle_ingress_xovr(struct rte_mbuf *m, uint8_t dpdk_rx_port) {
  SCIONHeader *scion_hdr;
  SCIONCommonHeader *sch;
  HopOpaqueField *hof;
  InfoOpaqueField *iof;

  RTE_LOG(DEBUG, HSR, "handle ingresst xovr\n");
  scion_hdr = (SCIONHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                                  struct ether_hdr) +
                              sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
  sch = &(scion_hdr->commonHeader);
  hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF +
                           SCION_COMMON_HEADER_LEN);
  iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF +
                            SCION_COMMON_HEADER_LEN);

  if (iof->info == OFT_SHORTCUT) {
    ingress_shortcut_xovr(m, dpdk_rx_port);
  } else if (iof->info == OFT_INTRA_ISD_PEER ||
             iof->info == OFT_INTER_ISD_PEER) {
    ingress_peer_xovr(m, dpdk_rx_port);
  } else if (iof->info == OFT_CORE) {
    ingress_core_xovr(m, dpdk_rx_port);
  } else {
    // invalid OF
  }
}

static inline void ingress_shortcut_xovr(struct rte_mbuf *m,
                                         uint8_t dpdk_rx_port) {
  SCIONHeader *scion_hdr;
  SCIONCommonHeader *sch;
  HopOpaqueField *hof;
  HopOpaqueField *prev_hof;
  InfoOpaqueField *iof;

  RTE_LOG(DEBUG, HSR, "ingress shortcut xovr\n");
  scion_hdr = (SCIONHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                                  struct ether_hdr) +
                              sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
  sch = &(scion_hdr->commonHeader);
  hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF +
                           SCION_COMMON_HEADER_LEN);
  iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF +
                            SCION_COMMON_HEADER_LEN);

  prev_hof = hof + 1;
  if (verify_of(hof, prev_hof, iof->timestamp) == 0) {
    return;
  }

  // switch to next segment
  sch->currentIOF = sch->currentOF + sizeof(HopOpaqueField) * 2;
  sch->currentOF += sizeof(HopOpaqueField) * 4;

  hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF +
                           SCION_COMMON_HEADER_LEN);
  iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF +
                            SCION_COMMON_HEADER_LEN);

  if (INGRESS_IF(hof) == 0 && is_last_path_of(sch)) {
    prev_hof = hof - 1;
    if (verify_of(hof, prev_hof, iof->timestamp) == 0) {
      return;
    }

    deliver(m, DATA_PACKET, dpdk_rx_port);
  } else {
    send_ingress(m, EGRESS_IF(hof), dpdk_rx_port);
  }
}
static inline void ingress_peer_xovr(struct rte_mbuf *m, uint8_t dpdk_rx_port) {
  SCIONHeader *scion_hdr;
  SCIONCommonHeader *sch;
  HopOpaqueField *hof;
  HopOpaqueField *prev_hof;
  InfoOpaqueField *iof;

  RTE_LOG(DEBUG, HSR, "ingress peer xovr\n");
  scion_hdr = (SCIONHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                                  struct ether_hdr) +
                              sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
  sch = &(scion_hdr->commonHeader);
  hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF +
                           SCION_COMMON_HEADER_LEN);
  iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF +
                            SCION_COMMON_HEADER_LEN);

  uint16_t fwd_if;
  if (is_on_up_path(iof)) {
    prev_hof = hof + 2;
    fwd_if = INGRESS_IF(hof + 1);
  } else {
    prev_hof = hof + 1;
    fwd_if = EGRESS_IF(hof + 1);
  }

  if (verify_of(hof, prev_hof, iof->timestamp) == 0) {
    return;
  }

  sch->currentOF += sizeof(HopOpaqueField);

  if (is_last_path_of(sch))
    deliver(m, DATA_PACKET, dpdk_rx_port);
  else
    send_ingress(m, fwd_if, dpdk_rx_port);
}
static inline void ingress_core_xovr(struct rte_mbuf *m, uint8_t dpdk_rx_port) {
  SCIONHeader *scion_hdr;
  SCIONCommonHeader *sch;
  HopOpaqueField *hof;
  HopOpaqueField *prev_hof;
  InfoOpaqueField *iof;

  RTE_LOG(DEBUG, HSR, "ingress peer xovr\n");
  scion_hdr = (SCIONHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                                  struct ether_hdr) +
                              sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
  sch = &(scion_hdr->commonHeader);
  hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF +
                           SCION_COMMON_HEADER_LEN);
  iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF +
                            SCION_COMMON_HEADER_LEN);

  uint32_t fwd_if;
  if (is_on_up_path(iof)) {
    prev_hof = NULL;
  } else {
    prev_hof = hof - 1;
  }

  if (verify_of(hof, prev_hof, iof->timestamp) == 0) {
    return;
  }

  if (is_last_path_of(sch))
    deliver(m, DATA_PACKET, dpdk_rx_port);
  else {
    // Switch to next path segment
    sch->currentIOF = sch->currentOF + sizeof(HopOpaqueField);
    sch->currentOF += sizeof(HopOpaqueField) * 2;
    iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF +
                              SCION_COMMON_HEADER_LEN);
    hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF +
                             SCION_COMMON_HEADER_LEN);

    if (is_on_up_path(iof)) {
      send_ingress(m, INGRESS_IF(hof), dpdk_rx_port);
    } else {
      send_ingress(m, EGRESS_IF(hof), dpdk_rx_port);
    }
  }
}

static inline void ingress_normal_forward(struct rte_mbuf *m,
                                          uint8_t dpdk_rx_port) {
  SCIONHeader *scion_hdr;
  SCIONCommonHeader *sch;
  HopOpaqueField *hof;
  HopOpaqueField *prev_hof;
  InfoOpaqueField *iof;

  RTE_LOG(DEBUG, HSR, "ingress normal forward\n");
  scion_hdr = (SCIONHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                                  struct ether_hdr) +
                              sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
  sch = &(scion_hdr->commonHeader);
  hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF +
                           SCION_COMMON_HEADER_LEN);
  iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF +
                            SCION_COMMON_HEADER_LEN);

  // printf("Ingress %d, Egress %d\n", INGRESS_IF(hof), EGRESS_IF(hof));
  uint16_t next_ifid;
  if (is_on_up_path(iof)) {
    next_ifid = INGRESS_IF(hof);
    prev_hof = hof + 1;
  } else {
    next_ifid = EGRESS_IF(hof);
    prev_hof = hof - 1;
  }

  if (verify_of(hof, prev_hof, iof->timestamp) == 0) {
    return;
  }

  if (next_ifid == 0 && is_last_path_of(sch)) {
    deliver(m, DATA_PACKET, dpdk_rx_port);
  } else {
    send_ingress(m, next_ifid, dpdk_rx_port);
  }
}

static inline void handle_egress_xovr(struct rte_mbuf *m, uint8_t dpdk_rx_port) {
  SCIONHeader *scion_hdr;
  SCIONCommonHeader *sch;
  HopOpaqueField *hof;
  InfoOpaqueField *iof;

  RTE_LOG(DEBUG, HSR, "handle egress xovr\n");
  scion_hdr = (SCIONHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                                  struct ether_hdr) +
                              sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
  sch = &(scion_hdr->commonHeader);
  iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF +
                            SCION_COMMON_HEADER_LEN);

  if (iof->info == OFT_SHORTCUT) {
    egress_shortcut_xovr(m, dpdk_rx_port);
  } else if (iof->info == OFT_INTRA_ISD_PEER ||
             iof->info == OFT_INTER_ISD_PEER) {
    egress_peer_xovr(m, dpdk_rx_port);
  } else if (iof->info == OFT_CORE) {
    egress_core_xovr(m, dpdk_rx_port);
  } else {
    // invalid OF
  }
}

static inline void egress_shortcut_xovr(struct rte_mbuf *m, uint8_t dpdk_rx_port) {
  egress_normal_forward(m, dpdk_rx_port);
}
static inline void egress_peer_xovr(struct rte_mbuf *m, uint8_t dpdk_rx_port) {
  struct ether_hdr *eth_hdr;
  SCIONHeader *scion_hdr;
  SCIONCommonHeader *sch;
  HopOpaqueField *hof;
  HopOpaqueField *prev_hof;
  InfoOpaqueField *iof;

  RTE_LOG(DEBUG, HSR, "egress normal forward\n");
  scion_hdr = (SCIONHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                                  struct ether_hdr) +
                              sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
  sch = &(scion_hdr->commonHeader);
  hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF +
                           SCION_COMMON_HEADER_LEN);
  iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF +
                            SCION_COMMON_HEADER_LEN);

  if (is_on_up_path(iof)) {
    prev_hof = hof - 1;
    if (verify_of(hof, prev_hof, iof->timestamp) == 0) {
      return;
    }

    // Switch to next segment
    sch->currentIOF = sch->currentOF + sizeof(HopOpaqueField) * 2;
    sch->currentOF += sizeof(HopOpaqueField) * 4;
  } else {

    prev_hof = hof - 2;
    if (verify_of(hof, prev_hof, iof->timestamp) == 0) {
      return;
    }
    sch->currentOF += sizeof(HopOpaqueField);
  }

  send_egress(m, dpdk_rx_port);
}
static inline void egress_core_xovr(struct rte_mbuf *m, uint8_t dpdk_rx_port) {
  struct ether_hdr *eth_hdr;
  SCIONHeader *scion_hdr;
  SCIONCommonHeader *sch;
  HopOpaqueField *hof;
  HopOpaqueField *prev_hof;
  InfoOpaqueField *iof;

  RTE_LOG(DEBUG, HSR, "egress core xovr\n");
  scion_hdr = (SCIONHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                                  struct ether_hdr) +
                              sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
  sch = &(scion_hdr->commonHeader);
  hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF +
                           SCION_COMMON_HEADER_LEN);
  iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF +
                            SCION_COMMON_HEADER_LEN);

  if (is_on_up_path(iof)) {
    prev_hof = NULL;
  } else {
    prev_hof = hof + 1;
  }

  if (verify_of(hof, prev_hof, iof->timestamp) == 0) {
    return;
  }

  sch->currentOF += sizeof(HopOpaqueField);
  send_egress(m, dpdk_rx_port);
}

static inline void egress_normal_forward(struct rte_mbuf *m,
                                         uint8_t dpdk_rx_port) {
  struct ether_hdr *eth_hdr;
  SCIONHeader *scion_hdr;
  SCIONCommonHeader *sch;
  HopOpaqueField *hof;
  HopOpaqueField *prev_hof;
  InfoOpaqueField *iof;

  RTE_LOG(DEBUG, HSR, "egress normal forward\n");
  scion_hdr = (SCIONHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                                  struct ether_hdr) +
                              sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
  sch = &(scion_hdr->commonHeader);
  hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF +
                           SCION_COMMON_HEADER_LEN);
  iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF +
                            SCION_COMMON_HEADER_LEN);

  // printf("Ingress %d, Egress %d\n", INGRESS_IF(hof), EGRESS_IF(hof));
  if (is_on_up_path(iof)) {
    prev_hof = hof + 1;
  } else {
    prev_hof = hof - 1;
  }

  // TODO  verify MAC
  if (verify_of(hof, prev_hof, iof->timestamp) == 0) {
    return;
  }

  sch + sch->currentOF + sizeof(HopOpaqueField);

  // send packet to neighbor AD's router
  send_egress(m, dpdk_rx_port);
}

static inline void forward_packet(struct rte_mbuf *m, uint32_t from_local_ad,
                                  uint8_t dpdk_rx_port) {

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

  if (from_local_ad == 0) {
    // Ingress entry point
    if (hof->info == OFT_XOVR_POINT) {
      handle_ingress_xovr(m, dpdk_rx_port);
    } else {
      ingress_normal_forward(m, dpdk_rx_port);
    }
  } else {
    // Egress entry point
    if (hof->info == OFT_XOVR_POINT) {
      handle_egress_xovr(m, dpdk_rx_port);
    } else {
      egress_normal_forward(m, dpdk_rx_port);
    }
  }
}

void handle_request(struct rte_mbuf *m, uint8_t dpdk_rx_port) {
  struct ether_hdr *eth_hdr;
  SCIONHeader *scion_hdr;

  RTE_LOG(DEBUG, HSR, "packet recieved, dpdk_port=%d\n", dpdk_rx_port);

  eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);

  // if (m->ol_flags & PKT_RX_IPV4_HDR )
  if (m->ol_flags & PKT_RX_IPV4_HDR || eth_hdr->ether_type == ntohs(0x0800)) {

    // from local socket?
    uint8_t from_local_socket = 0;
    if (dpdk_rx_port % 2 == 1) {
      from_local_socket = 1;
    }

    scion_hdr =
        (SCIONHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                            struct ether_hdr) +
                        sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));

    uint8_t ptype = get_type(scion_hdr);
    switch (ptype) {
    case DATA_PACKET:
      forward_packet(m, from_local_socket, dpdk_rx_port);
      break;
    case IFID_PKT_PACKET:
      if (!from_local_socket)
        process_ifid_request(m, dpdk_rx_port);
      else
        RTE_LOG(WARNING, HSR, "IFID packet from local socket\n");

      break;
    case BEACON_PACKET:
      process_pcb(m, from_local_socket, dpdk_rx_port);
      break;
    case CERT_CHAIN_REQ_PACKET:
    case CERT_CHAIN_REP_PACKET:
    case TRC_REQ_PACKET:
    case TRC_REP_PACKET:
      relay_cert_server_packet(m, from_local_socket, dpdk_rx_port);
      break;
    case PATH_MGMT_PACKET:
      process_path_mgmt_packet(m, from_local_socket, dpdk_rx_port);
      break;
    default:
      RTE_LOG(DEBUG, HSR, "unknown packet type %d ?\n", ptype);
      break;
    }
  }
}
