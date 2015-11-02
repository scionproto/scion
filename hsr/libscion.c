#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include "scion.h"

#define IP_DEFTTL  64   /* from RFC 1340. */
#define IP_VERSION 0x40
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)

const int ADDR_LENS[] = {0, 4, 16, 2};

unsigned char *get_dstaddr(SCIONCommonHeader *sch) {
  uint8_t src_len;
  uint8_t src_type = (ntohs(sch->versionSrcDst) & 0xfc0) >> 6;

  if (src_type < ADDR_NONE_TYPE || src_type > ADDR_SVC_TYPE)
    return NULL;

  src_len = ADDR_LENS[src_type];
  return (unsigned char *)sch + sizeof(*sch) + SCION_ISD_AD_LEN +
         src_len + SCION_ISD_AD_LEN;
}

uint8_t get_type(SCIONCommonHeader *sch) {
  //  printf("%x %x\n",*(unsigned char*)sch,*((unsigned char*)(sch)+1));
  //  printf("src type=%d, dst dype=%d\n",sch->src_type,sch->dst_type);

  uint8_t src_type = SRC_TYPE(sch);
  uint8_t dst_type = DST_TYPE(sch);

  if ((src_type == ADDR_IPV4_TYPE || ADDR_IPV6_TYPE) &&
      (dst_type == ADDR_IPV4_TYPE || ADDR_IPV6_TYPE))
    return DATA_PACKET;

  uint8_t payload_class =
      *(uint8_t *)((void *)sch + sch->headerLen +
                   sizeof(struct udp_hdr)); // first byte of the payload

  switch (payload_class) {
  case PCB_CLASS:
    return BEACON_PACKET;
  case IFID_CLASS:
    return IFID_PKT_PACKET;
  case CERT_CLASS:
    return CERT_CHAIN_REQ_PACKET;
  case PATH_CLASS:
    return PATH_MGMT_PACKET;
  default:
    fprintf(stderr, "Unknown packet class\n");
    return PACKET_TYPE_ERROR;
  }

  /*
    uint16_t src_svc = ntohs(*(uint16_t *)src->host_addr);
    uint16_t dst_svc = ntohs(*(uint16_t *)dst->host_addr);

    int b1 = src_svc == BEACON_PACKET || src_svc == PATH_MGMT_PACKET ||
             src_svc == CERT_CHAIN_REP_PACKET || src_svc == TRC_REP_PACKET;
    int b2 = dst_svc == PATH_MGMT_PACKET || dst_svc == TRC_REQ_PACKET ||
             dst_svc == TRC_REQ_LOCAL_PACKET ||
             dst_svc == CERT_CHAIN_REQ_PACKET ||
             dst_svc == CERT_CHAIN_REQ_LOCAL_PACKET || dst_svc ==
    IFID_PKT_PACKET;

    if (b1)
      return src_svc;
    else if (b2)
      return dst_svc;
    else
      return DATA_PACKET;
  */
}

uint8_t is_on_up_path(InfoOpaqueField *currOF) {
  if ((currOF->info & 0x1) ==
      1) { // low bit of type field is used for uppath/downpath flag
    return 1;
  }
  return 0;
}

uint8_t is_last_path_of(SCIONCommonHeader *sch) {
  uint8_t offset = SCION_COMMON_HEADER_LEN + sizeof(HopOpaqueField);
  return sch->currentOF == offset + sch->headerLen;
}

uint8_t is_regular(HopOpaqueField *currOF) {
  if ((currOF->info & (1 << 6)) == 0) {
    return 0;
  }
  return 1;
}

uint8_t is_continue(HopOpaqueField *currOF) {
  if ((currOF->info & (1 << 5)) == 0) {
    return 0;
  }
  return 1;
}
uint8_t is_xovr(HopOpaqueField *currOF) {
  if ((currOF->info & (1 << 4)) == 0) {
    return 0;
  }
  return 1;
}

uint16_t scion_udp_checksum(SCIONCommonHeader *sch)
{
  uint32_t sum = 0;
  int i;
  int src_len = ADDR_LENS[SRC_TYPE(sch)];
  int dst_len = ADDR_LENS[DST_TYPE(sch)];
  uint8_t buf[ntohs(sch->totalLen)]; // UDP packet + pseudoheader < totalLen
  uint8_t *ptr = buf;
  uint16_t payload_len;
  int total;

  payload_len = ntohs(*(uint16_t *)((uint8_t *)sch + sch->headerLen + 4));

  memcpy(ptr, sch + 1, src_len + dst_len + 8);
  ptr += src_len + dst_len + 8;
  *ptr = L4_UDP;
  ptr++;
  memcpy(ptr, (uint8_t *)sch + sch->headerLen, 6);
  ptr += 6;
  memcpy(ptr, (uint8_t *)sch + sch->headerLen + 8, payload_len);
  ptr += payload_len;

  total = ptr - buf;
  if (total % 2 != 0) {
    *ptr = 0;
    ptr++;
    total++;
  }

  for (i = 0; i < total; i += 2)
    sum += *(uint16_t *)(buf + i);
  sum = (sum >> 16) + (sum & 0xffff);
  sum += sum >> 16;
  sum = ~sum;

  if (htons(1) == 1) {
    /* Big endian */
    return sum & 0xffff;
  } else {
    /* Little endian */
    return (((sum >> 8) & 0xff) | sum << 8) & 0xffff;
  }
}

void
initialize_eth_header(struct ether_hdr *eth_hdr, struct ether_addr *src_mac,
		struct ether_addr *dst_mac, uint16_t ether_type,
		uint8_t vlan_enabled, uint16_t van_id)
{
	ether_addr_copy(dst_mac, &eth_hdr->d_addr);
	ether_addr_copy(src_mac, &eth_hdr->s_addr);

	if (vlan_enabled) {
		struct vlan_hdr *vhdr = (struct vlan_hdr *)((uint8_t *)eth_hdr +
				sizeof(struct ether_hdr));

		eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_VLAN);

		vhdr->eth_proto =  rte_cpu_to_be_16(ether_type);
		vhdr->vlan_tci = van_id;
	} else {
		eth_hdr->ether_type = rte_cpu_to_be_16(ether_type);
	}
}

uint16_t
initialize_ipv4_header(struct ipv4_hdr *ip_hdr, uint32_t src_addr,
		uint32_t dst_addr, uint16_t pkt_data_len)
{
	uint16_t pkt_len;
	uint16_t *ptr16;
	uint32_t ip_cksum;

	/*
	 * Initialize IP header.
	 */
	pkt_len = (uint16_t) (pkt_data_len + sizeof(struct ipv4_hdr));

	ip_hdr->version_ihl   = IP_VHL_DEF;
	ip_hdr->type_of_service   = 0;
	ip_hdr->fragment_offset = 0;
	ip_hdr->time_to_live   = IP_DEFTTL;
	ip_hdr->next_proto_id = IPPROTO_UDP;
	ip_hdr->packet_id = 0;
	ip_hdr->total_length   = rte_cpu_to_be_16(pkt_len);
	ip_hdr->src_addr = rte_cpu_to_be_32(src_addr);
	ip_hdr->dst_addr = rte_cpu_to_be_32(dst_addr);

	/*
	 * Compute IP header checksum.
	 */
	ptr16 = (uint16_t *)ip_hdr;
	ip_cksum = 0;
	ip_cksum += ptr16[0]; ip_cksum += ptr16[1];
	ip_cksum += ptr16[2]; ip_cksum += ptr16[3];
	ip_cksum += ptr16[4];
	ip_cksum += ptr16[6]; ip_cksum += ptr16[7];
	ip_cksum += ptr16[8]; ip_cksum += ptr16[9];

	/*
	 * Reduce 32 bit checksum to 16 bits and complement it.
	 */
	ip_cksum = ((ip_cksum & 0xFFFF0000) >> 16) +
		(ip_cksum & 0x0000FFFF);
	ip_cksum %= 65536;
	ip_cksum = (~ip_cksum) & 0x0000FFFF;
	if (ip_cksum == 0)
		ip_cksum = 0xFFFF;
	ip_hdr->hdr_checksum = (uint16_t) ip_cksum;

	return pkt_len;
}

uint16_t
initialize_udp_header(struct udp_hdr *udp_hdr, uint16_t src_port,
		uint16_t dst_port, uint16_t pkt_data_len)
{
	uint16_t pkt_len;

	pkt_len = (uint16_t) (pkt_data_len + sizeof(struct udp_hdr));

	udp_hdr->src_port = rte_cpu_to_be_16(src_port);
	udp_hdr->dst_port = rte_cpu_to_be_16(dst_port);
	udp_hdr->dgram_len = rte_cpu_to_be_16(pkt_len);
	udp_hdr->dgram_cksum = 0; /* No UDP checksum. */

	return pkt_len;
}

void
copy_buf_to_pkt_segs(void *buf, unsigned len, struct rte_mbuf *pkt,
		unsigned offset)
{
	struct rte_mbuf *seg;
	void *seg_buf;
	unsigned copy_len;

	seg = pkt;
	while (offset >= seg->data_len) {
		offset -= seg->data_len;
		seg = seg->next;
	}
	copy_len = seg->data_len - offset;
	seg_buf = rte_pktmbuf_mtod(seg, char *) + offset;
	while (len > copy_len) {
		rte_memcpy(seg_buf, buf, (size_t) copy_len);
		len -= copy_len;
		buf = ((char *) buf + copy_len);
		seg = seg->next;
		seg_buf = rte_pktmbuf_mtod(seg, void *);
	}
	rte_memcpy(seg_buf, buf, (size_t) len);
}

void
copy_buf_to_pkt(void *buf, unsigned len, struct rte_mbuf *pkt, unsigned offset)
{
	if (offset + len <= pkt->data_len) {
		rte_memcpy(rte_pktmbuf_mtod(pkt, char *) + offset, buf, (size_t) len);
		return;
	}
	copy_buf_to_pkt_segs(buf, len, pkt, offset);
}

extern uint32_t interface_ip[];

void build_lower_layers(struct rte_mbuf *pkt, struct ether_addr *eth_addrs,
                        struct ether_addr *dst_mac, uint32_t dst_ip, size_t size)
{
  struct ether_hdr eth;
  struct ipv4_hdr ip;
  struct udp_hdr udp;

  /* TODO: Actual dst MAC address? */
  memset(dst_mac->addr_bytes, 1, ETHER_ADDR_LEN);
  initialize_eth_header(&eth, &eth_addrs[0], dst_mac,
                        ETHER_TYPE_IPv4, 0, 0);
  copy_buf_to_pkt(&eth, sizeof(eth), pkt, 0);
  initialize_ipv4_header(&ip,
                         interface_ip[0], dst_ip,
                         size - sizeof(eth) - sizeof(ip));
  copy_buf_to_pkt(&ip, sizeof(ip), pkt, sizeof(eth));
  initialize_udp_header(&udp,
                        SCION_UDP_PORT, SCION_UDP_PORT,
                        size - sizeof(eth) - sizeof(ip) - sizeof(udp));
  copy_buf_to_pkt(&udp, sizeof(udp), pkt, sizeof(eth) + sizeof(ip));

  pkt->nb_segs = 1;
  pkt->pkt_len = size;
  pkt->l2_len = sizeof(eth);

  /* TODO: IPv6 */
  pkt->vlan_tci = ETHER_TYPE_IPv4;
  pkt->l3_len = sizeof(ip);
  pkt->ol_flags = PKT_RX_IPV4_HDR;
}

void
build_cmn_hdr(SCIONCommonHeader *sch, int src_type, int dst_type, int next_hdr)
{
  uint16_t vsd = 0;
  vsd |= src_type << 6;
  vsd |= dst_type;
  sch->versionSrcDst = htons(vsd);
  sch->nextHeader = next_hdr;
  sch->headerLen = sizeof(*sch);
  sch->currentIOF = 0;
  sch->currentOF = 0;
  sch->totalLen = htons(sch->headerLen);
}

void build_addr_hdr(SCIONCommonHeader *sch, SCIONAddr *src, SCIONAddr *dst)
{
  uint8_t src_type = SRC_TYPE(sch);
  int src_len = ADDR_LENS[src_type];
  uint8_t dst_type = DST_TYPE(sch);
  int dst_len = ADDR_LENS[dst_type];
  int pad = (SCION_ADDR_PAD - ((src_len + dst_len) % 8)) % 8;
  uint8_t *ptr = (uint8_t *)sch + sizeof(*sch);
  *(uint32_t *)ptr = htonl(src->isd_ad);
  ptr += 4;
  memcpy(ptr, src->host_addr, src_len);
  ptr += src_len;
  *(uint32_t *)ptr = htonl(dst->isd_ad);
  ptr += 4;
  memcpy(ptr, dst->host_addr, dst_len);
  sch->headerLen += src_len + dst_len + 8 + pad;
  sch->totalLen = htons(sch->headerLen);
}

void build_scion_udp(SCIONCommonHeader *sch, uint16_t payload_len)
{
  uint8_t *ptr = (uint8_t *)sch + sch->headerLen;
  *(uint16_t *)ptr = htons(SCION_UDP_PORT);
  ptr += 2;
  *(uint16_t *)ptr = htons(SCION_UDP_PORT);
  ptr += 2;
  *(uint16_t *)ptr = htons(payload_len);
  ptr += 2;
  *(uint16_t *)ptr = 0; // checksum, calculate later
  ptr += 2;
  return ptr;
}
