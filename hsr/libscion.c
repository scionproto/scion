#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <rte_udp.h>
#include "scion.h"

unsigned char *get_dstaddr(SCIONHeader *hdr) {
  uint8_t src_len;

  SCIONCommonHeader *sch;
  sch = &(hdr->commonHeader);
  if (hdr->commonHeader.srcType == ADDR_IPV4_TYPE)
    src_len = 4;
  else if (hdr->commonHeader.srcType == ADDR_IPV6_TYPE)
    src_len = 16;
  else if (hdr->commonHeader.srcType == ADDR_SVC_TYPE)
    src_len = SCION_SVC_ADDR_LEN;

  return (unsigned char *)hdr + sizeof(SCIONCommonHeader) + SCION_ISD_AD_LEN +
         src_len + SCION_ISD_AD_LEN;
}

uint8_t get_type(SCIONHeader *hdr) {
  // TODO check address type

  SCIONAddr *src = (SCIONAddr *)(&hdr->srcAddr);
  // SCIONAddr *dst = (SCIONAddr *)(&hdr->dstAddr);
  SCIONAddr *dst = (SCIONAddr *)(get_dstaddr(hdr));
  /*
    int i;
    for(i=0; i<8; i++)
          printf("%02x",*((unsigned char *)hdr +i));
    printf("\n");
    for(i=0; i<8; i++)
          printf("%02x",*((unsigned char *)src +i));
    printf("host addr
    %x,%x,%x,%x\n",src->host_addr[0],src->host_addr[1],src->host_addr[2],src->host_addr[3]);
    printf("host addr
    %x,%x,%x,%x\n",dst->host_addr[0],dst->host_addr[1],dst->host_addr[2],dst->host_addr[3]);
    printf("%d\n",ntohs(*(uint16_t*)dst->host_addr) );
  */
  SCIONCommonHeader *sch;
  sch = &(hdr->commonHeader);
// TODO move definitions to header file
#define IPV4 1
#define IPV6 2
  //  printf("%x %x\n",*(unsigned char*)sch,*((unsigned char*)(sch)+1));
  //  printf("src type=%d, dst dype=%d\n",sch->srcType,sch->dstType);

  // TODO fix this hack
  // we can not directly refer srcType and dstType due to little endian
  uint16_t srcdstType = ntohs(*(uint16_t *)sch);
  uint8_t srcType = (srcdstType & 0x0fc0) >> 6;
  uint8_t dstType = srcdstType & 0x3f;
  printf("src type=%d, dst dype=%d\n", srcType, dstType);

  if ((srcType == IPV4 || IPV6) && (dstType == IPV4 || IPV6))
    return DATA_PACKET;

  uint8_t payload_class =
      *(uint8_t *)((void *)sch + sch->headerLen +
                   sizeof(struct udp_hdr)); // first byte of the payload
  uint8_t payload_type =
      *(uint8_t *)((void *)sch + sch->headerLen +
                   sizeof(struct udp_hdr)); // first byte of the payload

// TODO move definitions to header file
#define PCB 0
#define IFID 1
#define CERT 2
#define PATH 3

  if (payload_class == PCB)
    return BEACON_PACKET;
  else if (payload_class == IFID)
    return IFID_PKT_PACKET;
  else if (payload_class == CERT)
    return CERT_CHAIN_REQ_PACKET;
  else if (payload_class == PATH)
    return PATH_MGMT_PACKET;
  else
    printf("Unknown packet class\n");

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
