#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include "scion.h"

uint8_t get_type(SCIONHeader *hdr) {
  // TODO check address type

  SCIONAddr *src = (SCIONAddr *)(&hdr->srcAddr);
  SCIONAddr *dst = (SCIONAddr *)(&hdr->dstAddr);
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

  uint16_t src_svc = ntohs(*(uint16_t *)src->host_addr);
  uint16_t dst_svc = ntohs(*(uint16_t *)dst->host_addr);

  int b1 = src_svc == BEACON_PACKET || src_svc == PATH_MGMT_PACKET ||
           src_svc == CERT_CHAIN_REP_PACKET || src_svc == TRC_REP_PACKET;
  int b2 = dst_svc == PATH_MGMT_PACKET || dst_svc == TRC_REQ_PACKET ||
           dst_svc == TRC_REQ_LOCAL_PACKET ||
           dst_svc == CERT_CHAIN_REQ_PACKET ||
           dst_svc == CERT_CHAIN_REQ_LOCAL_PACKET || dst_svc == IFID_PKT_PACKET;

  if (b1)
    return src_svc;
  else if (b2)
    return dst_svc;
  else
    return DATA_PACKET;
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
