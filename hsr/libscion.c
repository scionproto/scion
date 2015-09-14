#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include "scion.h"

uint8_t get_type(SCIONHeader *hdr) {
  SCIONAddr *src = (SCIONAddr *)(&hdr->srcAddr);
  //if (src->host_addr[0] != 10)
  //  return DATA_PACKET;
  //if (src->host_addr[1] != 224)
  //  return DATA_PACKET;
  //if (src->host_addr[2] != 0)
  //  return DATA_PACKET;

  SCIONAddr *dst = (SCIONAddr *)(&hdr->dstAddr);
  if (dst->host_addr[0] != 10)
    return DATA_PACKET;
  if (dst->host_addr[1] != 224)
    return DATA_PACKET;
  if (dst->host_addr[2] != 0)
    return DATA_PACKET;

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

