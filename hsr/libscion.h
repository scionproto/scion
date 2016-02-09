#include "scion.h"

void * get_dst_addr(SCIONCommonHeader *hdr);
uint8_t get_payload_class(SCIONCommonHeader *hdr);
uint8_t get_payload_type(SCIONCommonHeader *hdr);
uint8_t is_on_up_path(InfoOpaqueField *currOF);
uint8_t is_last_path_of(SCIONCommonHeader *sch);
uint8_t is_regular(HopOpaqueField *currOF);
uint8_t is_continue(HopOpaqueField *currOF);
uint8_t is_xovr(HopOpaqueField *currOF);
