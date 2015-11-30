#include "scion.h"

unsigned char *get_dstaddr(SCIONHeader *hdr);
uint8_t get_type(SCIONHeader *hdr);
uint8_t is_on_up_path(InfoOpaqueField *currOF);
uint8_t is_last_path_of(SCIONCommonHeader *sch);
uint8_t is_regular(HopOpaqueField *currOF);
uint8_t is_continue(HopOpaqueField *currOF);
uint8_t is_xovr(HopOpaqueField *currOF);
