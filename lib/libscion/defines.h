#ifndef _DEFINES_H_
#define _DEFINES_H_

#define SCION_UDP_PORT         30040
#define SCION_UDP_EH_DATA_PORT 30041
#define SCION_ROUTER_PORT      50000

// L4 Protocols
#define L4_ICMP     1
#define L4_TCP      6
#define L4_UDP      17
#define L4_SSP      152
#define L4_NONE     254
#define L4_RESERVED 255

#define SCION_HOST_ADDR_MAX 16

#define REV_TOKEN_LEN 32
#define AD_MARKING_METADATA_LEN 8
#define PCB_MARKING_LEN (12 + REV_TOKEN_LEN)

#endif
