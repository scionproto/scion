#ifndef _ADDRESS_H_
#define _ADDRESS_H_

#include "packet.h"

#define SCION_ISD_AD_LEN 4

/*
 * Struct for SCION Addresses:
 * 12 bits ISD ID
 * 20 bits AD ID
 * (4 bytes IPv4 Addr OR
 *  16 bytes IPv6 Addr OR
 *  2 bytes SVC addr)
 */
typedef struct {
    uint32_t isd_ad;
    uint8_t host_addr[16];
} SCIONAddr;

#define ISD(isd_ad) (isd_ad >> 20)
#define AD(isd_ad) (isd_ad & 0xfffff)
#define ISD_AD(isd, ad) ((isd) << 20 | (ad))

#define SCION_ADDR_PAD 8

// Address types and lens
// Null address type
#define ADDR_NONE_TYPE  0
#define ADDR_NONE_LEN   0
// IPv4 address type
#define ADDR_IPV4_TYPE  1
#define ADDR_IPV4_LEN   4
// IPv6 address type
#define ADDR_IPV6_TYPE  2
#define ADDR_IPV6_LEN   16
// SCION Service address type
#define ADDR_SVC_TYPE   3
#define ADDR_SVC_LEN    2

// SVC addresses
#define SVC_BEACON 1
#define SVC_PATH_MGMT 2
#define SVC_CERT_MGMT 3
#define SVC_IFID 4

uint8_t * get_src_addr(uint8_t *buf);
uint8_t get_src_len(uint8_t *buf);
void * get_dst_addr(uint8_t *buf);
uint8_t get_dst_len(uint8_t *buf);

#endif
