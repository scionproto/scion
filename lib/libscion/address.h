#ifndef _ADDRESS_H_
#define _ADDRESS_H_

#include "defines.h"

#define ISD_AS_LEN 4

typedef struct {
    int addr_len;
    uint8_t addr[MAX_HOST_ADDR_LEN];
    uint16_t port;
} HostAddr;

/*
 * Struct for SCION Addresses:
 * 12 bits ISD ID
 * 20 bits AS ID
 * (4 bytes IPv4 Addr OR
 *  16 bytes IPv6 Addr OR
 *  2 bytes SVC addr)
 */
typedef struct {
    uint32_t isd_as;
    HostAddr host;
} SCIONAddr;

#define ISD(isd_as) (isd_as >> 20)
#define AS(isd_as) (isd_as & 0xfffff)
#define ISD_AS(isd, as) ((isd) << 20 | (as))

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
#define SVC_BEACON 0
#define SVC_PATH_MGMT 1
#define SVC_CERT_MGMT 2
#define SVC_SIBRA 3

uint8_t * get_src_addr(uint8_t *buf);
uint8_t get_src_len(uint8_t *buf);
uint8_t * get_dst_addr(uint8_t *buf);
uint8_t get_dst_len(uint8_t *buf);

#endif
