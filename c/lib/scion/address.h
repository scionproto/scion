#ifndef _ADDRESS_H_
#define _ADDRESS_H_

#include "defines.h"

#define ISD_AS_LEN 8
// Maximum length string needed to describe any host address.
#define MAX_HOST_ADDR_STR INET6_ADDRSTRLEN

typedef struct {
    uint8_t addr_type;
    uint8_t addr[MAX_HOST_ADDR_LEN];
    uint16_t port;
} HostAddr;

typedef uint64_t isdas_t;

/*
 * Struct for SCION Addresses:
 * 16 bits ISD ID
 * 48 bits AS ID
 * (4 bytes IPv4 Addr OR
 *  16 bytes IPv6 Addr OR
 *  2 bytes SVC addr)
 */
typedef struct {
    isdas_t isd_as;
    HostAddr host;
} SCIONAddr;

#define ISD_BITS 16
#define AS_BITS 48
#define AS_MASK ((1L << AS_BITS) - 1)

#define ISD(isd_as) ((uint16_t)((isd_as) >> AS_BITS))
#define AS(isd_as) ((isd_as) & AS_MASK)
#define ISD_AS(isd, as) ((isd) << AS_BITS | ((as) & AS_MASK))

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

#define SVC_MULTICAST 0x8000

typedef struct {
    uint8_t addr[ISD_AS_LEN + MAX_HOST_ADDR_LEN];
    uint8_t type;
} saddr_t;

#define DST_IA_OFFSET sizeof(SCIONCommonHeader)
#define SRC_IA_OFFSET sizeof(SCIONCommonHeader) + ISD_AS_LEN

int get_addr_len(int type);
isdas_t get_dst_isd_as(uint8_t *buf);
isdas_t get_src_isd_as(uint8_t *buf);
uint8_t get_dst_len(uint8_t *buf);
uint8_t get_src_len(uint8_t *buf);
uint8_t get_addrs_len(uint8_t *buf);
uint8_t * get_dst_addr(uint8_t *buf);
uint8_t * get_src_addr(uint8_t *buf);
void format_host(int, uint8_t *, char *, int);
void print_addresses(uint8_t *buf);

#endif
