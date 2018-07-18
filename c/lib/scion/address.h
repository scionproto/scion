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
#define AS_MASK (((uint64_t)1 << AS_BITS) - 1)

#define ISD(isd_as) ((uint16_t)((isd_as) >> AS_BITS))
#define AS(isd_as) ((isd_as) & AS_MASK)
#define ISD_AS(isd, as) ((isd) << AS_BITS | ((as) & AS_MASK))

#define SCION_ADDR_PAD 8

// Address types and lens
#define foreach_addr_type_len \
_(NONE, 0)  \
_(IPV4, 4)  \
_(IPV6, 16) \
_(SVC, 2)

enum {
#define _(type, len) ADDR_##type##_TYPE,
    foreach_addr_type_len
#undef _
    ADDR_TYPE_N
};

enum {
#define _(type, len) ADDR_##type##_LEN = len,
    foreach_addr_type_len
#undef _
};

static const uint32_t ADDR_LENS[] = {
#define _(type, len) len,
    foreach_addr_type_len
#undef _
};

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

int get_addr_len(uint8_t type);
isdas_t get_dst_isd_as(uint8_t *buf);
isdas_t get_src_isd_as(uint8_t *buf);
uint8_t get_dst_len(uint8_t *buf);
uint8_t get_src_len(uint8_t *buf);
uint8_t get_addrs_len(uint8_t *buf);
uint8_t * get_dst_addr(uint8_t *buf);
uint8_t * get_src_addr(uint8_t *buf);
void format_host(int, uint8_t *, char *, int);
void print_addresses(uint8_t *buf);
char *addr_type_str(uint8_t addr_type);

#endif
