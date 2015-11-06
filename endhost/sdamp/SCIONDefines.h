#ifndef SCION_DEFINES_H
#define SCION_DEFINES_H

#include <stdint.h>
#include <stdlib.h>

// Shared defines

//#define SCIOND_API_HOST "127.255.255.254" // Given as compile option
#define SCIOND_API_PORT 3333
#define SCIOND_DISPATCHER_PORT 3334
#define DISPATCHER_BUF_SIZE 2048

#define SCION_UDP_PORT 30040
#define SCION_UDP_EH_DATA_PORT 30041

#define SCION_ADDR_LEN 8 // ISD + AD = 4, ADDR = 4
#define SCION_PROTO_SDAMP 150
#define SCION_PROTO_SUDP 151
#define SCION_PROTO_SSP 152

#define SCION_ISD_AD_LEN 4
#define SCION_HOST_ADDR_LEN 4
#define SCION_HOST_OFFSET 4
#define MAX_HOST_ADDR_LEN 8

#define NORMAL_OF    0x0
#define LAST_OF      0x10
#define PEER_XOVR    0x8
#define TDC_XOVR     0x40
#define NON_TDC_XOVR 0x60
#define INPATH_XOVR  0x70
#define INTRATD_PEER 0x78
#define INTERTD_PEER 0x7C

#define IS_HOP_OF(x) !((x) & 0x80)

typedef struct {
    int addrLen;
    uint8_t addr[MAX_HOST_ADDR_LEN];
    uint16_t port;
} HostAddr;

typedef struct{
    uint32_t isd_ad;
    HostAddr host;
} SCIONAddr;

typedef struct {
    uint32_t isd;
    uint32_t ad;
    uint8_t interface;
} SCIONInterface;

#pragma pack(push)
#pragma pack(1)

typedef struct {
    // 4-bit version
    // 6-bit src addr type
    // 6-bit dst addr type
    uint16_t versionAddrs;
    uint16_t totalLen;
    uint8_t currentIOF;
    uint8_t currentOF;
    uint8_t nextHeader;
    uint8_t headerLen;
} SCIONCommonHeader;

typedef struct {
    SCIONCommonHeader commonHeader;
    uint8_t srcAddr[SCION_ADDR_LEN];
    uint8_t dstAddr[SCION_ADDR_LEN];
    uint8_t *path;
    size_t pathLen;
} SCIONHeader;

#pragma pack(pop)

#endif // SCION_DEFINES_H
