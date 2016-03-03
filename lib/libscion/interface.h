#ifndef _INTERFACE_H_
#define _INTERFACE_H_

#include "defines.h"

#define IFID_PKT_US 1000000
#define IFSTATE_REQ_US 30000000

#pragma pack(push)
#pragma pack(1)

typedef struct {
    uint16_t reply_id; // how many bits?
    uint16_t request_id; // how many bits?
} IFIDHeader;

typedef struct {
    int is_active;
    uint8_t rev_info[REV_TOKEN_LEN];
} InterfaceState;

#pragma pack(pop)

#endif
