#ifndef _PATH_H_
#define _PATH_H_

#include "defines.h"

#pragma pack(push)
#pragma pack(1)

typedef struct {
    uint16_t isd_id:12;
    uint32_t ad_id:20;
    HopOpaqueField hof;
    char ig_rev_token[REV_TOKEN_LEN];
} PCBMarking;

typedef struct {
    uint16_t cert_ver;
    uint16_t sig_len;
    uint16_t asd_len;
    uint16_t block_len;
    PCBMarking pcbm;
    PCBMarking *pms;
    char *asd;
    char eg_rev_token[REV_TOKEN_LEN];
    char *sig;
} ADMarking;

typedef struct {
    InfoOpaqueField iof;
    uint32_t trc_ver;
    uint16_t if_id;
    char segment_id[REV_TOKEN_LEN];
    ADMarking *ads;
} PathSegment;

typedef struct {
    PathSegment payload;
} PathConstructionBeacon;

#pragma pack(pop)

// 12bit is egress if and 8 bit gap between uint32 and 24bit field
#define INGRESS_IF(HOF) (ntohl((HOF)->ingress_egress_if) >> (12 + 8))
#define EGRESS_IF(HOF) ((ntohl((HOF)->ingress_egress_if) >> 8) & 0x000fff)

int reverse_path(uint8_t *buf, uint8_t *reverse);
uint8_t * get_hof_ver(uint8_t *buf, int ingress);
uint8_t * get_hof_ver_normal(uint8_t *buf);

#endif
