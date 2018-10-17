#ifndef _OPAQUE_FIELD_H_
#define _OPAQUE_FIELD_H_

#define SCION_OF_LEN 8

#define IOF_FLAG_UPDOWN   0x01
#define IOF_FLAG_SHORTCUT 0x02
#define IOF_FLAG_PEER     0x04

#define HOF_FLAG_XOVER        0x01
#define HOF_FLAG_VERIFY_ONLY  0x02

#define PATH_TYPE_TDC 0
#define PATH_TYPE_XOVR 1
#define PATH_TYPE_PEER 2

#define MASK_MSB 0x80
#define UP_PATH_FLAG 0x80  // should be |=;i.e., turn on the first bit
#define DOWN_PATH_FLAG ~(0x80)  // should be &=;i.e., turn off the first bit
#define MASK_EXP_TIME 0x03  // bit mask for taking expiration time from OF

#define IS_HOP_OF(x) !((x) & 0x80)

#define TDC_AD 0
#define NON_TDC_AD 1

#pragma pack(push)
#pragma pack(1)

typedef struct {
/*
 *  Opaque field for a hop in a path of the SCION packet header.
 *  Each hop opaque field has a info (8 bits), expiration time (8 bits)
 *  ingress/egress interfaces (2 * 12 bits) and a MAC (24 bits) authenticating
 *  the opaque field.
 */
    uint8_t info;
    uint8_t exp_type;
    //uint16_t ingress_if:12;
    //uint16_t egress_if:12;
    uint32_t ingress_egress_if:24;
    uint32_t mac : 24;  
} HopOpaqueField ;

/*
 *  Special Opaque Field Structure
 *  The info opaque field contains type info of the path-segment (1 byte),
 *  a creation timestamp (4 bytes), the ISD ID (2 byte) and # hops for this
 *  segment (1 byte).
 */
typedef struct {
    /** Info field with timestamp information */
    uint8_t info;
    /** Timestamp value in 16 bit number */
    uint32_t timestamp;
    /** TD Id */
    uint16_t isd_id;
    /** Number of hops under this timestamp (either up or down) */
    uint8_t hops;
} InfoOpaqueField;

#pragma pack(pop)

#define IOF_UP(x) ((*x) & IOF_FLAG_UPDOWN)
#define IOF_SHORTCUT(x) ((*x) & IOF_FLAG_SHORTCUT)
#define IOF_PEER(x) ((*x) & IOF_FLAG_PEER)
#define IOF_TS(x) ntohl(*(uint32_t *)((uint8_t *)(x) + 1))
#define IOF_HOPS(x) (*((uint8_t *)(x) + SCION_OF_LEN - 1))

#define HOF_XOVER(x) ((*x) & HOF_FLAG_XOVER)
#define HOF_VERIFY(x) ((*x) & HOF_FLAG_VERIFY_ONLY)
#define HOF_EXP_TIME(x) (*((uint8_t *)(x) + 1))

uint8_t * get_current_iof(uint8_t *buf);
uint8_t * get_current_hof(uint8_t *buf);
uint16_t get_fwd_if(uint8_t *buf);
uint32_t get_ingress_egress(uint8_t *hof);
uint16_t get_ingress_if(uint8_t *hof);
uint16_t get_egress_if(uint8_t *hof);

#endif
