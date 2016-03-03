#ifndef _OPAQUE_FIELD_H_
#define _OPAQUE_FIELD_H_

// Types for HopOpaqueFields (7 MSB bits).
#define    OFT_NORMAL_OF       0b0000000
#define    OFT_XOVR_POINT      0b0010000  
// Types for Info Opaque Fields (7 MSB bits).
#define    OFT_CORE            0b1000000
#define    OFT_SHORTCUT        0b1100000
#define    OFT_INTRA_ISD_PEER  0b1111000
#define    OFT_INTER_ISD_PEER  0b1111100

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

#endif
