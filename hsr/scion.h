/* 
 * SCION HEADER 
 */

#ifndef _SCION_H_
#define _SCION_H_

#define COMMON_HEADER_SIZE 8 
#define EXTENSION_HEADER_SIZE 2
#define OPAQUE_FIELD_SIZE 8
#define BANDWIDTH_OPAQUE_FIELD_SIZE 16
#define FLOWID_SIZE 8
#define NEW_CAPPATH_SIZE 22
#define ROT_VERSION_SIZE 4
#define DEFAULT_ADDR_SIZE 20
#define SRC_ADDR_SIZE 4
#define DST_ADDR_SIZE 4

#define MAX_HOST_ADDR_LEN 8
#define MAX_PATH_LEN 256
#define MAX_TOTAL_PATHS 5
#define MAX_USED_PATHS 2
#define MAX_DATA_PACKET 1024

#define SCIOND_API_HOST "127.255.255.254"
#define SCIOND_API_PORT 3333
#define SCIOND_DISPATCHER_PORT 3334

#define SCION_UDP_PORT 30040
#define SCION_UDP_EH_DATA_PORT 30041

#define SCION_ADDR_LEN 8 // ISD + AD = 4, IPv4 ADDR = 4
#define SCION_PROTO_SDAMP 150

#define SCION_ISD_AD_LEN 4
#define SCION_HOST_ADDR_LEN 4
#define SCION_HOST_OFFSET (SCION_ISD_LEN + SCION_AD_LEN)

#define SCION_COMMON_HEADER_LEN 8

#define SCION_DEFAULT_MTU 576

/*Comments needed*/
#define MAX_FILE_LEN 1024
#define MAXLINELEN 20000
#define MAX_COMMAND_LEN 1024
#define MAX_LOG_LEN 1024
#define MASTER_KEY_LEN 16
#define IFID_SIZE 2
#define AID_SIZE 8
#define TS_SIZE 2 


#define MASTER_SECRET_KEY_SIZE 16 /*in bytes*/


   // # Types for HopOpaqueFields (7 MSB bits).
#define    OFT_NORMAL_OF  0b0000000
#define    OFT_XOVR_POINT  0b0010000  
//#define    PEER_XOVR  0b0001000
   // # Types for Info Opaque Fields (7 MSB bits).
#define    OFT_CORE  0b1000000
#define    OFT_SHORTCUT  0b1100000
//#define    OFT_INPATH_XOVR  0b1110000
#define    OFT_INTRA_ISD_PEER  0b1111000
#define    OFT_INTER_ISD_PEER  0b1111100

#define MAX_AD_HOPS 32
#define PATH_TYPE_TDC 0
#define PATH_TYPE_XOVR 1
#define PATH_TYPE_PEER 2

#define MASK_MSB 0x80
#define UP_PATH_FLAG 0x80  // should be |=;i.e., turn on the first bit
#define DOWN_PATH_FLAG ~(0x80)  // should be &=;i.e., turn off the first bit
#define MASK_EXP_TIME 0x03  // bit mask for taking expiration time from OF

#define TDC_AD 0
#define NON_TDC_AD 1

#define REV_TOKEN_LEN 32
#define AD_MARKING_METADATA_LEN 8
#define PCB_MARKING_LEN (12 + REV_TOKEN_LEN)

/* ===========  packetheader.h ============= */
/**
    @class SCIONPacketHeader
    @struct scionCommonHeader
    @brief Defines the 16byte Common header of the SCION packet

    This struct will represent the 16Byte Common Header for SCION Packet. This
    header will be included and should be included to ALL SCION packets.
*/

#pragma pack(push)
#pragma pack(1)

/**
	Struct for SCION Addresses:
	12 bits ISD ID
	20 bits AD ID
	4 bytes IP Addr
*/
typedef struct {
	uint16_t isd_id:12;
	uint32_t ad_id:20;
	uint8_t host_addr[4];
} SCIONAddr;

typedef struct {
	/** Packet Type of the packet*/
	uint8_t version:4; //last bit is up/down-path flag temporally
	/** Length of the source address */
	uint8_t srcLen:6;
	/** Length of the destination address*/
	uint8_t dstLen:6;
	/** Total Length of the packet */
	uint16_t totalLen;
	/** Index of current Info opaque field*/
	uint8_t currentIOF;
	/** Index of current opaque field*/
	uint8_t currentOF;
	/** next header type, shared with IP protocol number*/
	uint8_t nextHeader;
	/** Header length that includes the path */
	uint8_t headerLen;
} SCIONCommonHeader;

typedef struct {
    SCIONCommonHeader commonHeader;
    SCIONAddr srcAddr;
    SCIONAddr dstAddr;
    uint8_t *path;
    size_t pathLen;
} SCIONHeader;

typedef struct {
	SCIONCommonHeader commonHeader;
	SCIONAddr srcAddr;
	SCIONAddr dstAddr;
	uint8_t *path;
	size_t pathLen;
	uint16_t reply_id; // how many bits?
	uint16_t request_id; // how many bits?
} IFIDHeader;

typedef struct {
/**
    Opaque field for a hop in a path of the SCION packet header.
    Each hop opaque field has a info (8 bits), expiration time (8 bits)
    ingress/egress interfaces (2 * 12 bits) and a MAC (24 bits) authenticating
    the opaque field.
**/

	uint8_t info;
	uint8_t exp_type;
	//uint16_t ingress_if:12;
	//uint16_t egress_if:12;
	uint32_t ingress_egress_if:24;
	uint32_t mac : 24;	
} HopOpaqueField ;


/**
    @brief Special Opaque Field Structure
    The info opaque field contains type info of the path-segment (1 byte),
    a creation timestamp (4 bytes), the ISD ID (2 byte) and # hops for this
    segment (1 byte).

*/
typedef struct {
	/** Info field with timestamp information */
	uint8_t info;
	/** Timestamp value in 16 bit number */
	uint32_t timestamp;
	/** TD Id */
	uint16_t isd_id;
	/** Number of hops under this timestamp (either up or down)*/
	uint8_t hops;
} InfoOpaqueField;

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
	PCBMarking* pms;
	char* asd;
	char eg_rev_token[REV_TOKEN_LEN];
	char* sig;
} ADMarking;

typedef struct {
	InfoOpaqueField iof;
	uint32_t trc_ver;
	uint16_t if_id;
	char segment_id[REV_TOKEN_LEN];
	ADMarking* ads;
} PathSegment;

typedef struct {
	SCIONHeader hdr;
	PathSegment payload;
} PathConstructionBeacon;

#define DATA_PACKET 255
// Path Construction Beacon
#define BEACON_PACKET 1
// Path management packet from/to PS
#define PATH_MGMT_PACKET 2
// TRC file request to parent AD
#define TRC_REQ_PACKET 3
// TRC file request to lCS
#define TRC_REQ_LOCAL_PACKET 4
// TRC file reply from parent AD
#define TRC_REP_PACKET 5
// cert chain request to parent AD
#define CERT_CHAIN_REQ_PACKET 6
// local cert chain request
#define CERT_CHAIN_REQ_LOCAL_PACKET 7
// cert chain reply from lCS
#define CERT_CHAIN_REP_PACKET 8
// IF ID packet to the peer router
#define IFID_PKT_PACKET 9

#pragma pack(pop)


//DPDK port
#define DPDK_EGRESS_PORT 0
#define DPDK_LOCAL_PORT 1


#endif /* _ROUTE_H_ */
