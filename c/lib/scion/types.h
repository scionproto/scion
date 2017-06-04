#ifndef _TYPES_H_
#define _TYPES_H_

/* Packet types */
#define DATA_PACKET 0
// Path Construction Beacon
#define BEACON_PACKET 1
// Path management packet from/to PS
#define PATH_MGMT_PACKET 2
// Cert management packet
#define CERT_MGMT_PACKET 3
// IF ID packet to the peer router
#define IFID_PACKET 4
// error condition
#define PACKET_TYPE_ERROR 99

// SCION UDP packet classes
#define PCB_CLASS 0
#define IFID_CLASS 1
#define CERT_CLASS 2
#define PATH_CLASS 3

// IFID Packet types
#define IFID_PAYLOAD_TYPE 0

// PATH Packet types
#define PMT_REQUEST_TYPE 0
#define PMT_REPLY_TYPE 1
#define PMT_REG_TYPE 2
#define PMT_SYNC_TYPE 3
#define PMT_REVOCATION_TYPE 4
#define PMT_IFSTATE_INFO_TYPE 5
#define PMT_IFSTATE_REQ_TYPE 6

#endif
