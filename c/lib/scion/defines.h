#ifndef _DEFINES_H_
#define _DEFINES_H_

#define SCIOND_API_PORT 3333
#define DISPATCHER_DIR "/run/shm/dispatcher"
#define DEFAULT_DISPATCHER_ID "default"

#define DISPATCHER_BUF_SIZE 65535

#define SCION_UDP_EH_DATA_PORT 30041
#define SCION_FILTER_CMD_PORT  30042
#define SCION_ROUTER_PORT      50000

#define L4_PROTOCOL_COUNT 3
// L4 Protocols
#define L4_NONE     0
#define L4_SCMP     1
#define L4_TCP      6
#define L4_UDP      17

#define MAX_HOST_ADDR_LEN 16

#define IFID_LEN 2

#define REV_TOKEN_LEN 32
#define AD_MARKING_METADATA_LEN 8
#define PCB_MARKING_LEN (12 + REV_TOKEN_LEN)

#define MAX_SEGMENT_TTL (24 * 60 * 60)
#define EXP_TIME_UNIT (MAX_SEGMENT_TTL >> 8)

#define LINE_LEN 8

#endif
