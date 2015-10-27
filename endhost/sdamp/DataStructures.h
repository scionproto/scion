#ifndef SCION_DATASTRUCTURES_H
#define SCION_DATASTRUCTURES_H

#include <list>
#include <vector>

#include "SocketConfigs.h"
#include "SCIONDefines.h"

// Socket-related SCION layer stuff
// fields stored in host byte order for incoming, network order for outgoing

typedef struct {
    SCIONHeader header;
    void *payload;

    uint32_t firstHop;
    struct timeval arrivalTime;
    struct timeval sendTime;
    uint32_t rto;
    int pathIndex;
} SCIONPacket;

typedef struct {
    bool exists[MAX_TOTAL_PATHS];
    int receivedPackets[MAX_TOTAL_PATHS];
    int sentPackets[MAX_TOTAL_PATHS];
    int ackedPackets[MAX_TOTAL_PATHS];
    int rtts[MAX_TOTAL_PATHS];
    double lossRates[MAX_TOTAL_PATHS];
    uint64_t highestReceived;
    uint64_t highestAcked;
} SCIONStats;

enum DataProfile {
    SCION_PROFILE_DEFAULT = 0,
    SCION_PROFILE_VOIP,
    SCION_PROFILE_AUDIO,
    SCION_PROFILE_VIDEO,
    SCION_PROFILE_MAX,
};

#pragma pack(push)
#pragma pack(1)

typedef struct {
    uint64_t flowID;
    uint16_t dstPort;
    uint16_t srcPort;
    uint16_t version;
    uint8_t flags;
    uint8_t headerLen;
    uint64_t packetNum;
} SDAMPHeader;

typedef struct {
    uint64_t L;
    int32_t I;
    int32_t H;
    int32_t O;
    uint32_t V;
} SDAMPAck;

#pragma pack(pop)

typedef struct {
    uint32_t size;
    uint8_t *data;
    uint32_t deadline;
    int64_t offset;
    uint32_t retryAttempts;
} SDAMPFrame;

typedef struct {
    SDAMPHeader header;
    SDAMPAck ack;
    SDAMPFrame **frames;
    uint32_t frameCount;
    uint32_t deadline;
    uint32_t windowSize;
    uint32_t skipCount;
    uint32_t retryAttempts;
    uint32_t interfaceCount;
    uint8_t *interfaces;
} SDAMPPacket;

typedef struct {
    uint64_t flowID;
    uint16_t port;
} SDAMPEntry;

typedef enum {
    SDAMP_METRIC_BANDWIDTH,
    SDAMP_METRIC_LATENCY,
    SDAMP_METRIC_DEADLINE,
} SDAMPMetric;

#pragma pack(push)
#pragma pack(1)

typedef struct {
    uint64_t flowID;
    uint16_t port;
    uint8_t headerLen;
    uint32_t offset;
    uint8_t flags;
} SSPHeader;

typedef struct {
    uint64_t L;
    int32_t I;
    int32_t H;
    int32_t O;
    uint32_t V;
} SSPAck;

#pragma pack(pop)

typedef struct {
    uint8_t *data;
    int len;
    uint32_t deadline;
    int refs;
    pthread_mutex_t mutex;
} SSPData;

typedef struct {
    uint32_t offset;
    uint8_t *data;
    uint32_t len;
    int skipCount;
    int windowSize;
    SSPHeader header;
    SSPAck ack;
} SSPOutPacket;

typedef struct {
    uint32_t offset;
    uint8_t *data;
    uint32_t len;
    int windowSize;
    int interfaceCount;
    uint8_t *interfaces;
} SSPInPacket;

#pragma pack(push)
#pragma pack(1)

typedef struct {
    uint16_t srcPort;
    uint16_t dstPort;
    uint8_t flags;
} SUDPHeader;

#pragma pack(pop)

typedef struct {
    SUDPHeader header;
    void *payload;
    size_t payloadLen;
} SUDPPacket;

typedef struct {
    uint16_t port;
} SUDPEntry;

typedef std::list<SCIONPacket *> PacketList;
typedef std::list<SDAMPFrame *> FrameList;

#endif
