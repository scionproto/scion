#ifndef SCION_DATASTRUCTURES_H
#define SCION_DATASTRUCTURES_H

#include <stdlib.h>
#include <string.h>
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

enum DataProfile {
    SCION_PROFILE_DEFAULT = 0,
    SCION_PROFILE_VOIP,
    SCION_PROFILE_AUDIO,
    SCION_PROFILE_VIDEO,
    SCION_PROFILE_MAX,
};

class L4Packet {
public:
    L4Packet()
        : data(NULL),
        len(0),
        windowSize(0),
        skipCount(0),
        retryAttempts(0),
        interfaceCount(0),
        interfaces(NULL)
    {}

    virtual ~L4Packet()
    {
        if (data)
            free(data);
    }

    virtual uint64_t number() { return 0; }

    uint8_t *data;
    size_t len;
    size_t windowSize;
    uint32_t skipCount;
    uint8_t retryAttempts;
    size_t interfaceCount;
    uint8_t *interfaces;
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

class SDAMPPacket : public L4Packet {
public:
    SDAMPPacket()
        : L4Packet(),
        deadline(0)
    {
        memset(&header, 0, sizeof(header));
        memset(&ack, 0, sizeof(ack));
    }

    ~SDAMPPacket() {}

    uint64_t number() { return header.packetNum; }

    SDAMPHeader header;
    SDAMPAck ack;
    uint32_t deadline;
};

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
    uint64_t offset;
    uint8_t flags;
    uint8_t mark;
} SSPHeader;

typedef struct {
    uint64_t L;
    int32_t I;
    int32_t H;
    int32_t O;
    uint32_t V;
    uint8_t mark;
    bool full;
} SSPAck;

#pragma pack(pop)

class SSPPacket : public L4Packet {
public:
    SSPPacket()
        : L4Packet()
    {
        memset(&header, 0, sizeof(header));
        memset(&ack, 0, sizeof(ack));
    }

    ~SSPPacket() {}

    uint64_t number() { return header.offset; }

    SSPHeader header;
    SSPAck ack;
};

typedef struct {
    uint8_t *data;
    int len;
    uint32_t deadline;
    int refs;
    pthread_mutex_t mutex;
} SSPData;

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

#endif
