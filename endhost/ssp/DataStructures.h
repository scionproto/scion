#ifndef SCION_DATASTRUCTURES_H
#define SCION_DATASTRUCTURES_H

#include <string.h>

#include <list>
#include <memory>

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
        : len(0),
        dataOffset(0),
        windowSize(0),
        skipCount(0),
        retryAttempts(0),
        interfaceCount(0),
        interfaces(NULL)
    {}

    L4Packet(L4Packet &other)
        : len(other.len),
        dataOffset(other.dataOffset),
        windowSize(other.windowSize),
        skipCount(other.skipCount),
        retryAttempts(other.retryAttempts),
        interfaceCount(other.interfaceCount)
    {
        data = other.data;
        if (interfaceCount) {
            size_t len = interfaceCount * SCION_IF_SIZE;
            interfaces = (uint8_t *)malloc(len);
            memcpy(interfaces, other.interfaces, len);
        } else {
            interfaces = NULL;
        }
    }

    virtual ~L4Packet()
    {
        if (interfaces)
            free(interfaces);
    }

    virtual uint64_t number() { return 0; }

    std::shared_ptr<uint8_t> data;
    size_t len;
    size_t dataOffset;
    size_t windowSize;
    uint32_t skipCount;
    uint8_t retryAttempts;
    size_t interfaceCount;
    uint8_t *interfaces;
};

typedef struct {
    uint64_t flowID;
    uint16_t port;
} SSPEntry;

typedef enum {
    SSP_METRIC_BANDWIDTH,
    SSP_METRIC_LATENCY,
    SSP_METRIC_DEADLINE,
} SSPMetric;

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

    SSPPacket(SSPPacket &other)
        : L4Packet(other)
    {
        header = other.header;
        ack = other.ack;
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
    uint16_t len;
    uint16_t checksum;
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

typedef struct {
    pthread_cond_t *cond;
    pthread_mutex_t *mutex;
} Notification;

typedef std::list<SCIONPacket *> PacketList;

#endif
