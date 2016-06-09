#ifndef SCION_DATASTRUCTURES_H
#define SCION_DATASTRUCTURES_H

#include <string.h>

#include <list>
#include <memory>

#include "SCIONDefines.h"
#include "SocketConfigs.h"

// Socket-related SCION layer stuff
// fields stored in host byte order for incoming, network order for outgoing

enum DataProfile {
    SCION_PROFILE_DEFAULT = 0,
    SCION_PROFILE_VOIP,
    SCION_PROFILE_AUDIO,
    SCION_PROFILE_VIDEO,
    SCION_PROFILE_MAX,
};

typedef struct SCIONExtension {
    uint8_t nextHeader;
    uint8_t headerLen;
    uint8_t type;
    uint8_t extClass;
    void *data;
    struct SCIONExtension *nextExt;
} SCIONExtension;

typedef struct {
    SCIONCommonHeader commonHeader;
    uint8_t srcAddr[ISD_AS_LEN + MAX_HOST_ADDR_LEN];
    uint8_t dstAddr[ISD_AS_LEN + MAX_HOST_ADDR_LEN];
    uint8_t *path;
    size_t pathLen;
    SCIONExtension *extensions;
    size_t numExtensions;
} SCIONHeader;

typedef struct {
    SCIONHeader header;
    void *payload;

    uint32_t firstHop;
    struct timeval arrivalTime;
    struct timeval sendTime;
    uint32_t rto;
    int pathIndex;
} SCIONPacket;

#pragma pack(push)
#pragma pack(1)

typedef struct {
    uint64_t flowID;
    uint16_t port;
    uint8_t headerLen;
    uint64_t offset;
    uint8_t flags;
} SSPHeader;

typedef struct {
    uint64_t L;
    int32_t I;
    int32_t H;
    int32_t O;
    uint32_t V;
} SSPAck;

typedef enum {
    SSP_METRIC_BANDWIDTH,
    SSP_METRIC_LATENCY,
    SSP_METRIC_DEADLINE,
} SSPMetric;

#pragma pack(pop)

struct SSPPacket {
    SSPPacket()
        : data(NULL),
        len(0),
        dataOffset(0),
        windowSize(0),
        skipCount(0),
        retryAttempts(0),
        interfaceCount(0),
        interfaces(NULL)
    {
        memset(&header, 0, sizeof(header));
        memset(&ack, 0, sizeof(ack));
    }

    SSPPacket(SSPPacket &other)
        : len(other.len),
        dataOffset(other.dataOffset),
        windowSize(other.windowSize),
        skipCount(other.skipCount),
        retryAttempts(other.retryAttempts),
        interfaceCount(other.interfaceCount)
    {
        data = other.data;
        if (interfaceCount) {
            size_t len = interfaceCount * IF_TOTAL_LEN;
            interfaces = (uint8_t *)malloc(len);
            memcpy(interfaces, other.interfaces, len);
        } else {
            interfaces = NULL;
        }
        header = other.header;
        ack = other.ack;
    }

    ~SSPPacket()
    {
        if (interfaces)
            free(interfaces);
    }

    uint64_t getOffset(bool outgoing)
    {
        if (outgoing)
            return be64toh(header.offset) & 0xffffffffffffff;
        else
            return header.offset & 0xffffffffffffff;
    }

    void setOffset(uint64_t offset, bool outgoing)
    {
        header.offset = offset & 0xffffffffffffff;
        if (outgoing)
            header.offset = be64toh(header.offset);
    }

    uint8_t getMark(bool outgoing)
    {
        return getOffset(outgoing) >> 56;
    }

    void setMark(uint8_t mark, bool outgoing)
    {
        uint64_t offset = mark;
        offset = offset << 56;
        offset |= getOffset(outgoing);
        header.offset = offset;
        if (outgoing)
            header.offset = be64toh(header.offset);
    }

    std::shared_ptr<uint8_t> data;
    size_t len;
    size_t dataOffset;
    size_t windowSize;
    uint32_t skipCount;
    uint8_t retryAttempts;
    size_t interfaceCount;
    uint8_t *interfaces;

    SSPHeader header;
    SSPAck ack;
};

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
    uint32_t isd_as;
    uint16_t port;
    uint8_t addr_type;
    uint64_t flow_id;
    uint8_t addr[MAX_HOST_ADDR_LEN];
} DispatcherEntry;

typedef struct {
    pthread_cond_t *cond;
    pthread_mutex_t *mutex;
} Notification;

typedef std::list<SCIONPacket *> PacketList;

#endif
