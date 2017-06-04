/* Copyright 2015 ETH Zurich
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

    HostAddr firstHop;
    struct timeval arrivalTime;
    struct timeval sendTime;
    uint32_t rto;
    int pathIndex;
} SCIONPacket;

typedef struct {
    SCMPL4Header *header;
    SCMPPayload *payload;
} SCMPPacket;

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

    uint64_t getFlowID() { return be64toh(header.flowID); }
    void setFlowID(uint64_t flowID) { header.flowID = htobe64(flowID); }

    uint16_t getPort() { return ntohs(header.port); }
    void setPort(uint16_t port) { header.port = htons(port); }

    uint64_t getOffset() { return be64toh(header.offset) & 0xffffffffffffff; }
    void setOffset(uint64_t offset) { header.offset = htobe64(offset & 0xffffffffffffff); }

    uint8_t getMark() { return be64toh(header.offset) >> 56; }
    void setMark(uint8_t mark)
    {
        uint64_t offset = mark;
        offset = offset << 56;
        offset |= getOffset();
        header.offset = htobe64(offset);
    }

    uint64_t getL() { return be64toh(ack.L); }
    void setL(uint64_t L) { ack.L = htobe64(L); }

    int getI() { return ntohl(ack.I); }
    void setI(int I) { ack.I = htonl(I); }

    uint64_t getAckNum() { return getL() + getI(); }

    int getH() { return ntohl(ack.H); }
    void setH(int H) { ack.H = htonl(H); }

    int getO() { return ntohl(ack.O); }
    void setO(int O) { ack.O = htonl(O); }

    uint32_t getV() { return ntohl(ack.V); }
    void setV(uint32_t V) { ack.V = htonl(V); }

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
