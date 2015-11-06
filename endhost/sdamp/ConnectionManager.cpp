#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <time.h>
#include <limits.h>

#include "ConnectionManager.h"
#include "Path.h"
#include "SCIONProtocol.h"
#include "Utils.h"

PathManager::PathManager(std::vector<SCIONAddr> &addrs, int sock)
    : mSendSocket(sock),
    mDstAddrs(addrs)
{
    struct sockaddr_in addr;

    mDaemonSocket = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(mDaemonSocket, (struct sockaddr *)&addr, sizeof(addr));
    memset(&mLocalAddr, 0, sizeof(mLocalAddr));
}

PathManager::~PathManager()
{
    close(mDaemonSocket);
}

int PathManager::getSocket()
{
    return mSendSocket;
}

int PathManager::getPathCount()
{
    return mPaths.size();
}

int PathManager::maxPayloadSize()
{
    int min = INT_MAX;
    for (size_t i = 0; i < mPaths.size(); i++) {
        int size = mPaths[i]->getPayloadLen(false);
        if (size < min)
            min = size;
    }
    return min;
}

void PathManager::getPaths()
{
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    int buflen = (MAX_PATH_LEN + 15) * MAX_TOTAL_PATHS;
    int recvlen;
    uint8_t buf[buflen];
    std::vector<SCIONAddr>::iterator i;
    
    memset(&addr, 0, addrlen);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(SCIOND_API_HOST);
    addr.sin_port = htons(SCIOND_API_PORT);

    memset(buf, 0, buflen);

    // Get local address first
    if (mLocalAddr.isd_ad == 0) {
        // invalid ISD, meaning we haven't got the local address yet
        buf[0] = 1;
        sendto(mDaemonSocket, buf, 1, 0, (struct sockaddr *)&addr, addrlen);
        recvfrom(mDaemonSocket, buf, buflen, 0, NULL, NULL);
        mLocalAddr.isd_ad = ntohl(*(uint32_t *)buf);
        mLocalAddr.host.addrLen = SCION_HOST_ADDR_LEN;
        memcpy(mLocalAddr.host.addr, buf + SCION_HOST_OFFSET, SCION_HOST_ADDR_LEN);
    }

    int invalid = 0;
    for (size_t j = 0; j < mPaths.size(); j++) {
        if (!mPaths[j]->isValid())
            invalid++;
    }
    // Now get paths for remote address(es)
    std::vector<Path *> candidates;
    for (i = mDstAddrs.begin(); i != mDstAddrs.end(); i++) {
        memset(buf, 0, buflen);
        *(uint32_t *)(buf + 1) = htonl(i->isd_ad);
        sendto(mDaemonSocket, buf, 5, 0, (struct sockaddr *)&addr, addrlen);

        memset(buf, 0, buflen);
        recvlen = recvfrom(mDaemonSocket, buf, buflen, 0, NULL, NULL);
        if (recvlen > 0) {
            DEBUG("%d byte response from daemon\n", recvlen);
            int offset = 0;
            while (offset < recvlen &&
                    mPaths.size() - invalid + candidates.size() < MAX_TOTAL_PATHS) {
                bool found = false;
                int pathLen = *(buf + offset) * 8;
                int interfaceOffset = offset + 1 + pathLen + SCION_HOST_ADDR_LEN + 2;
                int interfaceCount = *(buf + interfaceOffset);
                for (size_t j = 0; j < mPaths.size(); j++) {
                    if (mPaths[j]->usesSameInterfaces(buf + interfaceOffset + 1, interfaceCount)) {
                        found = true;
                        break;
                    }
                }
                for (size_t j = 0; j < candidates.size(); j++) {
                    if (candidates[j]->usesSameInterfaces(buf + interfaceOffset + 1, interfaceCount)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    Path *p = createPath(*i, buf + offset, 0);
                    candidates.push_back(p);
                }
                offset = interfaceOffset + 1 + interfaceCount * 5;
            }
        }
        if (mPaths.size() - invalid + candidates.size() == MAX_TOTAL_PATHS)
            break;
    }
    for (size_t j = 0; j < candidates.size(); j++) {
        size_t slot;
        for (slot = 0; slot < mPaths.size(); slot++) {
            if (!mPaths[slot]->isValid()) {
                DEBUG("path %lu no longer valid, replace\n", slot);
                Path *p = mPaths[slot];
                mPaths[slot] = candidates[j];
                mPaths[slot]->setIndex(slot);
                delete p;
                break;
            }
        }
        if (slot == mPaths.size()) {
            mPaths.push_back(candidates[j]);
            mPaths[slot]->setIndex(slot);
        }
    }
    DEBUG("total %lu paths\n", mPaths.size() - invalid);
}

Path * PathManager::createPath(SCIONAddr &dstAddr, uint8_t *rawPath, int pathLen)
{
    return new Path(this, mLocalAddr, dstAddr, rawPath, pathLen);
}

void PathManager::handleTimeout()
{
}

void PathManager::getStats(SCIONStats *stats)
{
}

// SUDP

SUDPConnectionManager::SUDPConnectionManager(std::vector<SCIONAddr> &addrs, int sock)
    : PathManager(addrs, sock)
{
    memset(&mLastProbeTime, 0, sizeof(struct timeval));
    getPaths();
    mLastProbeAcked.resize(mPaths.size());
    for (size_t i = 0; i < mPaths.size(); i++) {
        mLastProbeAcked[i] = 0;
        mPaths[i]->setUp();
    }
}

SUDPConnectionManager::~SUDPConnectionManager()
{
}

int SUDPConnectionManager::send(SCIONPacket *packet)
{
    // TODO: Choose optimal path?
    for (size_t i = 0; i < mPaths.size(); i++)
        if (mPaths[i]->isUp())
            return mPaths[i]->send(packet, mSendSocket);
    return -1;
}

void SUDPConnectionManager::sendProbes(uint32_t probeNum, uint16_t srcPort, uint16_t dstPort)
{
    DEBUG("send probes to dst port %d\n", dstPort);
    int ret = 0;
    for (size_t i = 0; i < mPaths.size(); i++) {
        DEBUG("send probe on path %d\n", mPaths[i]->getIndex());
        SCIONPacket p;
        memset(&p, 0, sizeof(p));
        buildCommonHeader(p.header.commonHeader, SCION_PROTO_SUDP);
        SUDPPacket sp;
        memset(&sp, 0, sizeof(sp));
        p.payload = &sp;
        SUDPHeader &sh = sp.header;
        sh.srcPort = htons(srcPort);
        sh.dstPort = htons(dstPort);
        sh.flags |= SUDP_PROBE;
        sp.payload = (void *)(size_t)htonl(probeNum);
        sp.payloadLen = 4;
        ret |= mPaths[i]->send(&p, mSendSocket);
        if (mLastProbeAcked[i] < probeNum - 3) {
            struct timeval t;
            gettimeofday(&t, NULL);
            mPaths[i]->handleTimeout(&t);
        }
    }
}

void SUDPConnectionManager::handlePacket(SCIONPacket *packet)
{
    bool found = false;
    int index;
    for (size_t i = 0; i < mPaths.size(); i++) {
        if (mPaths[i]->isSamePath(packet->header.path, packet->header.pathLen)) {
            found = true;
            index = i;
            break;
        }
    }
    if (!found) {
        SCIONAddr saddr;
        saddr.isd_ad = ntohl(*(uint32_t *)(packet->header.srcAddr));
        saddr.host.addrLen = SCION_HOST_ADDR_LEN;
        memcpy(&(saddr.host.addr), packet->header.srcAddr + SCION_HOST_OFFSET, SCION_HOST_ADDR_LEN);

        SUDPPath *p = new SUDPPath(this, mLocalAddr, saddr, packet->header.path, packet->header.pathLen);
        p->setFirstHop(SCION_HOST_ADDR_LEN, (uint8_t *)&(packet->firstHop));
        mPaths.push_back(p);
        p->setIndex(mPaths.size() - 1);
        index = mPaths.size() - 1;
        mLastProbeAcked.resize(mPaths.size());
    }
    packet->pathIndex = index;

    DEBUG("packet came on path %d\n", index);
    mPaths[index]->setUp();
    SUDPPacket *sp = (SUDPPacket *)(packet->payload);
    if (sp->header.flags & SUDP_PROBE) {
        if (sp->header.flags & SUDP_PROBE_ACK) {
            mLastProbeAcked[index] = ntohl((size_t)(sp->payload) & 0xffffffff);
            DEBUG("probe %u acked on path %d\n", mLastProbeAcked[index], index);
        } else {
            SCIONPacket p;
            memset(&p, 0, sizeof(p));
            buildCommonHeader(p.header.commonHeader, SCION_PROTO_SUDP);
            SUDPPacket ack;
            p.payload = &ack;
            memset(&ack, 0, sizeof(ack));
            SUDPHeader &sh = ack.header;
            sh.srcPort = htons(sp->header.dstPort);
            sh.dstPort = htons(sp->header.srcPort);
            sh.flags |= SUDP_PROBE | SUDP_PROBE_ACK;
            ack.payload = sp->payload;
            ack.payloadLen = 4;
            mPaths[index]->send(&p, mSendSocket);
            DEBUG("sending probe ack back to dst port %d\n", sp->header.srcPort);
        }
    }
}

Path * SUDPConnectionManager::createPath(SCIONAddr &dstAddr, uint8_t *rawPath, int pathLen)
{
    return new SUDPPath(this, mLocalAddr, dstAddr, rawPath, pathLen);
}

// SDAMP

SDAMPConnectionManager::SDAMPConnectionManager(std::vector<SCIONAddr> &addrs, int sock)
    : PathManager(addrs, sock)
{
}

SDAMPConnectionManager::SDAMPConnectionManager(std::vector<SCIONAddr> &addrs, int sock, SDAMPProtocol *protocol)
    : PathManager(addrs, sock),
    mInitPacketQueued(false),
    mMetric(SDAMP_METRIC_BANDWIDTH),
    mProtocol(protocol)
{
    for (int i = 0; i < MAX_TOTAL_PATHS; i++)
        mRunning[i] = true;
    mFreshFrames = new PriorityQueue<SDAMPFrame *>(compareDeadline);
    mRetryFrames = new PriorityQueue<SDAMPFrame *>(compareDeadline);
    pthread_mutex_init(&mMutex, NULL);
    pthread_mutex_init(&mSentMutex, NULL);
    pthread_cond_init(&mSentCond, NULL);
    pthread_mutex_init(&mFreshMutex, NULL);
    pthread_mutex_init(&mRetryMutex, NULL);
    pthread_mutex_init(&mPacketMutex, NULL);
    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_REALTIME);
    pthread_cond_init(&mPacketCond, &ca);
    getPaths();
}

SDAMPConnectionManager::~SDAMPConnectionManager()
{
    for (int i = 0; i < MAX_TOTAL_PATHS; i++)
        mRunning[i] = false;
    pthread_cond_broadcast(&mPacketCond);
    DEBUG("broadcast to path threads\n");
    std::vector<SDAMPFrame *>::iterator it;
    for (it = mFreshFrames->begin(); it != mFreshFrames->end(); it++)
        destroySDAMPFrame(*it);
    delete mFreshFrames;
    for (it = mRetryFrames->begin(); it != mRetryFrames->end(); it++)
        destroySDAMPFrame(*it);
    delete mRetryFrames;
    while (!mPaths.empty()) {
        SDAMPPath *p = (SDAMPPath *)(mPaths.back());
        mPaths.pop_back();
        p->terminate();
        DEBUG("path %d terminated\n", p->getIndex());
        delete p;
    }
    pthread_mutex_destroy(&mMutex);
    pthread_mutex_destroy(&mSentMutex);
    pthread_cond_destroy(&mSentCond);
    pthread_mutex_destroy(&mFreshMutex);
    pthread_mutex_destroy(&mRetryMutex);
    pthread_mutex_destroy(&mPacketMutex);
    pthread_cond_destroy(&mPacketCond);
}

void SDAMPConnectionManager::waitForSendBuffer(int len, int windowSize)
{
    while (totalQueuedSize() + len > windowSize) {
        pthread_mutex_lock(&mSentMutex);
        DEBUG("%lu packets in sent list, %lu in retry list, %lu in fresh list\n",
                mSentPackets.size(), mRetryFrames->size(), mFreshFrames->size());
        pthread_cond_wait(&mSentCond, &mSentMutex);
        pthread_mutex_unlock(&mSentMutex);
    }
}

int SDAMPConnectionManager::totalQueuedSize()
{
    std::vector<SDAMPFrame *>::iterator i;
    int total = 0;
    pthread_mutex_lock(&mPacketMutex);

    pthread_mutex_lock(&mFreshMutex);
    for (i = mFreshFrames->begin(); i != mFreshFrames->end(); i++)
        total += (*i)->size;
    pthread_mutex_unlock(&mFreshMutex);
    pthread_mutex_lock(&mRetryMutex);
    for (i = mRetryFrames->begin(); i != mRetryFrames->end(); i++)
        total += (*i)->size;
    pthread_mutex_unlock(&mRetryMutex);
    PacketList::iterator j;
    pthread_mutex_lock(&mSentMutex);
    for (j = mSentPackets.begin(); j != mSentPackets.end(); j++)
        total += ntohs((*j)->header.commonHeader.totalLen);
    pthread_mutex_unlock(&mSentMutex);

    pthread_mutex_unlock(&mPacketMutex);
    return total;
}

void SDAMPConnectionManager::startPaths()
{
    for (size_t i = 0; i < mPaths.size(); i++)
        ((SDAMPPath *)(mPaths[i]))->start();
}

void SDAMPConnectionManager::queueFrame(SDAMPFrame *frame)
{
    pthread_mutex_lock(&mPacketMutex);
    if (frame->retryAttempts == 0) {
        DEBUG("queue new frame\n");
        pthread_mutex_lock(&mFreshMutex);
        mFreshFrames->push(frame);
        pthread_mutex_unlock(&mFreshMutex);
    } else {
        DEBUG("queue retry frame\n");
        pthread_mutex_lock(&mRetryMutex);
        mRetryFrames->push(frame);
        pthread_mutex_unlock(&mRetryMutex);
    }
    pthread_mutex_unlock(&mPacketMutex);
    pthread_cond_broadcast(&mPacketCond);
}

bool SDAMPConnectionManager::sleepIfUnused(int index)
{
    struct timeval t;
    gettimeofday(&t, NULL);
    while (!mPaths[index]->isUsed()) {
        if (mPaths[index]->isUp() &&
                mPaths[index]->getIdleTime(&t) >= SDAMP_PRIME_INTERVAL) {
            DEBUG("Prime path %d\n", index);
            return true;
        }
        DEBUG("path %d: wait until active\n", index);
        if (!mRunning[index])
            return false;
        pthread_cond_wait(&mPacketCond, &mPacketMutex);
        gettimeofday(&t, NULL);
    }
    return false;
}

void SDAMPConnectionManager::didSend(SCIONPacket *packet)
{
    SDAMPPacket *sp = (SDAMPPacket *)(packet->payload);
    if (sp->header.packetNum == 0) {
        if (mInitPacketQueued)
            return;
        else
            mInitPacketQueued = true;
    }
    pthread_mutex_lock(&mSentMutex);
    DEBUG("add packet %lu to sent list\n", be64toh(sp->header.packetNum));
    mSentPackets.push_back(packet);
    pthread_mutex_unlock(&mSentMutex);
}

void SDAMPConnectionManager::abortSend(SCIONPacket *packet)
{
    pthread_mutex_lock(&mRetryMutex);
    SDAMPPacket *sp = (SDAMPPacket *)(packet->payload);
    for (size_t i = 0; i < sp->frameCount; i++)
        mRetryFrames->push(sp->frames[i]);
    destroySDAMPPacket(sp);
    destroySCIONPacket(packet);
    pthread_mutex_unlock(&mRetryMutex);
}

void SDAMPConnectionManager::sendAck(SCIONPacket *packet)
{
    DEBUG("send ack on path %d\n", packet->pathIndex);
    mPaths[packet->pathIndex]->send(packet, mSendSocket);
}

void SDAMPConnectionManager::sendProbes(uint32_t probeNum, uint64_t flowID)
{
    DEBUG("send probes\n");
    bool refresh = false;
    std::vector<Path *>::iterator i;
    for (i = mPaths.begin(); i != mPaths.end(); i++) {
        if (!(*i)->isUp() && (*i)->isValid()) {
            DEBUG("send probe on path %d\n", (*i)->getIndex());
            SCIONPacket p;
            memset(&p, 0, sizeof(p));
            buildCommonHeader(p.header.commonHeader, SCION_PROTO_SDAMP);
            SDAMPPacket sp;
            memset(&sp, 0, sizeof(sp));
            p.payload = &sp;
            SDAMPHeader &sh = sp.header;
            sh.headerLen = sizeof(sh);
            sh.flowID = htobe64(flowID);
            sh.packetNum = htobe64(probeNum);
            sh.flags |= SDAMP_PROBE;
            int ret = (*i)->send(&p, mSendSocket);
            if (ret) {
                DEBUG("terminate path %d\n", (*i)->getIndex());
                mRunning[(*i)->getIndex()] = false;
                pthread_cond_broadcast(&mPacketCond);
                ((SDAMPPath *)(*i))->terminate();
                refresh = true;
            }
        }
    }
    if (refresh) {
        // One or more paths down for long time
        DEBUG("get fresh paths\n");
        getPaths();
        for (size_t j = 0; j < mPaths.size(); j++) {
            SDAMPPath *p = (SDAMPPath *)mPaths[j];
            if (p->isValid() && !mRunning[j]) {
                mRunning[j] = true;
                p->start();
            }
        }
    }
}

int SDAMPConnectionManager::sendAllPaths(SDAMPFrame *frame)
{
    std::vector<SDAMPFrame *> vec;
    vec.push_back(frame);
    SCIONPacket *packet = mProtocol->createPacket(vec);
    int res = 0;
    for (size_t i = 0; i < mPaths.size(); i++)
        res |= mPaths[i]->send(packet, mSendSocket);
    return res;
}

int SDAMPConnectionManager::handlePacket(SCIONPacket *packet)
{
    bool found = false;
    int index;
    SDAMPPacket *sp = (SDAMPPacket *)(packet->payload);
    for (size_t i = 0; i < mPaths.size(); i++) {
        if (sp->header.flags & SDAMP_NEW_PATH) {
#ifdef SIMULATOR
            if (mPaths[i]->isSamePath(packet->header.path, packet->header.pathLen)) {
#else
            if (mPaths[i]->usesSameInterfaces(sp->interfaces, sp->interfaceCount)) {
#endif
                found = true;
                index = i;
                mPaths[i]->setRawPath(packet->header.path, packet->header.pathLen);
                break;
            }
        } else if (mPaths[i]->isSamePath(packet->header.path, packet->header.pathLen)) {
            found = true;
            index = i;
            break;
        }
    }
    if (!found) {
        SCIONAddr saddr;
        saddr.isd_ad = ntohl(*(uint32_t *)(packet->header.srcAddr));
        saddr.host.addrLen = SCION_HOST_ADDR_LEN;
        memcpy(&(saddr.host.addr), packet->header.srcAddr + SCION_HOST_OFFSET, SCION_HOST_ADDR_LEN);

        SDAMPPath *p = new SDAMPPath(this, mLocalAddr, saddr, packet->header.path, packet->header.pathLen);
        p->setFirstHop(SCION_HOST_ADDR_LEN, (uint8_t *)&(packet->firstHop));
        p->setInterfaces(sp->interfaces, sp->interfaceCount);
        mPaths.push_back(p);
        p->setIndex(mPaths.size() - 1);
        index = mPaths.size() - 1;
    }
    packet->pathIndex = index;
    if (sp->frameCount > 0)
        return ((SDAMPPath *)(mPaths[index]))->handleData(packet);
    return 0;
}

void SDAMPConnectionManager::handleAck(SCIONPacket *packet, size_t initCount, bool receiver)
{
    SDAMPPacket *sdampPacket = (SDAMPPacket *)(packet->payload);
    SDAMPAck &sdampAck = sdampPacket->ack;
    uint64_t packetNum = sdampAck.L + sdampAck.I;

    DEBUG("got some acks: L = %lu, I = %d, O = %d, V = %#x\n",
            sdampAck.L, sdampAck.I, sdampAck.O, sdampAck.V);
    std::set<uint64_t> ackNums;
    ackNums.insert(packetNum);
    uint64_t minAck = packetNum;
    for (int j = 0; j < 32; j++) {
        if ((sdampAck.V >> j) & 1) {
            uint64_t pn = sdampAck.L + sdampAck.O + j;
            DEBUG("includes ack for %lu\n", pn);
            ackNums.insert(pn);
            if (pn < minAck)
                minAck = pn;
        }
    }

    DEBUG("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
    pthread_mutex_lock(&mPacketMutex);
    pthread_mutex_lock(&mSentMutex);
    PacketList::iterator i = mSentPackets.begin();
    while (i != mSentPackets.end()) {
        SCIONPacket *p = *i;
        SDAMPPacket *sp = (SDAMPPacket *)(p->payload);
        SDAMPHeader &sh = sp->header;
        uint64_t pn = be64toh(sh.packetNum);
        bool found = ackNums.find(pn) != ackNums.end();
        if (found || pn < sdampAck.L) {
            if (pn != 0 && found && p->pathIndex != packet->pathIndex) {
                DEBUG("ack for previous send of packet %lu came late, discard\n",
                        be64toh(sh.packetNum));
                i++;
                continue;
            }
            if (found) {
                packet->sendTime = p->sendTime;
                DEBUG("got ack for packet %lu\n", pn);
                sdampPacket->header.packetNum = pn;
                handleAckOnPath(packet, pn == packetNum);
            } else if (pn != 0) {
                DEBUG("no longer care about packet %lu: min is %lu\n", pn, sdampAck.L);
                p->arrivalTime = packet->arrivalTime;
                sh.packetNum = be64toh(sh.packetNum);
                handleAckOnPath(p, false);
            }
            if (pn > 0 || (receiver || initCount == mPaths.size())) {
                ackNums.erase(pn);
                i = mSentPackets.erase(i);
                DEBUG("removed packet %lu from sent list\n", pn);
                destroySDAMPPacket(sp);
                destroySCIONPacket(p);
                if (ackNums.size() == 0)
                    break;
                continue;
            }
        } else {
            if (p->pathIndex == packet->pathIndex && pn < minAck) {
                DEBUG("out of order ack: packet %lu possibly dropped\n", pn);
                handleDupAck(p->pathIndex);
                sp->skipCount++;
                if (sp->skipCount >= SDAMP_FR_THRESHOLD) {
                    i = mSentPackets.erase(i);
                    pthread_mutex_lock(&mRetryMutex);
                    for (size_t j = 0; j < sp->frameCount; j++) {
                        sp->frames[j]->retryAttempts++;
                        mRetryFrames->push(sp->frames[j]);
                        DEBUG("frame offset %lu pushed into retry list\n", sp->frames[j]->offset);
                    }
                    ((SDAMPPath *)(mPaths[p->pathIndex]))->addLoss(be64toh(sp->header.packetNum));
                    ((SDAMPPath *)(mPaths[p->pathIndex]))->addRetransmit();
                    destroySDAMPPacket(sp);
                    destroySCIONPacket(p);
                    pthread_mutex_unlock(&mRetryMutex);
                    pthread_cond_broadcast(&mPacketCond);
                    continue;
                }
            }
        }
        i++;
    }
    pthread_mutex_unlock(&mSentMutex);
    pthread_mutex_unlock(&mPacketMutex);
    pthread_cond_broadcast(&mSentCond);
}

int SDAMPConnectionManager::handleAckOnPath(SCIONPacket *packet, bool rttSample)
{
    SDAMPPacket *sp = (SDAMPPacket *)(packet->payload);
    if (sp->header.packetNum == 0) {
        DEBUG("bringing path %d back up with ack\n", packet->pathIndex);
        mPaths[packet->pathIndex]->setUp();
        int used = 0;
        for (size_t i = 0; i < mPaths.size(); i++) {
            if (mPaths[i]->isUsed())
                used++;
        }
        if (used >= MAX_USED_PATHS)
            mPaths[packet->pathIndex]->setUsed(false);
        else
            mPaths[packet->pathIndex]->setUsed(true);
        pthread_cond_broadcast(&mPacketCond);
    }
    return ((SDAMPPath *)(mPaths[packet->pathIndex]))->handleAck(packet, rttSample);
}

void SDAMPConnectionManager::handleDupAck(int index)
{
    ((SDAMPPath *)(mPaths[index]))->handleDupAck();
}

void SDAMPConnectionManager::handleProbeAck(SCIONPacket *packet)
{
    pthread_mutex_lock(&mMutex);
    for (size_t i = 0; i < mPaths.size(); i++) {
        if (mPaths[i]->isSamePath(packet->header.path, packet->header.pathLen)) {
            DEBUG("path %lu back up from probe\n", i);
            mPaths[i]->setUp();
            pthread_cond_broadcast(&mPacketCond);
            int used = 0;
            for (size_t j = 0; j < mPaths.size(); j++) {
                if (mPaths[j]->isUsed())
                    used++;
            }
            if (used < MAX_USED_PATHS) {
                DEBUG("set active\n");
                mPaths[i]->setUsed(true);
                pthread_cond_broadcast(&mPacketCond);
            }
        }
    }
    pthread_mutex_unlock(&mMutex);
}

void SDAMPConnectionManager::handleTimeout()
{
    struct timeval current;
    gettimeofday(&current, NULL);
    bool lost[mPaths.size()];
    memset(lost, 0, sizeof(lost));
    int timeout[mPaths.size()];
    memset(timeout, 0, sizeof(timeout));
    for (size_t i = 0; i < mPaths.size(); i++)
        timeout[i] = mPaths[i]->didTimeout(&current);

    pthread_mutex_lock(&mPacketMutex);
    pthread_mutex_lock(&mSentMutex);
    PacketList::iterator i = mSentPackets.begin();
    while (i != mSentPackets.end()) {
        int index = (*i)->pathIndex;
        SDAMPPacket *sp = (SDAMPPacket *)((*i)->payload);
        // Special case for packet 0
        if (sp->header.packetNum == 0) {
            size_t up = 0, down = 0;
            for (size_t j = 0; j < mPaths.size(); j++) {
                SDAMPPath *p = (SDAMPPath *)(mPaths[j]);
                if (p->isUp()) {
                    up++;
                } else if (p->didTimeout(&current)) {
                    DEBUG("path %lu timed out on packet 0\n", j);
                    p->setUsed(false);
                    p->addLoss(0);
                    down++;
                }
            }
            if (up + down == mPaths.size())
                i = mSentPackets.erase(i);
            else
                i++;
            continue;
        }
        if (timeout[index] > 0 ||
                sp->skipCount >= SDAMP_FR_THRESHOLD) {
            DEBUG("put packet %ld (path %d) in retransmit list (%d dups, timeout = %d)\n",
                    be64toh(sp->header.packetNum), index, sp->skipCount, timeout[index]);
            SCIONPacket *p = *i;
            i = mSentPackets.erase(i);
            sp->skipCount = 0;
            sp->retryAttempts++;
            pthread_mutex_lock(&mRetryMutex);
            for (size_t j = 0; j < sp->frameCount; j++) {
                sp->frames[j]->retryAttempts++;
                mRetryFrames->push(sp->frames[j]);
                DEBUG("frame offset %lu pushed into retry list\n", sp->frames[j]->offset);
            }
            destroySDAMPPacket(sp);
            destroySCIONPacket(p);
            pthread_mutex_unlock(&mRetryMutex);
            pthread_cond_broadcast(&mPacketCond);
            lost[index] = true;
            ((SDAMPPath *)(mPaths[index]))->addLoss(be64toh(sp->header.packetNum));
        } else {
            i++;
        }
    }
    pthread_mutex_unlock(&mSentMutex);
    pthread_mutex_unlock(&mPacketMutex);
    for (size_t j = 0; j < mPaths.size(); j++) {
        if (timeout[j] > 0) {
            DEBUG("%ld.%06ld: path %lu timed out\n", current.tv_sec, current.tv_usec, j);
            mPaths[j]->handleTimeout(&current);
            if (!mPaths[j]->isUp()) {
                DEBUG("path %lu is down: disable\n", j);
                mPaths[j]->setUsed(false);
                for (size_t k = 0; k < mPaths.size(); k++) {
                    if (!mPaths[k]->isUsed() && mPaths[k]->isUp()) {
                        DEBUG("use backup path %lu\n", k);
                        mPaths[k]->setUsed(true);
                        break;
                    }
                }
            }
        }
        if (lost[j]) {
            ((SDAMPPath *)(mPaths[j]))->addRetransmit();
        }
    }
}

int SDAMPConnectionManager::maxFrameSize()
{
    // TODO: Calculate based on path MTUs
    return SDAMP_FRAME_SIZE;
}

void SDAMPConnectionManager::getStats(SCIONStats *stats)
{
    for (size_t i = 0; i < mPaths.size(); i++)
        mPaths[i]->getStats(stats);
}

Path * SDAMPConnectionManager::createPath(SCIONAddr &dstAddr, uint8_t *rawPath, int pathLen)
{
    return new SDAMPPath(this, mLocalAddr, dstAddr, rawPath, pathLen);
}

SCIONPacket * SDAMPConnectionManager::maximizeBandwidth(int index, int bps, int rtt, double loss)
{
    pthread_mutex_lock(&mPacketMutex);
    sleepIfUnused(index);
    SDAMPFrame *frame = NULL;
    std::vector<SDAMPFrame *> vec;
    uint32_t deadline = 0;
    size_t available = mPaths[index]->getPayloadLen(false);
    while (vec.empty()) {
        if (!mRunning[index]) {
            pthread_mutex_unlock(&mPacketMutex);
            return NULL;
        }

        DEBUG("path %d: requesting packet\n", index);
        pthread_mutex_lock(&mRetryMutex);
        while (!mRetryFrames->empty()) {
            frame = mRetryFrames->top();
            if (available < frame->size + 12) {
                DEBUG("retry frame too big\n");
                break;
            }
            if (deadline > 0 && frame->deadline != deadline) {
                DEBUG("different deadlines\n");
                break;
            }
            mRetryFrames->pop();
            vec.push_back(frame);
            if (deadline == 0)
                deadline = frame->deadline;
            available -= frame->size + 12;
            DEBUG("retry frame %lu\n", frame->offset);
        }
        pthread_mutex_unlock(&mRetryMutex);

        pthread_mutex_lock(&mFreshMutex);
        while (!mFreshFrames->empty()) {
            frame = mFreshFrames->top();
            if (available < frame->size + 12) {
                DEBUG("fresh frame too big\n");
                break;
            }
            if (deadline > 0 && frame->deadline != deadline) {
                DEBUG("different deadlines\n");
                break;
            }
            mFreshFrames->pop();
            vec.push_back(frame);
            if (deadline == 0)
                deadline = frame->deadline;
            available -= frame->size + 12;
            DEBUG("fresh packet %lu\n", frame->offset);
        }
        pthread_mutex_unlock(&mFreshMutex);

        if (vec.empty())
            pthread_cond_wait(&mPacketCond, &mPacketMutex);
        DEBUG("path %d woken up\n", index);
    }
    pthread_mutex_unlock(&mPacketMutex);
    SCIONPacket *p = mProtocol->createPacket(vec);
    DEBUG("send packet\n");
    return p;
}

SCIONPacket * SDAMPConnectionManager::requestPacket(int index, int bps, int rtt, double loss)
{
    switch (mMetric) {
        case SDAMP_METRIC_BANDWIDTH:
            return maximizeBandwidth(index, bps, rtt, loss);
        case SDAMP_METRIC_LATENCY:
        case SDAMP_METRIC_DEADLINE:
        default:
            return NULL;
    }
}

// SSP

SSPConnectionManager::SSPConnectionManager(std::vector<SCIONAddr> &addrs, int sock)
    : SDAMPConnectionManager(addrs, sock)
{
}

SSPConnectionManager::SSPConnectionManager(std::vector<SCIONAddr> &addrs, int sock, SSPProtocol *protocol)
    : SDAMPConnectionManager(addrs, sock, protocol)
{
    delete mFreshFrames;
    mFreshFrames = NULL;
    delete mRetryFrames;
    mRetryFrames = NULL;
    for (size_t i = 0; i < mPaths.size(); i++)
        delete mPaths[i];
    mPaths.clear();

    mFreshBuffer = new RingBuffer(SDAMP_DEFAULT_WINDOW_SIZE);
    mRetryPackets = new PriorityQueue<SCIONPacket *>(compareOffset);
    mProtocol = protocol;
    getPaths();
}

SSPConnectionManager::~SSPConnectionManager()
{
}

Path * SSPConnectionManager::createPath(SCIONAddr &dstAddr, uint8_t *rawPath, int pathLen)
{
    return new SSPPath(this, mLocalAddr, dstAddr, rawPath, pathLen);
}

void SSPConnectionManager::waitForSendBuffer(int len, int windowSize)
{
    while (totalQueuedSize() + len > windowSize) {
        pthread_mutex_lock(&mSentMutex);
        DEBUG("%lu packets in sent list, %lu in retry list, %lu in fresh list\n",
                mSentPackets.size(), mRetryPackets->size(), mFreshBuffer->size());
        pthread_cond_wait(&mSentCond, &mSentMutex);
        pthread_mutex_unlock(&mSentMutex);
    }
}

int SSPConnectionManager::totalQueuedSize()
{
    PacketList::iterator i;
    std::vector<SCIONPacket *>::iterator j;
    int total = 0;
    pthread_mutex_lock(&mPacketMutex);
    pthread_mutex_lock(&mFreshMutex);
    total += mFreshBuffer->size();
    pthread_mutex_unlock(&mFreshMutex);
    pthread_mutex_lock(&mRetryMutex);
    for (j = mRetryPackets->begin(); j != mRetryPackets->end(); j++)
        total += ntohs((*j)->header.commonHeader.totalLen);
    pthread_mutex_unlock(&mRetryMutex);
    pthread_mutex_lock(&mSentMutex);
    for (i = mSentPackets.begin(); i != mSentPackets.end(); i++)
        total += ntohs((*i)->header.commonHeader.totalLen);
    pthread_mutex_unlock(&mSentMutex);
    pthread_mutex_unlock(&mPacketMutex);
    return total;
}

int SSPConnectionManager::sendAllPaths(uint8_t *buf, size_t len)
{
    size_t max = maxPayloadSize();
    if (max > len)
        max = len;
    uint8_t *data = (uint8_t *)malloc(max);
    memcpy(data, buf, max);
    SCIONPacket *packet = mProtocol->createPacket(data, max);
    int res = 0;
    for (size_t i = 0; i < mPaths.size(); i++)
        res |= mPaths[i]->send(packet, mSendSocket);
    if (max < len)
        queueData(buf + max, len - max);
    return res;
}

int SSPConnectionManager::queueData(uint8_t *buf, size_t len)
{
    pthread_mutex_lock(&mPacketMutex);
    pthread_mutex_lock(&mFreshMutex);
    mFreshBuffer->write(buf, len);
    pthread_mutex_unlock(&mFreshMutex);
    pthread_mutex_unlock(&mPacketMutex);
    pthread_cond_broadcast(&mPacketCond);
    return len;
}

void SSPConnectionManager::sendProbes(uint32_t probeNum, uint64_t flowID)
{
    bool refresh = false;
    for (size_t i = 0; i < mPaths.size(); i++) {
        SSPPath *p = (SSPPath *)mPaths[i];
        if (p->isUp() || !p->isValid())
            continue;
        DEBUG("send probe on path %lu\n", i);
        SCIONPacket packet;
        memset(&packet, 0, sizeof(packet));
        buildCommonHeader(packet.header.commonHeader, SCION_PROTO_SSP);
        SSPOutPacket sp;
        memset(&sp, 0, sizeof(sp));
        packet.payload = &sp;
        SSPHeader &sh = sp.header;
        sh.headerLen = sizeof(sh);
        sh.flowID = htobe64(flowID);
        sh.offset = htonl(probeNum);
        sh.flags |= SSP_PROBE;
        int ret = p->send(&packet, mSendSocket);
        if (ret) {
            DEBUG("terminate path %u\n", i);
            mRunning[i] = false;
            pthread_cond_broadcast(&mPacketCond);
            p->terminate();
            refresh = true;
        }
    }
    if (refresh) {
        // One or more paths down for long time
        DEBUG("get fresh paths\n");
        getPaths();
        for (size_t j = 0; j < mPaths.size(); j++) {
            SSPPath *p = (SSPPath *)mPaths[j];
            if (p->isValid() && !mRunning[j]) {
                mRunning[j] = true;
                p->start();
            }
        }
    }
}

int SSPConnectionManager::handlePacket(SCIONPacket *packet)
{
    bool found = false;
    int index;
    SSPInPacket *sp = (SSPInPacket *)(packet->payload);
    for (size_t i = 0; i < mPaths.size(); i++) {
        if (sp->interfaceCount > 0) {
#ifdef SIMULATOR
            if (mPaths[i]->isSamePath(packet->header.path, packet->header.pathLen)) {
#else
            if (mPaths[i]->usesSameInterfaces(sp->interfaces, sp->interfaceCount)) {
#endif
                found = true;
                index = i;
                mPaths[i]->setRawPath(packet->header.path, packet->header.pathLen);
                break;
            }
        } else if (mPaths[i]->isSamePath(packet->header.path, packet->header.pathLen)) {
            found = true;
            index = i;
            break;
        }
    }
    if (!found) {
        SCIONAddr saddr;
        saddr.isd_ad = ntohl(*(uint32_t *)(packet->header.srcAddr));
        saddr.host.addrLen = SCION_HOST_ADDR_LEN;
        memcpy(&(saddr.host.addr), packet->header.srcAddr + SCION_HOST_OFFSET, SCION_HOST_ADDR_LEN);

        SSPPath *p = new SSPPath(this, mLocalAddr, saddr, packet->header.path, packet->header.pathLen);
        p->setFirstHop(SCION_HOST_ADDR_LEN, (uint8_t *)&(packet->firstHop));
        p->setInterfaces(sp->interfaces, sp->interfaceCount);
        mPaths.push_back(p);
        p->setIndex(mPaths.size() - 1);
        index = mPaths.size() - 1;
    }
    packet->pathIndex = index;
    if (sp->len > 0)
        return ((SDAMPPath *)(mPaths[index]))->handleData(packet);
    return 0;
}

void SSPConnectionManager::handleAck(SCIONPacket *packet, size_t initCount, bool receiver)
{
    SSPAck *ack = (SSPAck *)(packet->payload);
    uint64_t offset = ack->L + ack->I;

    DEBUG("ack: %p\n", ack);
    DEBUG("got some acks: L = %lu, I = %d, O = %d, V = %#x\n",
            ack->L, ack->I, ack->O, ack->V);
    std::set<uint64_t> ackNums;
    ackNums.insert(offset);
    uint64_t minAck = offset;
    for (int j = 0; j < 32; j++) {
        if ((ack->V >> j) & 1) {
            uint64_t pn = ack->L + ack->O + j;
            DEBUG("includes ack for %lu\n", pn);
            ackNums.insert(pn);
            if (pn < minAck)
                minAck = pn;
        }
    }

    DEBUG("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
    pthread_mutex_lock(&mPacketMutex);
    pthread_mutex_lock(&mSentMutex);
    PacketList::iterator i = mSentPackets.begin();
    while (i != mSentPackets.end()) {
        SCIONPacket *p = *i;
        SSPOutPacket *sp = (SSPOutPacket *)(p->payload);
        SSPHeader &sh = sp->header;
        uint64_t pn = ntohl(sh.offset);
        bool found = ackNums.find(pn) != ackNums.end();
        if (found || pn < ack->L) {
            if (pn != 0 && found && p->pathIndex != packet->pathIndex) {
                DEBUG("ack for previous send of packet %lu came late, discard\n",
                        be64toh(sh.offset));
                i++;
                continue;
            }
            if (found) {
                packet->sendTime = p->sendTime;
                DEBUG("got ack for packet %lu\n", pn);
                handleAckOnPath(packet, pn == offset);
            } else if (pn != 0) {
                DEBUG("no longer care about packet %lu: min is %lu\n", pn, ack->L);
                p->arrivalTime = packet->arrivalTime;
                sh.offset = be64toh(sh.offset);
                handleAckOnPath(p, false);
            }
            if (pn > 0 || (receiver || initCount == mPaths.size())) {
                ackNums.erase(pn);
                i = mSentPackets.erase(i);
                DEBUG("removed packet %lu from sent list\n", pn);
                destroySSPOutPacket(sp);
                destroySCIONPacket(p);
                if (ackNums.empty())
                    break;
                continue;
            }
        } else {
            if (p->pathIndex == packet->pathIndex && pn < minAck) {
                DEBUG("out of order ack: packet %lu possibly dropped\n", pn);
                ((SSPPath *)(mPaths[p->pathIndex]))->handleDupAck();
                sp->skipCount++;
                if (sp->skipCount >= SDAMP_FR_THRESHOLD) {
                    i = mSentPackets.erase(i);
                    pthread_mutex_lock(&mRetryMutex);
                    mRetryPackets->push(p);
                    ((SSPPath *)(mPaths[p->pathIndex]))->addLoss(be64toh(sh.offset));
                    ((SSPPath *)(mPaths[p->pathIndex]))->addRetransmit();
                    destroySSPOutPacket(sp);
                    pthread_mutex_unlock(&mRetryMutex);
                    pthread_cond_broadcast(&mPacketCond);
                    continue;
                }
            }
        }
        i++;
    }
    pthread_mutex_unlock(&mSentMutex);
    pthread_mutex_unlock(&mPacketMutex);
    pthread_cond_broadcast(&mSentCond);
}

int SSPConnectionManager::handleAckOnPath(SCIONPacket *packet, bool rttSample)
{
    SSPAck *ack = (SSPAck *)(packet->payload);
    uint32_t offset = ack->L + ack->I;
    if (offset == 0) {
        DEBUG("bringing path %d back up with ack\n", packet->pathIndex);
        mPaths[packet->pathIndex]->setUp();
        int used = 0;
        for (size_t i = 0; i < mPaths.size(); i++) {
            if (mPaths[i]->isUsed())
                used++;
        }
        if (used >= MAX_USED_PATHS)
            mPaths[packet->pathIndex]->setUsed(false);
        else
            mPaths[packet->pathIndex]->setUsed(true);
        pthread_cond_broadcast(&mPacketCond);
    }
    return ((SSPPath *)(mPaths[packet->pathIndex]))->handleAck(packet, rttSample);
}

void SSPConnectionManager::handleTimeout()
{
    struct timeval current;
    gettimeofday(&current, NULL);
    bool lost[mPaths.size()];
    memset(lost, 0, sizeof(lost));
    int timeout[mPaths.size()];
    memset(timeout, 0, sizeof(timeout));
    for (size_t i = 0; i < mPaths.size(); i++)
        timeout[i] = mPaths[i]->didTimeout(&current);

    pthread_mutex_lock(&mPacketMutex);
    pthread_mutex_lock(&mSentMutex);
    PacketList::iterator i = mSentPackets.begin();
    while (i != mSentPackets.end()) {
        int index = (*i)->pathIndex;
        SSPOutPacket *sp = (SSPOutPacket *)((*i)->payload);
        // Special case for packet 0
        if (sp->header.offset == 0) {
            size_t up = 0, down = 0;
            for (size_t j = 0; j < mPaths.size(); j++) {
                SSPPath *p = (SSPPath *)(mPaths[j]);
                if (p->isUp()) {
                    up++;
                } else if (p->didTimeout(&current)) {
                    DEBUG("path %lu timed out on packet 0\n", j);
                    p->setUsed(false);
                    p->addLoss(0);
                    down++;
                }
            }
            if (up + down == mPaths.size())
                i = mSentPackets.erase(i);
            else
                i++;
            continue;
        }
        if (timeout[index] > 0 ||
                sp->skipCount >= SDAMP_FR_THRESHOLD) {
            DEBUG("put packet %ld (path %d) in retransmit list (%d dups, timeout = %d)\n",
                    ntohl(sp->header.offset), index, sp->skipCount, timeout[index]);
            SCIONPacket *p = *i;
            i = mSentPackets.erase(i);
            sp->skipCount = 0;
            pthread_mutex_lock(&mRetryMutex);
            mRetryPackets->push(p);
            pthread_mutex_unlock(&mRetryMutex);
            pthread_cond_broadcast(&mPacketCond);
            lost[index] = true;
            ((SSPPath *)(mPaths[index]))->addLoss(ntohl(sp->header.offset));
        } else {
            i++;
        }
    }
    pthread_mutex_unlock(&mSentMutex);
    pthread_mutex_unlock(&mPacketMutex);
    for (size_t j = 0; j < mPaths.size(); j++) {
        if (timeout[j] > 0) {
            DEBUG("%ld.%06ld: path %lu timed out\n", current.tv_sec, current.tv_usec, j);
            mPaths[j]->handleTimeout(&current);
            if (!mPaths[j]->isUp()) {
                DEBUG("path %lu is down: disable\n", j);
                mPaths[j]->setUsed(false);
                for (size_t k = 0; k < mPaths.size(); k++) {
                    if (!mPaths[k]->isUsed() && mPaths[k]->isUp()) {
                        DEBUG("use backup path %lu\n", k);
                        mPaths[k]->setUsed(true);
                        break;
                    }
                }
            }
        }
        if (lost[j]) {
            ((SSPPath *)(mPaths[j]))->addRetransmit();
        }
    }
}

void SSPConnectionManager::didSend(SCIONPacket *packet)
{
    SSPOutPacket *sp = (SSPOutPacket *)(packet->payload);
    if (sp->header.offset == 0) {
        if (mInitPacketQueued)
            return;
        else
            mInitPacketQueued = true;
    }
    pthread_mutex_lock(&mSentMutex);
    DEBUG("add packet %lu to sent list\n", be64toh(sp->header.offset));
    mSentPackets.push_back(packet);
    pthread_mutex_unlock(&mSentMutex);
}

SCIONPacket * SSPConnectionManager::maximizeBandwidth(int index, int bps, int rtt, double loss)
{
    pthread_mutex_lock(&mPacketMutex);
    sleepIfUnused(index);
    SCIONPacket *packet = NULL;
    size_t available = mPaths[index]->getPayloadLen(false);
    while (!packet) {
        if (!mRunning[index]) {
            pthread_mutex_unlock(&mPacketMutex);
            return NULL;
        }

        DEBUG("path %d: requesting packet\n", index);
        pthread_mutex_lock(&mRetryMutex);
        if (!mRetryPackets->empty()) {
            packet = mRetryPackets->top();
            mRetryPackets->pop();
            pthread_mutex_unlock(&mRetryMutex);
            pthread_mutex_unlock(&mPacketMutex);
            return packet;
        }
        pthread_mutex_unlock(&mRetryMutex);

        pthread_mutex_lock(&mFreshMutex);
        size_t fresh = mFreshBuffer->size();
        DEBUG("%d bytes queued to send\n", fresh);
        int len = fresh > available ? available : fresh;
        if (len > 0) {
            uint8_t *data = (uint8_t *)malloc(len);
            mFreshBuffer->read(data, len);
            packet = mProtocol->createPacket(data, len);
        }
        pthread_mutex_unlock(&mFreshMutex);

        if (!packet)
            pthread_cond_wait(&mPacketCond, &mPacketMutex);
    }
    pthread_mutex_unlock(&mPacketMutex);
    DEBUG("send packet\n");
    return packet;
}

SCIONPacket * SSPConnectionManager::requestPacket(int index, int bps, int rtt, double loss)
{
    switch (mMetric) {
        case SDAMP_METRIC_BANDWIDTH:
            return maximizeBandwidth(index, bps, rtt, loss);
        case SDAMP_METRIC_LATENCY:
        case SDAMP_METRIC_DEADLINE:
        default:
            return NULL;
    }
}

void SSPConnectionManager::abortSend(SCIONPacket *packet)
{
    pthread_mutex_lock(&mRetryMutex);
    mRetryPackets->push(packet);
    pthread_mutex_unlock(&mRetryMutex);
}

    /*
SCIONPacket * LatencyConnectionManager::requestPacket(int index, int bps, int rtt, double loss)
{
    return NULL;
    pthread_mutex_lock(&mPacketMutex);
    bool shouldPrime = sleepIfUnused(index);
    SCIONPacket *p = NULL;
    while (p == NULL) {
        DEBUG("path %d: requesting packet\n", index);
        while (mRunning && !shouldPrime) {
            struct timeval current;
            gettimeofday(&current, NULL);
            if (mPaths[index]->getIdleTime(&current) > SDAMP_PRIME_INTERVAL) {
                DEBUG("path %d: waited long enough\n", index);
                break;
            }
            size_t minETA = ~0;
            size_t minIndex = -1;
            size_t currentETA;
            for (size_t i = 0; i < mPaths.size(); i++) {
                size_t eta = mPaths[i]->getETA(NULL);
                DEBUG("ETA %lu on path %lu\n", eta, i);
                if (eta < minETA) {
                    minIndex = i;
                    minETA = eta;
                }
                if (i == (size_t)index)
                    currentETA = eta;
            }
            DEBUG("path %d: min eta = %ld, my eta = %ld\n", index, minETA, currentETA);
            if ((size_t)index == minIndex)
                break;
            struct timespec t;
            clock_gettime(CLOCK_REALTIME, &t);
            long nsec = t.tv_nsec + (currentETA - minETA) * 1000;
            if (nsec >= 1000000000) {
                nsec -= 1000000000;
                t.tv_sec++;
            }
            t.tv_nsec = nsec;
            pthread_cond_timedwait(&mPacketCond, &mPacketMutex, &t);
        }

        if (!mRunning) {
            pthread_mutex_unlock(&mPacketMutex);
            return NULL;
        }

        pthread_mutex_lock(&mRetryMutex);
        if (!mRetryPackets.empty()) {
            p = mRetryPackets.top();
            mRetryPackets.pop();
            pthread_mutex_unlock(&mRetryMutex);
            break;
        }
        pthread_mutex_unlock(&mRetryMutex);

        pthread_mutex_lock(&mFreshMutex);
        if (!mFreshPackets.empty()) {
            p = mFreshPackets.top();
            mFreshPackets.pop();
            DEBUG("path %d: send fresh packet\n", index);
            pthread_mutex_unlock(&mFreshMutex);
            break;
        }
        pthread_mutex_unlock(&mFreshMutex);

        pthread_cond_wait(&mPacketCond, &mPacketMutex);
        DEBUG("path %d woken up\n", index);
    }
    pthread_mutex_unlock(&mPacketMutex);
    pthread_cond_signal(&mPacketCond);
    DEBUG("path %d: packet ready\n", index);
    return p;
}

SCIONPacket * DeadlineConnectionManager::requestPacket(int index, int bps, int rtt, double loss)
{
    return NULL;
    pthread_mutex_lock(&mPacketMutex);
    bool shouldPrime = sleepIfUnused(index);
    SCIONPacket *p = NULL;
    while (p == NULL) {
        if (!mRunning) {
            pthread_mutex_unlock(&mPacketMutex);
            return NULL;
        }
        struct timeval current;
        gettimeofday(&current, NULL);
        if (mPaths[index]->getIdleTime(&current) > SDAMP_PRIME_INTERVAL) {
            DEBUG("path %d: waited long enough\n", index);
            shouldPrime = true;
        }

        DEBUG("path %d: requesting packet (rtt = %d)\n", index, rtt);
        pthread_mutex_lock(&mRetryMutex);
        if (!mRetryPackets.empty()) {
            p = mRetryPackets.top();
            SDAMPPacket *sp = (SDAMPPacket *)(p->payload);
            if (rtt <= (int)sp->deadline || shouldPrime) {
                DEBUG("path %d: send retry packet\n", index);
                mRetryPackets.pop();
                pthread_mutex_unlock(&mRetryMutex);
                break;
            }
        }
        pthread_mutex_unlock(&mRetryMutex);
        p = NULL;

        pthread_mutex_lock(&mFreshMutex);
        if (!mFreshPackets.empty()) {
            p = mFreshPackets.top();
            SDAMPPacket *sp = (SDAMPPacket *)(p->payload);
            if (rtt <= (int)sp->deadline || shouldPrime) {
                DEBUG("path %d: send fresh packet\n", index);
                mFreshPackets.pop();
                pthread_mutex_unlock(&mFreshMutex);
                break;
            }
        }
        pthread_mutex_unlock(&mFreshMutex);
        p = NULL;

        DEBUG("no packets with appropriate deadline\n");
        pthread_cond_wait(&mPacketCond, &mPacketMutex);
        DEBUG("path %d woken up\n", index);
    }
    pthread_mutex_unlock(&mPacketMutex);
    DEBUG("path %d ready to send packet\n", index);
    return p;
}
    */
