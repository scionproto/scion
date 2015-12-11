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

        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        memcpy(&sa.sin_addr, mLocalAddr.host.addr, mLocalAddr.host.addrLen);
        bind(mSendSocket, (struct sockaddr *)&sa, sizeof(sa));
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
                if (pathLen + offset > buflen)
                    break;
                int interfaceOffset = offset + 1 + pathLen + SCION_HOST_ADDR_LEN + 2 + 2;
                int interfaceCount = *(buf + interfaceOffset);
                if (interfaceOffset + 1 + interfaceCount * SCION_IF_SIZE > buflen)
                    break;
                for (size_t j = 0; j < mPaths.size(); j++) {
                    if (mPaths[j]->isSamePath(buf + offset + 1, pathLen)) {
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
                offset = interfaceOffset + 1 + interfaceCount * SCION_IF_SIZE;
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
    mRunning = true;
    mFreshPackets = new OrderedList<SCIONPacket *>(NULL, destroySDAMPPacketFull);
    mRetryPackets = new OrderedList<SCIONPacket *>(comparePacketNumNested, destroySDAMPPacketFull);
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
    pthread_cond_init(&mPathCond, &ca);
}

SDAMPConnectionManager::~SDAMPConnectionManager()
{
    mRunning = false;
    pthread_cond_broadcast(&mPacketCond);
    pthread_cond_broadcast(&mPathCond);
    pthread_join(mWorker, NULL);
    PacketList::iterator i;
    for (i = mSentPackets.begin(); i != mSentPackets.end(); i++) {
        SCIONPacket *p = *i;
        SDAMPPacket *sp = (SDAMPPacket *)(p->payload);
        destroySDAMPPacket(sp);
        destroySCIONPacket(p);
    }
    mFreshPackets->clean();
    delete mFreshPackets;
    mRetryPackets->clean();
    delete mRetryPackets;
    while (!mPaths.empty()) {
        SDAMPPath *p = (SDAMPPath *)(mPaths.back());
        mPaths.pop_back();
        delete p;
    }
    pthread_mutex_destroy(&mMutex);
    pthread_mutex_destroy(&mSentMutex);
    pthread_cond_destroy(&mSentCond);
    pthread_mutex_destroy(&mFreshMutex);
    pthread_mutex_destroy(&mRetryMutex);
    pthread_mutex_destroy(&mPacketMutex);
    pthread_cond_destroy(&mPacketCond);
    pthread_cond_destroy(&mPathCond);
}

void SDAMPConnectionManager::setRemoteWindow(uint32_t window)
{
    for (size_t i = 0; i < mPaths.size(); i++)
        ((SDAMPPath*)mPaths[i])->setRemoteWindow(window);
}

void SDAMPConnectionManager::waitForSendBuffer(int len, int windowSize)
{
    while (totalQueuedSize() + len > windowSize) {
        pthread_mutex_lock(&mSentMutex);
        DEBUG("%lu packets in sent list, %lu in retry list, %lu in fresh list\n",
                mSentPackets.size(), mRetryPackets->size(), mFreshPackets->size());
        pthread_cond_wait(&mSentCond, &mSentMutex);
        pthread_mutex_unlock(&mSentMutex);
    }
}

int SDAMPConnectionManager::totalQueuedSize()
{
    int total = 0;

    PacketList::iterator i;
    pthread_mutex_lock(&mFreshMutex);
    for (i = mFreshPackets->begin(); i != mFreshPackets->end(); i++) {
        SDAMPPacket *sp = (SDAMPPacket *)((*i)->payload);
        total += sizeof(SCIONPacket) + sizeof(SDAMPPacket) + sp->len;
    }
    pthread_mutex_unlock(&mFreshMutex);

    pthread_mutex_lock(&mRetryMutex);
    for (i = mRetryPackets->begin(); i != mRetryPackets->end(); i++) {
        SDAMPPacket *sp = (SDAMPPacket *)((*i)->payload);
        total += sizeof(SCIONPacket) + sizeof(SDAMPPacket) + sp->len;
    }
    pthread_mutex_unlock(&mRetryMutex);

    pthread_mutex_lock(&mSentMutex);
    for (i = mSentPackets.begin(); i != mSentPackets.end(); i++) {
        SDAMPPacket *sp = (SDAMPPacket *)((*i)->payload);
        total += sizeof(SCIONPacket) + sizeof(SDAMPPacket) + sp->len;
    }
    pthread_mutex_unlock(&mSentMutex);

    return total;
}

void SDAMPConnectionManager::queuePacket(SCIONPacket *packet)
{
    pthread_mutex_lock(&mFreshMutex);
    mFreshPackets->push(packet);
    pthread_mutex_unlock(&mFreshMutex);
    pthread_cond_broadcast(&mPacketCond);
}

bool SDAMPConnectionManager::sleepIfUnused(int index)
{
    struct timeval t;
    gettimeofday(&t, NULL);
    while (!mPaths[index]->isUsed()) {
        /*
        if (mPaths[index]->isUp() &&
                mPaths[index]->getIdleTime(&t) >= SDAMP_PRIME_INTERVAL) {
            DEBUG("Prime path %d\n", index);
            return true;
        }
        */
        DEBUG("path %d: wait until active\n", index);
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
    DEBUG("add packet %lu (%p) to sent list\n", be64toh(sp->header.packetNum), packet->payload);
    mSentPackets.push_back(packet);
    pthread_mutex_unlock(&mSentMutex);
}

void SDAMPConnectionManager::abortSend(SCIONPacket *packet)
{
    pthread_mutex_lock(&mRetryMutex);
    mRetryPackets->push(packet);
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
                refresh = true;
            }
        }
    }
    if (refresh) {
        // One or more paths down for long time
        DEBUG("get fresh paths\n");
        getPaths();
    }
}

int SDAMPConnectionManager::sendAllPaths(SCIONPacket *packet)
{
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
    if (sp->len > 0)
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
    for (int j = 0; j < 32; j++) {
        if ((sdampAck.V >> j) & 1) {
            uint64_t pn = sdampAck.L + sdampAck.O + j;
            DEBUG("includes ack for %lu\n", pn);
            ackNums.insert(pn);
        }
    }

    DEBUG("received ack for packet %lu (path %d)\n", packetNum, packet->pathIndex);
    pthread_mutex_lock(&mSentMutex);
    PacketList::iterator i = mSentPackets.begin();
    while (i != mSentPackets.end()) {
        SCIONPacket *p = *i;
        SDAMPPacket *sp = (SDAMPPacket *)(p->payload);
        SDAMPHeader &sh = sp->header;
        uint64_t pn = be64toh(sh.packetNum);
        DEBUG("in sent list: packet %lu (path %d)\n", pn, p->pathIndex);
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
                DEBUG("removed packet %lu (%p) from sent list\n", pn, sp);
                destroySDAMPPacket(sp);
                destroySCIONPacket(p);
                if (ackNums.size() == 0)
                    break;
                continue;
            }
        } else {
            if (p->pathIndex == packet->pathIndex && pn < packetNum) {
                DEBUG("out of order ack: packet %lu possibly dropped\n", pn);
                handleDupAck(p->pathIndex);
                sp->skipCount++;
            }
        }
        i++;
    }
    pthread_mutex_unlock(&mSentMutex);
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
    }
    pthread_cond_broadcast(&mPathCond);
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
            if (!mPaths[i]->isUp()) {
                DEBUG("path %lu back up from probe\n", i);
                mPaths[i]->setUp();
                pthread_cond_broadcast(&mPathCond);
                int used = 0;
                for (size_t j = 0; j < mPaths.size(); j++) {
                    if (mPaths[j]->isUsed())
                        used++;
                }
                if (used < MAX_USED_PATHS) {
                    DEBUG("set active\n");
                    mPaths[i]->setUsed(true);
                    pthread_cond_broadcast(&mPathCond);
                }
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

    std::vector<SCIONPacket *> retries;
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
            retries.push_back(p);
            lost[index] = true;
            ((SDAMPPath *)(mPaths[index]))->addLoss(be64toh(sp->header.packetNum));
        } else {
            i++;
        }
    }
    pthread_mutex_unlock(&mSentMutex);
    pthread_mutex_lock(&mRetryMutex);
    for (size_t j = 0; j < retries.size(); j++)
        mRetryPackets->push(retries[j]);
    pthread_mutex_unlock(&mRetryMutex);
    if (!retries.empty())
        pthread_cond_broadcast(&mPacketCond);
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
            pthread_cond_broadcast(&mPathCond);
        }
        if (lost[j]) {
            ((SDAMPPath *)(mPaths[j]))->addRetransmit();
        }
    }
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

void SDAMPConnectionManager::startScheduler()
{
    getPaths();
    pthread_create(&mWorker, NULL, &SDAMPConnectionManager::workerHelper, this);
}

void * SDAMPConnectionManager::workerHelper(void *arg)
{
    SDAMPConnectionManager *manager = (SDAMPConnectionManager *)arg;
    manager->schedule();
    return NULL;
}

bool SDAMPConnectionManager::readyToSend()
{
    bool ready = false;
    pthread_mutex_lock(&mRetryMutex);
    ready = !mRetryPackets->empty();
    pthread_mutex_unlock(&mRetryMutex);
    if (ready)
        return ready;
    pthread_mutex_lock(&mFreshMutex);
    ready = !mFreshPackets->empty();
    pthread_mutex_unlock(&mFreshMutex);
    return ready;
}

void SDAMPConnectionManager::schedule()
{
    while (mRunning) {
        pthread_mutex_lock(&mPacketMutex);
        while (!readyToSend()) {
            pthread_cond_wait(&mPacketCond, &mPacketMutex);
            if (!mRunning)
                return;
        }

        DEBUG("get path to send stuff\n");
        Path *p = NULL;
        while (!(p = pathToSend())) {
            pthread_cond_wait(&mPathCond, &mPacketMutex);
            if (!mRunning)
                return;
        }
        pthread_mutex_unlock(&mPacketMutex);
        SCIONPacket *packet = nextPacket();
        if (!packet) {
            DEBUG("no packet to send\n");
            continue;
        }
        DEBUG("send packet %lu on path %d\n",
                be64toh(((L4Packet *)(packet->payload))->number()),
                p->getIndex());
        p->send(packet, mSendSocket);
    }
}

SCIONPacket * SDAMPConnectionManager::nextPacket()
{
    SCIONPacket *packet = NULL;
    pthread_mutex_lock(&mPacketMutex);
    pthread_mutex_lock(&mRetryMutex);
    if (!mRetryPackets->empty())
        packet = mRetryPackets->pop();
    pthread_mutex_unlock(&mRetryMutex);
    if (!packet) {
        pthread_mutex_lock(&mFreshMutex);
        if (!mFreshPackets->empty())
            packet = mFreshPackets->pop();
        pthread_mutex_unlock(&mFreshMutex);
    }
    pthread_mutex_unlock(&mPacketMutex);
    return packet;
}

Path * SDAMPConnectionManager::pathToSend()
{
    for (size_t i = 0; i < mPaths.size(); i++) {
        Path *p = mPaths[i];
        if (!p->isUp() || !p->isUsed()) {
            DEBUG("path %lu: up(%d), used(%d)\n", i, p->isUp(), p->isUsed());
            continue;
        }
        int ready = p->timeUntilReady();
        DEBUG("path %lu: ready = %d\n", i, ready);
        if (ready == 0)
            return p;
    }
    return NULL;
}

SCIONPacket * SDAMPConnectionManager::maximizeBandwidth(int index, int bps, int rtt, double loss)
{
    pthread_mutex_lock(&mPacketMutex);
    sleepIfUnused(index);
    SCIONPacket *packet = NULL;
    while (!packet) {
        if (!mRunning) {
            pthread_mutex_unlock(&mPacketMutex);
            return NULL;
        }

        DEBUG("path %d: requesting packet\n", index);
        pthread_mutex_lock(&mRetryMutex);
        if (!mRetryPackets->empty()) {
            packet = mRetryPackets->pop();
            pthread_mutex_unlock(&mRetryMutex);
            pthread_mutex_unlock(&mPacketMutex);
            return packet;
        }
        pthread_mutex_unlock(&mRetryMutex);

        pthread_mutex_lock(&mFreshMutex);
        if (!mFreshPackets->empty()) {
            packet = mFreshPackets->pop();
            pthread_mutex_unlock(&mFreshMutex);
            pthread_mutex_unlock(&mPacketMutex);
            return packet;
        }
        pthread_mutex_unlock(&mFreshMutex);

        if (!packet) {
            DEBUG("wait for data to send\n");
            pthread_cond_wait(&mPacketCond, &mPacketMutex);
        }
    }
    pthread_mutex_unlock(&mPacketMutex);
    DEBUG("path %d: send packet\n", index);
    return packet;
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
    delete mRetryPackets;
    mRetryPackets = NULL;
    for (size_t i = 0; i < mPaths.size(); i++)
        delete mPaths[i];
    mPaths.clear();

    mRetryPackets = new OrderedList<SCIONPacket *>(compareOffsetNested, destroySSPPacketFull);
}

SSPConnectionManager::~SSPConnectionManager()
{
    mRetryPackets->clean();
    delete mRetryPackets;
}

Path * SSPConnectionManager::createPath(SCIONAddr &dstAddr, uint8_t *rawPath, int pathLen)
{
    return new SSPPath(this, mLocalAddr, dstAddr, rawPath, pathLen);
}

void SSPConnectionManager::waitForSendBuffer(int len, int windowSize)
{
    while (totalQueuedSize() + len > windowSize) {
        pthread_mutex_lock(&mSentMutex);
        DEBUG("%lu packets in sent list, %lu in retry list, %lu fresh packets\n",
                mSentPackets.size(), mRetryPackets->size(), mFreshPackets->size());
        pthread_cond_wait(&mSentCond, &mSentMutex);
        pthread_mutex_unlock(&mSentMutex);
    }
}

int SSPConnectionManager::totalQueuedSize()
{
    PacketList::iterator i;
    int total = 0;
    pthread_mutex_lock(&mFreshMutex);
    for (i = mFreshPackets->begin(); i != mFreshPackets->end(); i++)
        total += ntohs((*i)->header.commonHeader.totalLen);
    pthread_mutex_unlock(&mFreshMutex);
    pthread_mutex_lock(&mRetryMutex);
    for (i = mRetryPackets->begin(); i != mRetryPackets->end(); i++)
        total += ntohs((*i)->header.commonHeader.totalLen);
    pthread_mutex_unlock(&mRetryMutex);
    pthread_mutex_lock(&mSentMutex);
    for (i = mSentPackets.begin(); i != mSentPackets.end(); i++)
        total += ntohs((*i)->header.commonHeader.totalLen);
    pthread_mutex_unlock(&mSentMutex);
    return total;
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
        SSPPacket sp;
        packet.payload = &sp;
        SSPHeader &sh = sp.header;
        sh.headerLen = sizeof(sh);
        sh.flowID = htobe64(flowID);
        sh.offset = htobe64((uint64_t)probeNum);
        sh.flags |= SSP_PROBE;
        int ret = p->send(&packet, mSendSocket);
        if (ret) {
            DEBUG("terminate path %lu\n", i);
            refresh = true;
        }
    }
    if (refresh) {
        // One or more paths down for long time
        DEBUG("get fresh paths\n");
        getPaths();
    }
}

int SSPConnectionManager::handlePacket(SCIONPacket *packet)
{
    bool found = false;
    int index;
    SSPPacket *sp = (SSPPacket *)(packet->payload);
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
    SSPPacket *spacket = (SSPPacket *)(packet->payload);
    SSPAck &ack = spacket->ack;
    uint8_t mark = spacket->header.mark;
    bool full = spacket->header.flags & SSP_FULL;
    uint64_t offset = ack.L + ack.I;

    DEBUG("got some acks on path %d: L = %lu, I = %d, O = %d, V = %#x, full? %d\n",
            packet->pathIndex, ack.L, ack.I, ack.O, ack.V, full);
    std::set<uint64_t> ackNums;
    ackNums.insert(offset);
    for (int j = 0; j < 32; j++) {
        if ((ack.V >> j) & 1) {
            uint64_t pn = ack.L + ack.O + j;
            DEBUG("includes ack for %lu\n", pn);
            ackNums.insert(pn);
        }
    }

    std::vector<SCIONPacket *> retries;
    pthread_mutex_lock(&mSentMutex);
    PacketList::iterator i = mSentPackets.begin();
    while (i != mSentPackets.end()) {
        SCIONPacket *p = *i;
        SSPPacket *sp = (SSPPacket *)(p->payload);
        SSPHeader &sh = sp->header;
        uint64_t pn = be64toh(sh.offset);
        bool found = ackNums.find(pn) != ackNums.end();
        if (found || pn < ack.L) {
            if (pn != 0 && found && p->pathIndex != packet->pathIndex) {
                DEBUG("ack for previous send of packet %u came late, discard\n",
                        be64toh(sh.offset));
                i++;
                continue;
            }
            if (found) {
                packet->sendTime = p->sendTime;
                DEBUG("got ack for packet %u (path %d), mark: %d|%d\n",
                        pn, packet->pathIndex, sh.mark, mark);
                handleAckOnPath(packet, pn == offset && mark == sh.mark);
            } else if (pn != 0) {
                DEBUG("no longer care about packet %u (path %d): min is %lu\n",
                        pn, p->pathIndex, ack.L);
                p->arrivalTime = packet->arrivalTime;
                sp->ack.L = pn;
                handleAckOnPath(p, false);
            }
            if (pn > 0 || (receiver || initCount == mPaths.size())) {
                ackNums.erase(pn);
                i = mSentPackets.erase(i);
                DEBUG("removed packet %u from sent list\n", pn);
                destroySSPPacket(sp);
                destroySCIONPacket(p);
                if (ackNums.empty())
                    break;
                continue;
            }
        } else {
            if (p->pathIndex == packet->pathIndex && pn < offset) {
                DEBUG("out of order ack: packet %u possibly dropped\n", pn);
                ((SSPPath *)(mPaths[p->pathIndex]))->handleDupAck();
                sp->skipCount++;
                if (sp->skipCount >= SDAMP_FR_THRESHOLD) {
                    DEBUG("packet %u dropped, add to resend list\n", pn);
                    i = mSentPackets.erase(i);
                    sp->skipCount = 0;
                    sp->header.mark++;
                    retries.push_back(p);
                    continue;
                }
            }
            if (full && pn == ack.L) {
                DEBUG("receive buffer full, resend %u now\n", pn);
                i = mSentPackets.erase(i);
                sp->skipCount = 0;
                sp->header.mark++;
                retries.push_back(p);
                continue;
            }
        }
        i++;
    }
    pthread_mutex_unlock(&mSentMutex);
    pthread_cond_broadcast(&mSentCond);

    if (!retries.empty()) {
        pthread_mutex_lock(&mRetryMutex);
        bool done[mPaths.size()];
        memset(done, 0, sizeof(done));
        for (size_t j = 0; j < retries.size(); j++) {
            SCIONPacket *p = retries[j];
            SSPPacket *sp = (SSPPacket *)(p->payload);
            int index= p->pathIndex;
            mRetryPackets->push(p);
            ((SSPPath *)(mPaths[index]))->addLoss(be64toh(sp->header.offset));
            if (!done[index]) {
                done[index] = true;
                ((SSPPath *)(mPaths[index]))->addRetransmit();
            }
        }
        pthread_mutex_unlock(&mRetryMutex);
        pthread_cond_broadcast(&mPacketCond);
    }
}

int SSPConnectionManager::handleAckOnPath(SCIONPacket *packet, bool rttSample)
{
    SSPPacket *sp = (SSPPacket *)(packet->payload);
    SSPAck *ack = &sp->ack;
    if (ack->L + ack->I == 0) {
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
    }
    pthread_cond_broadcast(&mPathCond);
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

    std::vector<SCIONPacket *> retries;
    pthread_mutex_lock(&mPacketMutex);
    pthread_mutex_lock(&mSentMutex);
    PacketList::iterator i = mSentPackets.begin();
    while (i != mSentPackets.end()) {
        int index = (*i)->pathIndex;
        SSPPacket *sp = (SSPPacket *)((*i)->payload);
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
            DEBUG("put packet %u (path %d) in retransmit list (%d dups, timeout = %d)\n",
                    be64toh(sp->header.offset), index, sp->skipCount, timeout[index]);
            SCIONPacket *p = *i;
            i = mSentPackets.erase(i);
            sp->skipCount = 0;
            sp->header.mark++;
            retries.push_back(p);
            lost[index] = true;
            ((SSPPath *)(mPaths[index]))->addLoss(be64toh(sp->header.offset));
        } else {
            i++;
        }
    }
    pthread_mutex_unlock(&mSentMutex);

    pthread_mutex_lock(&mRetryMutex);
    for (size_t j = 0; j < retries.size(); j++)
        mRetryPackets->push(retries[j]);
    pthread_mutex_unlock(&mRetryMutex);
    pthread_mutex_unlock(&mPacketMutex);
    if (!retries.empty())
        pthread_cond_broadcast(&mPacketCond);

    for (size_t j = 0; j < mPaths.size(); j++) {
        if (timeout[j] > 0) {
            DEBUG("%lu.%06lu: path %lu timed out after rto %d\n",
                    current.tv_sec, current.tv_usec, j, ((SDAMPPath *)(mPaths[j]))->getRTO());
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
            pthread_cond_broadcast(&mPathCond);
        }
        if (lost[j]) {
            ((SSPPath *)(mPaths[j]))->addRetransmit();
        }
    }
}

void SSPConnectionManager::didSend(SCIONPacket *packet)
{
    SSPPacket *sp = (SSPPacket *)(packet->payload);
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

void SSPConnectionManager::abortSend(SCIONPacket *packet)
{
    pthread_mutex_lock(&mRetryMutex);
    mRetryPackets->push(packet);
    pthread_mutex_unlock(&mRetryMutex);
    pthread_cond_broadcast(&mPacketCond);
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
