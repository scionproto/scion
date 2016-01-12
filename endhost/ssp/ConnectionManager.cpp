#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <time.h>
#include <limits.h>

#include "ConnectionManager.h"
#include "Extensions.h"
#include "Path.h"
#include "SCIONProtocol.h"
#include "Utils.h"

PathManager::PathManager(std::vector<SCIONAddr> &addrs, int sock)
    : mSendSocket(sock),
    mDstAddrs(addrs),
    mInvalid(0)
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
        if (!mPaths[i])
            continue;
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

    prunePaths();
    int numPaths = mPaths.size() - mInvalid;
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
                    numPaths + candidates.size() < MAX_TOTAL_PATHS) {
                bool found = false;
                int pathLen = *(buf + offset) * 8;
                if (pathLen + offset > buflen)
                    break;
                int interfaceOffset = offset + 1 + pathLen + SCION_HOST_ADDR_LEN + 2 + 2;
                int interfaceCount = *(buf + interfaceOffset);
                if (interfaceOffset + 1 + interfaceCount * SCION_IF_SIZE > buflen)
                    break;
                for (size_t j = 0; j < mPaths.size(); j++) {
                    if (mPaths[j] &&
                            mPaths[j]->isSamePath(buf + offset + 1, pathLen)) {
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
        if (numPaths + candidates.size() == MAX_TOTAL_PATHS)
            break;
    }
    insertPaths(candidates);
    DEBUG("total %lu paths\n", mPaths.size() - mInvalid);
}

void PathManager::prunePaths()
{
    for (size_t i = 0; i < mPaths.size(); i++) {
        Path *p = mPaths[i];
        if (p && !p->isValid()) {
            mPaths[i] = NULL;
            delete p;
            mInvalid++;
        }
    }
}

void PathManager::insertPaths(std::vector<Path *> &candidates)
{
    if (candidates.empty())
        return;

    for (size_t i = 0; i < mPaths.size(); i++) {
        if (mPaths[i])
            continue;
        Path *p = candidates.front();
        candidates.erase(candidates.begin());
        mPaths[i] = p;
        p->setIndex(i);
        mInvalid--;
        if (candidates.empty())
            break;
    }
    for (size_t i = 0; i < candidates.size(); i++) {
        Path *p = candidates[i];
        int index = mPaths.size();
        mPaths.push_back(p);
        p->setIndex(index);
    }
}

int PathManager::insertOnePath(Path *p)
{
    for (size_t i = 0; i < mPaths.size(); i++) {
        if (mPaths[i])
            continue;
        mPaths[i] = p;
        p->setIndex(i);
        mInvalid--;
        return i;
    }
    int index = mPaths.size();
    mPaths.push_back(p);
    p->setIndex(index);
    return index;
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
        if (!mPaths[i])
            continue;
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
        if (mPaths[i] && mPaths[i]->isUp())
            return mPaths[i]->send(packet, mSendSocket);
    return -1;
}

void SUDPConnectionManager::sendProbes(uint32_t probeNum, uint16_t srcPort, uint16_t dstPort)
{
    DEBUG("send probes to dst port %d\n", dstPort);
    int ret = 0;
    for (size_t i = 0; i < mPaths.size(); i++) {
        if (!mPaths[i])
            continue;
        DEBUG("send probe on path %lu\n", i);
        SCIONPacket p;
        memset(&p, 0, sizeof(p));
        buildCommonHeader(p.header.commonHeader, SCION_PROTO_UDP);
        addProbeExtension(&p.header, probeNum, 0);
        SUDPPacket sp;
        memset(&sp, 0, sizeof(sp));
        p.payload = &sp;
        SUDPHeader &sh = sp.header;
        sh.srcPort = htons(srcPort);
        sh.dstPort = htons(dstPort);
        sh.len = htons(sizeof(SUDPHeader));
        ret |= mPaths[i]->send(&p, mSendSocket);
        free(p.header.extensions);
        if (mLastProbeAcked[i] < probeNum - 3) {
            struct timeval t;
            gettimeofday(&t, NULL);
            mPaths[i]->handleTimeout(&t);
        }
    }
    if (mPaths.size() - mInvalid == 0) {
        DEBUG("no valid paths, periodically try fetching\n");
        getPaths();
    }
}

void SUDPConnectionManager::handlePacket(SCIONPacket *packet)
{
    bool found = false;
    int index;
    for (size_t i = 0; i < mPaths.size(); i++) {
        if (mPaths[i] &&
                mPaths[i]->isSamePath(packet->header.path, packet->header.pathLen)) {
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
        index = insertOnePath(p);
        mLastProbeAcked.resize(mPaths.size());
    }
    packet->pathIndex = index;

    DEBUG("packet came on path %d\n", index);
    mPaths[index]->setUp();
    SUDPPacket *sp = (SUDPPacket *)(packet->payload);
    SCIONExtension *ext = findProbeExtension(&packet->header);
    if (ext != NULL) {
        uint32_t probeNum = getProbeNum(ext);
        DEBUG("contains probe extension with ID %u\n", probeNum);
        if (*(uint8_t *)ext->data) {
            mLastProbeAcked[index] = probeNum;
            DEBUG("probe %u acked on path %d\n", mLastProbeAcked[index], index);
        } else {
            SCIONPacket p;
            memset(&p, 0, sizeof(p));
            buildCommonHeader(p.header.commonHeader, SCION_PROTO_UDP);
            addProbeExtension(&p.header, probeNum, 1);
            SUDPPacket ack;
            p.payload = &ack;
            memset(&ack, 0, sizeof(ack));
            SUDPHeader &sh = ack.header;
            sh.srcPort = htons(sp->header.dstPort);
            sh.dstPort = htons(sp->header.srcPort);
            sh.len = htons(sizeof(sh));
            mPaths[index]->send(&p, mSendSocket);
            DEBUG("sending probe ack back to dst port %d\n", sp->header.srcPort);
        }
    }
}

Path * SUDPConnectionManager::createPath(SCIONAddr &dstAddr, uint8_t *rawPath, int pathLen)
{
    return new SUDPPath(this, mLocalAddr, dstAddr, rawPath, pathLen);
}

// SSP

SSPConnectionManager::SSPConnectionManager(std::vector<SCIONAddr> &addrs, int sock)
    : PathManager(addrs, sock)
{
}

SSPConnectionManager::SSPConnectionManager(std::vector<SCIONAddr> &addrs, int sock, SSPProtocol *protocol)
    : PathManager(addrs, sock),
    mInitSends(0),
    mRunning(true),
    mFinAcked(false),
    mFinAttempts(0),
    mResendInit(false),
    mProtocol(protocol)
{
    mFreshPackets = new OrderedList<SCIONPacket *>(NULL, destroySSPPacketFull);
    mRetryPackets = new OrderedList<SCIONPacket *>(compareOffsetNested, destroySSPPacketFull);
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

SSPConnectionManager::~SSPConnectionManager()
{
    mRunning = false;
    pthread_cond_broadcast(&mPacketCond);
    pthread_cond_broadcast(&mPathCond);
    pthread_join(mWorker, NULL);
    PacketList::iterator i;
    for (i = mSentPackets.begin(); i != mSentPackets.end(); i++) {
        SCIONPacket *p = *i;
        SSPPacket *sp = (SSPPacket *)(p->payload);
        destroySSPPacket(sp);
        destroySCIONPacket(p);
    }
    mFreshPackets->clean();
    delete mFreshPackets;
    mRetryPackets->clean();
    delete mRetryPackets;
    while (!mPaths.empty()) {
        SSPPath *p = (SSPPath *)(mPaths.back());
        mPaths.pop_back();
        if (p)
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

void SSPConnectionManager::setRemoteWindow(uint32_t window)
{
    for (size_t i = 0; i < mPaths.size(); i++) {
        if (mPaths[i])
            ((SSPPath*)mPaths[i])->setRemoteWindow(window);
    }
}

bool SSPConnectionManager::bufferFull(int window)
{
    return window - totalQueuedSize() < maxPayloadSize();
}

void SSPConnectionManager::waitForSendBuffer(int len, int windowSize)
{
    while (totalQueuedSize() + len > windowSize) {
        pthread_mutex_lock(&mSentMutex);
        DEBUG("%lu packets in sent list, %lu in retry list, %lu in fresh list\n",
                mSentPackets.size(), mRetryPackets->size(), mFreshPackets->size());
        pthread_cond_wait(&mSentCond, &mSentMutex);
        pthread_mutex_unlock(&mSentMutex);
    }
}

int SSPConnectionManager::totalQueuedSize()
{
    int total = 0;

    PacketList::iterator i;
    pthread_mutex_lock(&mFreshMutex);
    for (i = mFreshPackets->begin(); i != mFreshPackets->end(); i++) {
        SSPPacket *sp = (SSPPacket *)((*i)->payload);
        total += sizeof(SCIONPacket) + sizeof(SSPPacket) + sp->len;
    }
    pthread_mutex_unlock(&mFreshMutex);

    pthread_mutex_lock(&mRetryMutex);
    for (i = mRetryPackets->begin(); i != mRetryPackets->end(); i++) {
        SSPPacket *sp = (SSPPacket *)((*i)->payload);
        total += sizeof(SCIONPacket) + sizeof(SSPPacket) + sp->len;
    }
    pthread_mutex_unlock(&mRetryMutex);

    pthread_mutex_lock(&mSentMutex);
    for (i = mSentPackets.begin(); i != mSentPackets.end(); i++) {
        SSPPacket *sp = (SSPPacket *)((*i)->payload);
        total += sizeof(SCIONPacket) + sizeof(SSPPacket) + sp->len;
    }
    pthread_mutex_unlock(&mSentMutex);

    return total;
}

void SSPConnectionManager::queuePacket(SCIONPacket *packet)
{
    pthread_mutex_lock(&mFreshMutex);
    mFreshPackets->push(packet);
    pthread_mutex_unlock(&mFreshMutex);
    pthread_mutex_lock(&mPacketMutex);
    pthread_cond_broadcast(&mPacketCond);
    pthread_mutex_unlock(&mPacketMutex);
}

void SSPConnectionManager::sendAck(SCIONPacket *packet)
{
    DEBUG("send ack on path %d\n", packet->pathIndex);
    if (mPaths[packet->pathIndex])
        mPaths[packet->pathIndex]->send(packet, mSendSocket);
}

void SSPConnectionManager::sendProbes(uint32_t probeNum, uint64_t flowID)
{
    bool refresh = false;
    for (size_t i = 0; i < mPaths.size(); i++) {
        SSPPath *p = (SSPPath *)mPaths[i];
        if (!p || p->isUp() || !p->isValid())
            continue;
        DEBUG("send probe %u on path %lu\n", probeNum, i);
        SCIONPacket packet;
        memset(&packet, 0, sizeof(packet));
        buildCommonHeader(packet.header.commonHeader, SCION_PROTO_SSP);
        addProbeExtension(&packet.header, probeNum, 0);
        SSPPacket sp;
        packet.payload = &sp;
        SSPHeader &sh = sp.header;
        sh.headerLen = sizeof(sh);
        sh.flowID = htobe64(flowID);
        int ret = p->send(&packet, mSendSocket);
        free(packet.header.extensions);
        if (ret) {
            DEBUG("terminate path %lu\n", i);
            refresh = true;
        }
    }
    if (refresh || mPaths.empty()) {
        // One or more paths down for long time
        DEBUG("get fresh paths\n");
        getPaths();
    }
}

int SSPConnectionManager::sendAllPaths(SCIONPacket *packet)
{
    int res = 0;
    SSPPacket *sp = (SSPPacket *)(packet->payload);
    if ((sp->header.flags & SSP_FIN) && !(sp->header.flags & SSP_ACK)) {
        DEBUG("%lu: send FIN packet on all paths\n", mProtocol->mFlowID);
        mFinAttempts++;
    }
    pthread_mutex_lock(&mPacketMutex);
    for (size_t i = 0; i < mPaths.size(); i++) {
        if (mPaths[i])
            res |= mPaths[i]->send(packet, mSendSocket);
    }
    pthread_mutex_unlock(&mPacketMutex);
    return res;
}

int SSPConnectionManager::handlePacket(SCIONPacket *packet)
{
    bool found = false;
    int index;
    SSPPacket *sp = (SSPPacket *)(packet->payload);
    for (size_t i = 0; i < mPaths.size(); i++) {
        if (!mPaths[i])
            continue;
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
        index = insertOnePath(p);
    }
    packet->pathIndex = index;
    if (sp->len > 0)
        return ((SSPPath *)(mPaths[index]))->handleData(packet);
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
    pthread_mutex_lock(&mPacketMutex);
    pthread_mutex_lock(&mSentMutex);
    PacketList::iterator i = mSentPackets.begin();
    while (i != mSentPackets.end()) {
        SCIONPacket *p = *i;
        SSPPacket *sp = (SSPPacket *)(p->payload);
        SSPHeader &sh = sp->header;
        uint64_t pn = be64toh(sh.offset);
        bool found = ackNums.find(pn) != ackNums.end();
        if (found || pn < ack.L) {
            if (pn != 0 && !(sh.flags & SSP_FIN) &&
                    found && p->pathIndex != packet->pathIndex) {
                DEBUG("ack for previous send of packet %u came late, discard\n",
                        be64toh(sh.offset));
                i++;
                continue;
            }
            if (found) {
                packet->sendTime = p->sendTime;
                DEBUG("got ack for packet %lu (path %d), mark: %d|%d\n",
                        pn, packet->pathIndex, sh.mark, mark);
                handleAckOnPath(packet, pn == offset && mark == sh.mark);
            } else if (pn != 0) {
                DEBUG("no longer care about packet %u (path %d): min is %lu\n",
                        pn, p->pathIndex, ack.L);
                p->arrivalTime = packet->arrivalTime;
                sp->ack.L = pn;
                handleAckOnPath(p, false);
            }
            DEBUG("notify scheduler: successful ack\n");
            pthread_cond_broadcast(&mPathCond);
            if (pn > 0 ||
                    (receiver || initCount == mPaths.size() - mInvalid)) {
                ackNums.erase(pn);
                i = mSentPackets.erase(i);
                DEBUG("%lu: removed packet %lu (%p) from sent list\n", mProtocol->mFlowID, pn, p);
                if (sh.flags & SSP_FIN) {
                    DEBUG("%lu: FIN packet (%lu) acked, %lu more sent packets\n",
                            mProtocol->mFlowID, be64toh(sp->header.offset), mSentPackets.size());
                    mFinAcked = true;
                }
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
                handleDupAck(p->pathIndex);
                if (sp->skipCount >= SSP_FR_THRESHOLD) {
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
    pthread_cond_broadcast(&mSentCond);
    pthread_mutex_unlock(&mSentMutex);

    if (!retries.empty()) {
        pthread_mutex_lock(&mRetryMutex);
        bool done[mPaths.size()];
        memset(done, 0, sizeof(done));
        for (size_t j = 0; j < retries.size(); j++) {
            SCIONPacket *p = retries[j];
            SSPPacket *sp = (SSPPacket *)(p->payload);
            if (sp->header.flags & SSP_FIN) {
                DEBUG("%lu: resend FIN packet (%lu)\n", mProtocol->mFlowID, be64toh(sp->header.offset));
            }
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
        DEBUG("notify scheduler: loss from dup acks and/or buffer full\n");
        pthread_cond_broadcast(&mPathCond);
    }
    pthread_mutex_unlock(&mPacketMutex);
    bool retriesLeft = false;
    pthread_mutex_lock(&mRetryMutex);
    retriesLeft = !mRetryPackets->empty();
    pthread_mutex_unlock(&mRetryMutex);
    if (mFinAcked && mSentPackets.empty() && !retriesLeft) {
        DEBUG("%lu: everything acked\n", mProtocol->mFlowID);
        mProtocol->notifyFinAck();
        mRunning = false;
    }
}

int SSPConnectionManager::handleAckOnPath(SCIONPacket *packet, bool rttSample)
{
    SSPPacket *sp = (SSPPacket *)(packet->payload);
    SSPAck *ack = &sp->ack;
    if (ack->L + ack->I == 0) {
        DEBUG("%p: setting path %d up with ack\n", this, packet->pathIndex);
        mPaths[packet->pathIndex]->setUp();
        int used = 0;
        for (size_t i = 0; i < mPaths.size(); i++) {
            if (mPaths[i] && mPaths[i]->isUsed())
                used++;
        }
        if (used >= MAX_USED_PATHS)
            mPaths[packet->pathIndex]->setUsed(false);
        else
            mPaths[packet->pathIndex]->setUsed(true);
    }
    return ((SSPPath *)(mPaths[packet->pathIndex]))->handleAck(packet, rttSample);
}

void SSPConnectionManager::handleDupAck(int index)
{
    ((SSPPath *)(mPaths[index]))->handleDupAck();
}

void SSPConnectionManager::handleProbeAck(SCIONPacket *packet)
{
    pthread_mutex_lock(&mMutex);
    for (size_t i = 0; i < mPaths.size(); i++) {
        if (mPaths[i] &&
                mPaths[i]->isSamePath(packet->header.path, packet->header.pathLen)) {
            if (!mPaths[i]->isUp()) {
                DEBUG("path %lu back up from probe\n", i);
                mPaths[i]->setUp();
                pthread_cond_broadcast(&mPathCond);
                int used = 0;
                for (size_t j = 0; j < mPaths.size(); j++) {
                    if (mPaths[j] && mPaths[j]->isUsed())
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

void SSPConnectionManager::handleTimeout()
{
    struct timeval current;
    gettimeofday(&current, NULL);
    bool lost[mPaths.size()];
    memset(lost, 0, sizeof(lost));
    int timeout[mPaths.size()];
    memset(timeout, 0, sizeof(int) * mPaths.size());
    for (size_t i = 0; i < mPaths.size(); i++) {
        if (mPaths[i])
            timeout[i] = mPaths[i]->didTimeout(&current);
        else
            timeout[i] = false;
    }

    std::vector<SCIONPacket *> retries;
    pthread_mutex_lock(&mPacketMutex);
    pthread_mutex_lock(&mSentMutex);
    PacketList::iterator i = mSentPackets.begin();
    while (i != mSentPackets.end()) {
        int index = (*i)->pathIndex;
        SSPPacket *sp = (SSPPacket *)((*i)->payload);
        // Special case for packet 0
        if (be64toh(sp->header.offset == 0)) {
            size_t up = 0, down = 0;
            for (size_t j = 0; j < mPaths.size(); j++) {
                SSPPath *p = (SSPPath *)(mPaths[j]);
                if (!p) {
                    down++;
                    continue;
                }
                if (p->isUp()) {
                    up++;
                } else if (p->didTimeout(&current)) {
                    DEBUG("path %lu timed out on packet 0\n", j);
                    p->setUsed(false);
                    p->addLoss(0);
                    down++;
                }
            }
            if (up + down == mPaths.size()) {
                DEBUG("%lu: remove packet 0 from sent list, %lu paths up\n",
                        mProtocol->mFlowID, up);
                if (up == 0) {
                    DEBUG("no paths up, resend packet 0\n");
                    retries.push_back(*i);
                    mResendInit = true;
                    pthread_cond_broadcast(&mPathCond);
                }
                i = mSentPackets.erase(i);
            } else {
                i++;
            }
            continue;
        }
        if (timeout[index] > 0 ||
                sp->skipCount >= SSP_FR_THRESHOLD) {
            DEBUG("put packet %lu (path %d) in retransmit list (%d dups, timeout = %d)\n",
                    be64toh(sp->header.offset), index, sp->skipCount, timeout[index]);
            SCIONPacket *p = *i;
            i = mSentPackets.erase(i);
            sp->skipCount = 0;
            sp->header.mark++;
            if (sp->header.flags & SSP_FIN) {
                DEBUG("%lu: resend FIN packet (%lu)\n", mProtocol->mFlowID, be64toh(sp->header.offset));
            }
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

    bool retriesLeft = false;
    pthread_mutex_lock(&mRetryMutex);
    retriesLeft = !mRetryPackets->empty();
    pthread_mutex_unlock(&mRetryMutex);
    if (mFinAcked && mSentPackets.empty() && !retriesLeft) {
        DEBUG("%lu: everything acked\n", mProtocol->mFlowID);
        mProtocol->notifyFinAck();
        mRunning = false;
    }

    for (size_t j = 0; j < mPaths.size(); j++) {
        if (timeout[j] > 0) {
            DEBUG("%lu.%06lu: path %lu timed out after rto %d\n",
                    current.tv_sec, current.tv_usec, j, ((SSPPath *)(mPaths[j]))->getRTO());
            mPaths[j]->handleTimeout(&current);
            if (!mPaths[j]->isUp()) {
                DEBUG("path %lu is down: disable\n", j);
                mPaths[j]->setUsed(false);
                for (size_t k = 0; k < mPaths.size(); k++) {
                    if (mPaths[k] && !mPaths[k]->isUsed() && mPaths[k]->isUp()) {
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

void SSPConnectionManager::getStats(SCIONStats *stats)
{
    for (size_t i = 0; i < mPaths.size(); i++) {
        if (mPaths[i])
            mPaths[i]->getStats(stats);
    }
}

Path * SSPConnectionManager::createPath(SCIONAddr &dstAddr, uint8_t *rawPath, int pathLen)
{
    return new SSPPath(this, mLocalAddr, dstAddr, rawPath, pathLen);
}

void SSPConnectionManager::startScheduler()
{
    getPaths();
    pthread_create(&mWorker, NULL, &SSPConnectionManager::workerHelper, this);
}

void * SSPConnectionManager::workerHelper(void *arg)
{
    SSPConnectionManager *manager = (SSPConnectionManager *)arg;
    manager->schedule();
    return NULL;
}

bool SSPConnectionManager::readyToSend()
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

void SSPConnectionManager::schedule()
{
    while (mRunning) {
        pthread_mutex_lock(&mPacketMutex);
        while (!readyToSend()) {
            DEBUG("wait until there is stuff to send\n");
            pthread_cond_wait(&mPacketCond, &mPacketMutex);
            if (!mRunning) {
                pthread_mutex_unlock(&mPacketMutex);
                return;
            }
        }

        DEBUG("%p: get path to send stuff\n", this);
        Path *p = NULL;
        while (!(p = pathToSend())) {
            DEBUG("no path ready yet, wait\n");
            pthread_cond_wait(&mPathCond, &mPacketMutex);
            DEBUG("woke up from waiting\n");
            if (!mRunning) {
                pthread_mutex_unlock(&mPacketMutex);
                return;
            }
            if (mResendInit) {
                mResendInit = false;
                break;
            }
        }
        SCIONPacket *packet = nextPacket();
        pthread_mutex_unlock(&mPacketMutex);
        if (!packet) {
            DEBUG("no packet to send\n");
            continue;
        }
        SSPPacket *sp = (SSPPacket *)(packet->payload);
        if (be64toh(sp->header.offset) == 0) {
            DEBUG("%p: resend packet 0 on all paths\n", this);
            mInitSends = 0;
            sendAllPaths(packet);
        } else {
            DEBUG("%p: send packet %lu on path %d\n", this,
                    be64toh(sp->header.offset), p->getIndex());
            if (sp->header.flags & SSP_FIN) {
                DEBUG("%lu: sending FIN packet (%lu)\n",
                        mProtocol->mFlowID, be64toh(sp->header.offset));
                mFinAttempts++;
            }
            p->send(packet, mSendSocket);
        }
    }
}

SCIONPacket * SSPConnectionManager::nextPacket()
{
    SCIONPacket *packet = NULL;
    pthread_mutex_lock(&mRetryMutex);
    if (!mRetryPackets->empty())
        packet = mRetryPackets->pop();
    pthread_mutex_unlock(&mRetryMutex);
    if (!packet) {
        pthread_mutex_lock(&mFreshMutex);
        if (!mFreshPackets->empty()) {
            packet = mFreshPackets->pop();
            DEBUG("popped packet from fresh queue, notify sender\n");
            mProtocol->notifySender();
            if (mFinAttempts > 0)
                packet = NULL;
        }
        pthread_mutex_unlock(&mFreshMutex);
    }
    return packet;
}

Path * SSPConnectionManager::pathToSend()
{
    for (size_t i = 0; i < mPaths.size(); i++) {
        Path *p = mPaths[i];
        if (!p)
            continue;
        if (!p->isUp() || !p->isUsed()) {
            DEBUG("path %lu: up(%d), used(%d)\n", i, p->isUp(), p->isUsed());
            continue;
        }
        DEBUG("is path %lu ready?\n", i);
        int ready = p->timeUntilReady();
        DEBUG("path %lu: ready = %d\n", i, ready);
        if (ready == 0)
            return p;
    }
    return NULL;
}

void SSPConnectionManager::didSend(SCIONPacket *packet)
{
    SSPPacket *sp = (SSPPacket *)(packet->payload);
    if (be64toh(sp->header.offset) == 0) {
        ++mInitSends;
        DEBUG("%lu: packet %p, mInitSends = %d\n", mProtocol->mFlowID, packet, mInitSends);
        if (mInitSends < (int)mPaths.size() - mInvalid)
            return;
    }
    pthread_mutex_lock(&mSentMutex);
    PacketList::iterator i;
    for (i = mSentPackets.begin(); i != mSentPackets.end(); i++) {
        if (*i == packet) {
            SCIONPacket *p = *i;
            SSPPacket *s = (SSPPacket *)(p->payload);
            if (s->header.flags & SSP_FIN) {
                pthread_mutex_unlock(&mSentMutex);
                return;
            }
            printf("duplicate packet in sent list: %lu|%lu, path %d|%d (%p)\n",
                    be64toh(s->header.offset), be64toh(sp->header.offset),
                    packet->pathIndex, p->pathIndex, packet);
            exit(0);
        }
    }
    mSentPackets.push_back(packet);
    pthread_mutex_unlock(&mSentMutex);
}
