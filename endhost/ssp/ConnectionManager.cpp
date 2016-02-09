#include <arpa/inet.h>
#include <limits.h>
#include <unistd.h>

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
    pthread_mutex_init(&mPathMutex, NULL);
}

PathManager::~PathManager()
{
    close(mDaemonSocket);
    pthread_mutex_destroy(&mPathMutex);
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
    pthread_mutex_lock(&mPathMutex);
    for (size_t i = 0; i < mPaths.size(); i++) {
        if (!mPaths[i])
            continue;
        int size = mPaths[i]->getPayloadLen(false);
        if (size < min)
            min = size;
    }
    pthread_mutex_unlock(&mPathMutex);
    return min;
}

void PathManager::getLocalAddress()
{
    struct sockaddr_in addr;
    char buf[32];
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(SCIOND_API_HOST);
    addr.sin_port = htons(SCIOND_API_PORT);

    buf[0] = 1;
    sendto(mDaemonSocket, buf, 1, 0, (struct sockaddr *)&addr, sizeof(addr));
    recvfrom(mDaemonSocket, buf, 32, 0, NULL, NULL);
    mLocalAddr.isd_ad = ntohl(*(uint32_t *)buf);
    mLocalAddr.host.addrLen = SCION_HOST_ADDR_LEN;
    memcpy(mLocalAddr.host.addr, buf + SCION_HOST_OFFSET, SCION_HOST_ADDR_LEN);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr, mLocalAddr.host.addr, mLocalAddr.host.addrLen);
    bind(mSendSocket, (struct sockaddr *)&addr, sizeof(addr));
}

int PathManager::checkPath(uint8_t *ptr, int len, int addr, std::vector<Path *> &candidates)
{
    bool add = true;
    int pathLen = *ptr * 8;
    if (pathLen > len)
        return -1;
    int interfaceOffset = 1 + pathLen + SCION_HOST_ADDR_LEN + 2 + 2;
    int interfaceCount = *(ptr + interfaceOffset);
    if (interfaceOffset + 1 + interfaceCount * SCION_IF_SIZE > len)
        return -1;
    for (size_t j = 0; j < mPaths.size(); j++) {
        if (mPaths[j] &&
                mPaths[j]->isSamePath(ptr + 1, pathLen)) {
            add = false;
            break;
        }
    }
    for (size_t j = 0; j < candidates.size(); j++) {
        if (candidates[j]->usesSameInterfaces(ptr + interfaceOffset + 1, interfaceCount)) {
            add = false;
            break;
        }
    }
    if (add) {
        Path *p = createPath(mDstAddrs[addr], ptr, 0);
        if (mPolicy.validate(p))
            candidates.push_back(p);
        else
            delete p;
    }
    return interfaceOffset + 1 + interfaceCount * SCION_IF_SIZE;
}

void PathManager::getPaths()
{
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    int buflen = (MAX_PATH_LEN + 15) * MAX_TOTAL_PATHS;
    int recvlen;
    uint8_t buf[buflen];
    
    memset(&addr, 0, addrlen);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(SCIOND_API_HOST);
    addr.sin_port = htons(SCIOND_API_PORT);

    memset(buf, 0, buflen);

    // Get local address first
    if (mLocalAddr.isd_ad == 0) {
        getLocalAddress();
    }

    pthread_mutex_lock(&mPathMutex);

    prunePaths();
    int numPaths = mPaths.size() - mInvalid;

    // Now get paths for remote address(es)
    std::vector<Path *> candidates;
    for (size_t i = 0; i < mDstAddrs.size(); i++) {
        memset(buf, 0, buflen);
        *(uint32_t *)(buf + 1) = htonl(mDstAddrs[i].isd_ad);
        sendto(mDaemonSocket, buf, 5, 0, (struct sockaddr *)&addr, addrlen);

        memset(buf, 0, buflen);
        recvlen = recvfrom(mDaemonSocket, buf, buflen, 0, NULL, NULL);
        if (recvlen > 0) {
            DEBUG("%d byte response from daemon\n", recvlen);
            int offset = 0;
            while (offset < recvlen &&
                    numPaths + candidates.size() < MAX_TOTAL_PATHS) {
                uint8_t *ptr = buf + offset;
                offset += checkPath(ptr, buflen - offset, i, candidates);
            }
        }
        if (numPaths + candidates.size() == MAX_TOTAL_PATHS)
            break;
    }
    insertPaths(candidates);
    DEBUG("total %lu paths\n", mPaths.size() - mInvalid);

    pthread_mutex_unlock(&mPathMutex);
}

void PathManager::prunePaths()
{
    for (size_t i = 0; i < mPaths.size(); i++) {
        Path *p = mPaths[i];
        if (p && (!p->isValid() || !mPolicy.validate(p))) {
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

int PathManager::setStayISD(uint16_t isd)
{
    if (mLocalAddr.isd_ad == 0) {
        getLocalAddress();
    }

    if (isd != GET_ISD(mLocalAddr.isd_ad)) {
        DEBUG("Request to stay in non-local ISD\n");
        return -EINVAL;
    }
    if (isd != GET_ISD(mDstAddrs[0].isd_ad)) {
        DEBUG("Remote host in different ISD\n");
        return -EINVAL;
    }

    mPolicy.setStayISD(isd);
    getPaths();
    return 0;
}

// SUDP

SUDPConnectionManager::SUDPConnectionManager(std::vector<SCIONAddr> &addrs, int sock)
    : PathManager(addrs, sock)
{
    memset(&mLastProbeTime, 0, sizeof(struct timeval));
    getPaths();
    pthread_mutex_lock(&mPathMutex);
    mLastProbeAcked.resize(mPaths.size());
    for (size_t i = 0; i < mPaths.size(); i++) {
        if (!mPaths[i])
            continue;
        mLastProbeAcked[i] = 0;
        mPaths[i]->setUp();
    }
    pthread_mutex_unlock(&mPathMutex);
}

SUDPConnectionManager::~SUDPConnectionManager()
{
}

int SUDPConnectionManager::send(SCIONPacket *packet)
{
    Path *p = NULL;
    // TODO: Choose optimal path?
    pthread_mutex_lock(&mPathMutex);
    for (size_t i = 0; i < mPaths.size(); i++) {
        if (mPaths[i] && mPaths[i]->isUp()) {
            p = mPaths[i];
            break;
        }
    }
    int ret = -1;
    if (p)
        ret = p->send(packet, mSendSocket);
    pthread_mutex_unlock(&mPathMutex);
    return ret;
}

void SUDPConnectionManager::sendProbes(uint32_t probeNum, uint16_t srcPort, uint16_t dstPort)
{
    DEBUG("send probes to dst port %d\n", dstPort);
    int ret = 0;
    pthread_mutex_lock(&mPathMutex);
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
    bool refresh = (mPaths.size() - mInvalid == 0);
    pthread_mutex_unlock(&mPathMutex);
    if (refresh) {
        DEBUG("no valid paths, periodically try fetching\n");
        getPaths();
    }
}

void SUDPConnectionManager::handleProbe(SUDPPacket *sp, SCIONExtension *ext, int index)
{
    uint32_t probeNum = getProbeNum(ext);
    DEBUG("contains probe extension with ID %u\n", probeNum);
    if (isProbeAck(ext)) {
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

void SUDPConnectionManager::handlePacket(SCIONPacket *packet)
{
    bool found = false;
    int index;
    pthread_mutex_lock(&mPathMutex);
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
    if (ext != NULL)
        handleProbe(sp, ext, index);
    pthread_mutex_unlock(&mPathMutex);
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
    mInitAcked(false),
    mResendInit(false),
    mTotalSize(0),
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
    pthread_mutex_lock(&mPathMutex);
    for (size_t i = 0; i < mPaths.size(); i++) {
        if (mPaths[i])
            ((SSPPath*)mPaths[i])->setRemoteWindow(window);
    }
    pthread_mutex_unlock(&mPathMutex);
}

bool SSPConnectionManager::bufferFull(int window)
{
    return window - totalQueuedSize() < maxPayloadSize();
}

void SSPConnectionManager::waitForSendBuffer(int len, int windowSize)
{
    while (totalQueuedSize() + len > windowSize) {
        pthread_mutex_lock(&mSentMutex);
        pthread_cond_wait(&mSentCond, &mSentMutex);
        pthread_mutex_unlock(&mSentMutex);
    }
}

int SSPConnectionManager::totalQueuedSize()
{
    size_t total;
    pthread_mutex_lock(&mPacketMutex);
    total = mTotalSize;
    pthread_mutex_unlock(&mPacketMutex);
    return total;
}

void SSPConnectionManager::queuePacket(SCIONPacket *packet)
{
    pthread_mutex_lock(&mFreshMutex);
    mFreshPackets->push(packet);
    pthread_mutex_unlock(&mFreshMutex);
    pthread_mutex_lock(&mPacketMutex);
    SSPPacket *sp = (SSPPacket *)(packet->payload);
    mTotalSize += sp->len;
    pthread_cond_broadcast(&mPacketCond);
    pthread_mutex_unlock(&mPacketMutex);
}

void SSPConnectionManager::sendAck(SCIONPacket *packet)
{
    DEBUG("send ack on path %d\n", packet->pathIndex);
    pthread_mutex_lock(&mPathMutex);
    if (mPaths[packet->pathIndex])
        mPaths[packet->pathIndex]->send(packet, mSendSocket);
    pthread_mutex_unlock(&mPathMutex);
}

void SSPConnectionManager::sendProbes(uint32_t probeNum, uint64_t flowID)
{
    bool refresh = false;
    pthread_mutex_lock(&mPathMutex);
    DEBUG("send probes\n");
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
    refresh = refresh || mPaths.size() - mInvalid == 0;
    pthread_mutex_unlock(&mPathMutex);
    if (refresh) {
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
    pthread_mutex_lock(&mPathMutex);
    for (size_t i = 0; i < mPaths.size(); i++) {
        if (mPaths[i] && mPaths[i]->timeUntilReady() == 0) {
            SCIONPacket *dup = cloneSSPPacket(packet);
            res |= mPaths[i]->send(dup, mSendSocket);
        }
    }
    pthread_mutex_unlock(&mPathMutex);
    destroySSPPacket(packet->payload);
    destroySCIONPacket(packet);
    return res;
}

int SSPConnectionManager::sendAlternatePath(SCIONPacket *packet, size_t exclude)
{
    int ret = 0;
    pthread_mutex_lock(&mPacketMutex);
    for (size_t i = 0; i < mPaths.size(); i++) {
        Path *p = mPaths[i];
        if (i == exclude || !p ||
                p->timeUntilReady() > 0 ||
                p->getLossRate() > SSP_HIGH_LOSS)
            continue;
        SCIONPacket *clone = cloneSSPPacket(packet);
        pthread_mutex_unlock(&mPacketMutex);
        ret = p->send(clone, mSendSocket);
        break;
    }
    pthread_mutex_unlock(&mPacketMutex);
    return ret;
}

int SSPConnectionManager::handlePacket(SCIONPacket *packet)
{
    bool found = false;
    int index;
    int ret = 0;
    SSPPacket *sp = (SSPPacket *)(packet->payload);
    pthread_mutex_lock(&mPathMutex);
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
        if (mPolicy.validate(p)) {
            index = insertOnePath(p);
        } else {
            delete p;
            pthread_mutex_unlock(&mPathMutex);
            return 0;
        }
    }
    packet->pathIndex = index;
    if (sp->len > 0)
        ret = ((SSPPath *)(mPaths[index]))->handleData(packet);
    pthread_mutex_unlock(&mPathMutex);
    return ret;
}

void SSPConnectionManager::handlePacketAcked(bool found, SCIONPacket *ack, SCIONPacket *sent)
{
    SSPPacket *acksp = (SSPPacket *)(ack->payload);
    SSPPacket *sp = (SSPPacket *)(sent->payload);
    SSPHeader &sh = sp->header;
    uint64_t pn = be64toh(sh.offset);
    uint64_t offset = acksp->ack.L + acksp->ack.I;
    if (found) {
        ack->sendTime = sent->sendTime;
        DEBUG("got ack for packet %lu (path %d), mark: %d|%d\n",
                pn, ack->pathIndex, sh.mark, acksp->header.mark);
        bool sampleRtt = (pn == offset &&
                acksp->header.mark == sh.mark &&
                sent->pathIndex == ack->pathIndex);
        handleAckOnPath(ack, sampleRtt);
    } else if (pn != 0) {
        DEBUG("no longer care about packet %lu (path %d): min is %lu\n",
                pn, sent->pathIndex, acksp->ack.L);
        sent->arrivalTime = ack->arrivalTime;
        sp->ack.L = pn;
        handleAckOnPath(sent, false);
    }
    if (pn == 0)
        mInitAcked = true;
    DEBUG("notify scheduler: successful ack\n");
    pthread_cond_broadcast(&mPathCond);
    if (sh.flags & SSP_FIN) {
        DEBUG("%lu: FIN packet (%lu) acked, %lu more sent packets\n",
                mProtocol->mFlowID, be64toh(sp->header.offset), mSentPackets.size());
        mFinAcked = true;
    }
    if (sp->data.use_count() == 1)
        mTotalSize -= sp->len;
    destroySSPPacket(sp);
    destroySCIONPacket(sent);
}

bool SSPConnectionManager::handleDupAck(SCIONPacket *packet)
{
    SSPPacket *sp = (SSPPacket *)(packet->payload);
    bool dropped = false;
    DEBUG("out of order ack: packet %lu possibly dropped\n",
            be64toh(sp->header.offset));
    ((SSPPath *)(mPaths[packet->pathIndex]))->handleDupAck();
    sp->skipCount++;
    if (sp->skipCount >= SSP_FR_THRESHOLD) {
        DEBUG("packet %lu dropped, add to resend list\n",
                be64toh(sp->header.offset));
        sp->skipCount = 0;
        sp->header.mark++;
        dropped = true;
    }
    return dropped;
}

void SSPConnectionManager::addRetries(std::vector<SCIONPacket *> &retries)
{
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
    DEBUG("notify scheduler: loss from dup acks and/or buffer full\n");
    pthread_cond_broadcast(&mPathCond);
}

void SSPConnectionManager::handleAck(SCIONPacket *packet, size_t initCount, bool receiver)
{
    SSPPacket *spacket = (SSPPacket *)(packet->payload);
    SSPAck &ack = spacket->ack;
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
    pthread_mutex_lock(&mPathMutex);
    pthread_mutex_lock(&mSentMutex);
    PacketList::iterator i = mSentPackets.begin();
    while (i != mSentPackets.end()) {
        SCIONPacket *p = *i;
        SSPPacket *sp = (SSPPacket *)(p->payload);
        SSPHeader &sh = sp->header;
        uint64_t pn = be64toh(sh.offset);
        bool found = ackNums.find(pn) != ackNums.end();
        if (found || pn < ack.L) {
            handlePacketAcked(found, packet, p);
            i = mSentPackets.erase(i);
            DEBUG("%lu: removed packet %lu (path %d) from sent list\n",
                    mProtocol->mFlowID, pn, p->pathIndex);
            ackNums.erase(pn);
            if (ackNums.empty())
                break;
            continue;
        } else {
            if (p->pathIndex == packet->pathIndex && pn < offset) {
                if (handleDupAck(p)) {
                    i = mSentPackets.erase(i);
                    retries.push_back(p);
                    continue;
                }
            }
            if (full && pn == ack.L) {
                DEBUG("receive buffer full, resend %lu now\n", pn);
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

    if (!retries.empty())
        addRetries(retries);

    pthread_mutex_unlock(&mPathMutex);

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
    int pathIndex = packet->pathIndex;
    SSPPath *path = (SSPPath *)(mPaths[pathIndex]);
    SSPPacket *sp = (SSPPacket *)(packet->payload);
    SSPAck *ack = &sp->ack;

    if (!path)
        return -1;

    if (ack->L + ack->I == 0) {
        DEBUG("%p: setting path %d up with ack\n", this, pathIndex);
        mPaths[pathIndex]->setUp();
        int used = 0;
        for (size_t i = 0; i < mPaths.size(); i++) {
            if (mPaths[i] && mPaths[i]->isUsed())
                used++;
        }
        if (used >= MAX_USED_PATHS)
            mPaths[pathIndex]->setUsed(false);
        else
            mPaths[pathIndex]->setUsed(true);
    }
    return path->handleAck(packet, rttSample);
}

void SSPConnectionManager::handleProbeAck(SCIONPacket *packet)
{
    pthread_mutex_lock(&mPathMutex);
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
    pthread_mutex_unlock(&mPathMutex);
}

void SSPConnectionManager::handleTimeout()
{
    struct timeval current;
    gettimeofday(&current, NULL);

    pthread_mutex_lock(&mPathMutex);

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
        uint64_t offset = be64toh(sp->header.offset);
        if (timeout[index] > 0 ||
                sp->skipCount >= SSP_FR_THRESHOLD) {
            DEBUG("put packet %lu (path %d) in retransmit list (%d dups, timeout = %d)\n",
                    offset, index, sp->skipCount, timeout[index]);
            SCIONPacket *p = *i;
            i = mSentPackets.erase(i);
            sp->skipCount = 0;
            sp->header.mark++;
            if (offset == 0) {
                if (!mInitAcked && !mResendInit) {
                    DEBUG("resend init packet\n");
                    mResendInit = true;
                } else {
                    continue;
                }
            }
            retries.push_back(p);
        } else {
            i++;
        }
    }
    pthread_mutex_unlock(&mSentMutex);

    if (!retries.empty()) {
        addRetries(retries);
        pthread_cond_broadcast(&mPacketCond);
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
    }
    pthread_mutex_unlock(&mPathMutex);
}

void SSPConnectionManager::getStats(SCIONStats *stats)
{
    pthread_mutex_lock(&mPathMutex);
    for (size_t i = 0; i < mPaths.size() && i < MAX_TOTAL_PATHS; i++) {
        if (mPaths[i])
            mPaths[i]->getStats(stats);
    }
    pthread_mutex_unlock(&mPathMutex);
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
        pthread_mutex_unlock(&mPacketMutex);

        DEBUG("%p: get path to send stuff\n", this);
        Path *p = NULL;
        bool dup = false;
        pthread_mutex_lock(&mPathMutex);
        while (!(p = pathToSend(&dup))) {
            DEBUG("no path ready yet, wait\n");
            if (mResendInit)
                break;
            pthread_cond_wait(&mPathCond, &mPathMutex);
            DEBUG("woke up from waiting\n");
            if (!mRunning) {
                return;
            }
        }
        SCIONPacket *packet = nextPacket();
        if (!packet) {
            DEBUG("no packet to send\n");
            continue;
        }
        SSPPacket *sp = (SSPPacket *)(packet->payload);
        uint64_t offset = be64toh(sp->header.offset);
        if (offset == 0) {
            DEBUG("%p: resend packet 0 on all paths\n", this);
            mInitSends = 0;
            mResendInit = false;
            pthread_mutex_unlock(&mPathMutex);
            sendAllPaths(packet);
        } else {
            if (!p)
                continue;
            DEBUG("%p: send packet %lu on path %d\n", this,
                    offset, p->getIndex());
            if (sp->header.flags & SSP_FIN) {
                DEBUG("%lu: sending FIN packet (%lu)\n",
                        mProtocol->mFlowID, offset);
                mFinAttempts++;
            }
            p->send(packet, mSendSocket);
            if (p->getLossRate() > SSP_HIGH_LOSS)
                sendAlternatePath(packet, p->getIndex());
            pthread_mutex_unlock(&mPathMutex);
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

Path * SSPConnectionManager::pathToSend(bool *dup)
{
    Path *sendPath = NULL;
    double totalLoss = 0.0;
    int count = 0;
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
        if (ready == 0 && !sendPath)
            sendPath = p;
        totalLoss += p->getLossRate();
        count++;
    }
    double average = totalLoss / count;
    *dup = average > SSP_HIGH_LOSS;
    return sendPath;
}

void SSPConnectionManager::didSend(SCIONPacket *packet)
{
    SSPPacket *sp = (SSPPacket *)(packet->payload);
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
