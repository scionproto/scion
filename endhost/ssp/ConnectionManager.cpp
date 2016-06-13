#include <arpa/inet.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <limits.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/un.h>

#include "ConnectionManager.h"
#include "Extensions.h"
#include "Path.h"
#include "SCIONProtocol.h"
#include "Utils.h"

PathManager::PathManager(int sock, const char *sciond)
    : mSendSocket(sock),
    mInvalid(0)
{
    mDaemonSocket = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, sciond);
    if (connect(mDaemonSocket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "failed to connect to sciond at %s: %s\n", sciond, strerror(errno));
        exit(1);
    }
    memset(&mLocalAddr, 0, sizeof(mLocalAddr));
    memset(&mDstAddr, 0, sizeof(mDstAddr));
    pthread_mutex_init(&mPathMutex, NULL);
    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_REALTIME);
    pthread_cond_init(&mPathCond, &ca);
    pthread_mutex_init(&mDispatcherMutex, NULL);

    // get default IP from OS - can be overwritten by bind()
    getDefaultIP();
}

PathManager::~PathManager()
{
    close(mDaemonSocket);
    pthread_mutex_destroy(&mPathMutex);
    pthread_cond_destroy(&mPathCond);
}

void PathManager::getDefaultIP()
{
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) < 0) {
        fprintf(stderr, "failed to get OS IP addr: %s\n", strerror(errno));
        exit(1);
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        if (ifa->ifa_flags & IFF_LOOPBACK)
            continue;
        // TODO(aznair): IPv6
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)(ifa->ifa_addr);
            mLocalAddr.host.addr_len = 4;
            memcpy(mLocalAddr.host.addr, &sa->sin_addr, 4);
            break;
        }
    }
    freeifaddrs(ifaddr);
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

SCIONAddr * PathManager::localAddress()
{
    return &mLocalAddr;
}

void PathManager::queryLocalAddress()
{
    DEBUG("%s\n", __func__);
    uint8_t buf[32];

    buf[0] = 1;
    send_dp_header(mDaemonSocket, NULL, 1);
    send_all(mDaemonSocket, buf, 1);
    recv_all(mDaemonSocket, buf, DP_HEADER_LEN);
    int len = 0;
    parse_dp_header(buf, NULL, &len);
    if (len == -1) {
        fprintf(stderr, "out of sync with sciond\n");
        exit(1);
    }
    recv_all(mDaemonSocket, buf, len);
    mLocalAddr.isd_as = ntohl(*(uint32_t *)buf);
}

int PathManager::setLocalAddress(SCIONAddr addr)
{
    DEBUG("%p: bind to (%d-%d):%s\n",
            this, ISD(addr.isd_as), AS(addr.isd_as),
            inet_ntoa(*(struct in_addr *)addr.host.addr));

    if (mLocalAddr.isd_as == 0)
        queryLocalAddress();

    if (addr.isd_as == 0) /* bind to any address */
        return 0;

    mLocalAddr.host.addr_len = addr.host.addr_len;
    memcpy(mLocalAddr.host.addr, addr.host.addr, addr.host.addr_len);

    return 0;
}

void PathManager::setRemoteAddress(SCIONAddr addr)
{
    DEBUG("%p: setRemoteAddress: (%d-%d)\n", this, ISD(addr.isd_as), AS(addr.isd_as));
    if (addr.isd_as == mDstAddr.isd_as) {
        DEBUG("%p: dst addr already set: (%d-%d)\n", this, ISD(mDstAddr.isd_as), AS(mDstAddr.isd_as));
        return -EPERM;
    }

    mDstAddr = addr;
    for (size_t i = 0; i < mPaths.size(); i++) {
        Path *p = mPaths[i];
        if (p)
            delete p;
    }
    mPaths.clear();
    getPaths();
    gettimeofday(&end, NULL);
    long delta = elapsedTime(&start, &end);
    waitTime -= delta / 1000000.0;
    if (timeout > 0.0 && waitTime < 0)
        return -ETIMEDOUT;
    waitTime = floor(waitTime);

    pthread_mutex_lock(&mPathMutex);
    while (mPaths.size() - mInvalid == 0) {
        DEBUG("%p: trying to connect but no paths available\n", this);
        if (timeout > 0.0) {
            gettimeofday(&start, NULL);
            int ret;
            if ((ret = timedWait(&mPathCond, &mPathMutex, waitTime)) == ETIMEDOUT) {
                DEBUG("%p: timeout in setRemoteAddress\n", this);
                pthread_mutex_unlock(&mPathMutex);
                return -ETIMEDOUT;
            }
            gettimeofday(&end, NULL);
            delta = elapsedTime(&start, &end);
            waitTime -= delta / 1000000.0;
            if (waitTime < 0)
                return -ETIMEDOUT;
            waitTime = floor(waitTime);
        } else {
            pthread_cond_wait(&mPathCond, &mPathMutex);
        }
    }
    pthread_mutex_unlock(&mPathMutex);
    return 0;
}

int PathManager::checkPath(uint8_t *ptr, int len, std::vector<Path *> &candidates)
{
    bool add = true;
    int pathLen = *ptr * 8;
    if (pathLen > len)
        return -1;
    // TODO: IPv6?
    int interfaceOffset = 1 + pathLen + ADDR_IPV4_LEN + 2 + 2;
    int interfaceCount = *(ptr + interfaceOffset);
    if (interfaceOffset + 1 + interfaceCount * IF_TOTAL_LEN > len)
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
        Path *p = createPath(mDstAddr, ptr, 0);
        if (mPolicy.validate(p))
            candidates.push_back(p);
        else
            delete p;
    }
    return interfaceOffset + 1 + interfaceCount * IF_TOTAL_LEN;
}

void PathManager::getPaths()
{
    int buflen = (MAX_PATH_LEN + 15) * MAX_TOTAL_PATHS;
    int recvlen;
    uint8_t buf[buflen];

    memset(buf, 0, buflen);

    // Get local address first
    if (mLocalAddr.isd_as == 0) {
        queryLocalAddress();
    }

    pthread_mutex_lock(&mPathMutex);

    prunePaths();
    int numPaths = mPaths.size() - mInvalid;

    // Now get paths for remote address(es)
    std::vector<Path *> candidates;
    memset(buf, 0, buflen);
    *(uint32_t *)(buf + 1) = htonl(mDstAddr.isd_as);
    send_dp_header(mDaemonSocket, NULL, 5);
    send_all(mDaemonSocket, buf, 5);

    memset(buf, 0, buflen);
    recv_all(mDaemonSocket, buf, DP_HEADER_LEN);
    parse_dp_header(buf, NULL, &recvlen);
    if (recvlen == -1) {
        fprintf(stderr, "out of sync with sciond\n");
        exit(1);
    }
    recvlen = recv_all(mDaemonSocket, buf, recvlen);
    if (recvlen > 0) {
        DEBUG("%d byte response from daemon\n", recvlen);
        int offset = 0;
        while (offset < recvlen &&
                numPaths + candidates.size() < MAX_TOTAL_PATHS) {
            uint8_t *ptr = buf + offset;
            offset += checkPath(ptr, buflen - offset, candidates);
        }
    }
    insertPaths(candidates);
    DEBUG("total %lu paths\n", mPaths.size() - mInvalid);

    pthread_cond_broadcast(&mPathCond);
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
    PathParams params;
    params.localAddr = &mLocalAddr;
    params.dstAddr = &dstAddr;
    params.rawPath = rawPath;
    params.pathLen = pathLen;
    return new Path(this, &params);
}

void PathManager::handleTimeout()
{
}

void PathManager::getStats(SCIONStats *stats)
{
}

int PathManager::setISDWhitelist(void *data, size_t len)
{
    if (len % 2 != 0) {
        DEBUG("List of ISDs should have an even total length\n");
        return -EINVAL;
    }

    if (mLocalAddr.isd_as == 0) {
        queryLocalAddress();
    }

    std::vector<uint16_t> isds;
    bool foundSelf = false;
    bool foundDst = false;
    for (size_t i = 0; i < len / 2; i ++) {
        uint16_t isd = *((uint16_t *)data + i);
        if (isd == ISD(mLocalAddr.isd_as))
            foundSelf = true;
        if (isd == ISD(mDstAddr.isd_as))
            foundDst = true;
        isds.push_back(isd);
    }

    if (len > 0) {
        if (!foundSelf) {
            DEBUG("Own ISD not whitelisted\n");
            return -EINVAL;
        }
        if (!foundDst) {
            DEBUG("Destination ISD not whitelisted\n");
            return -EINVAL;
        }
    }

    mPolicy.setISDWhitelist(isds);
    getPaths();
    return 0;
}

void PathManager::threadCleanup()
{
    pthread_mutex_unlock(&mPathMutex);
}

void PathManager::didSend(SCIONPacket *packet)
{
}

int PathManager::sendRawPacket(uint8_t *buf, int len, HostAddr *firstHop)
{
    pthread_mutex_lock(&mDispatcherMutex);
    send_dp_header(mSendSocket, firstHop, len);
    int sent = send_all(mSendSocket, buf, len);
    pthread_mutex_unlock(&mDispatcherMutex);
    return sent;
}

// SSP

SSPConnectionManager::SSPConnectionManager(int sock, const char *sciond)
    : PathManager(sock, sciond)
{
}

SSPConnectionManager::SSPConnectionManager(int sock, const char *sciond, SSPProtocol *protocol)
    : PathManager(sock, sciond),
    mRunning(true),
    mFinAcked(false),
    mFinAttempts(0),
    mInitAcked(false),
    mResendInit(true),
    mHighestAcked(0),
    mTotalSize(0),
    mProtocol(protocol)
{
    mFreshPackets = new OrderedList<SCIONPacket *>(NULL, destroySSPPacketFull);
    mRetryPackets = new OrderedList<SCIONPacket *>(compareOffsetNested, destroySSPPacketFull);
    pthread_mutex_init(&mMutex, NULL);
    pthread_mutex_init(&mSentMutex, NULL);
    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_REALTIME);
    pthread_cond_init(&mSentCond, NULL);
    pthread_mutex_init(&mFreshMutex, NULL);
    pthread_mutex_init(&mRetryMutex, NULL);
    pthread_mutex_init(&mPacketMutex, NULL);
    pthread_cond_init(&mPacketCond, &ca);
    memset(&mFinSentTime, 0, sizeof(mFinSentTime));

    pthread_create(&mWorker, NULL, &SSPConnectionManager::workerHelper, this);
}

SSPConnectionManager::~SSPConnectionManager()
{
    mRunning = false;
    pthread_cancel(mWorker);
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

int SSPConnectionManager::waitForSendBuffer(int len, int windowSize, double timeout)
{
    while (totalQueuedSize() + len > windowSize) {
        pthread_mutex_lock(&mSentMutex);
        if (timeout > 0.0) {
            if (timedWait(&mSentCond, &mSentMutex, timeout) == ETIMEDOUT) {
                DEBUG("%p: timeout waiting for send buffer\n", this);
                pthread_mutex_unlock(&mSentMutex);
                return -ETIMEDOUT;
            }
        } else {
            pthread_cond_wait(&mSentCond, &mSentMutex);
        }
        pthread_mutex_unlock(&mSentMutex);
    }
    return 0;
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
        mPaths[packet->pathIndex]->sendPacket(packet, mSendSocket);
    pthread_mutex_unlock(&mPathMutex);
}

void SSPConnectionManager::sendProbes(uint32_t probeNum, uint64_t flowID)
{
    DEBUG("send probes\n");

    if (!mInitAcked)
        return;

    bool refresh = false;
    pthread_mutex_lock(&mPathMutex);
    if (mInitAcked) {
        for (size_t i = 0; i < mPaths.size(); i++) {
            SSPPath *p = (SSPPath *)mPaths[i];
            if (!p || p->isUp() || !p->isValid())
                continue;
            DEBUG("send probe %u on path %lu\n", probeNum, i);
            SCIONPacket packet;
            memset(&packet, 0, sizeof(packet));
            pack_cmn_hdr((uint8_t *)&packet.header.commonHeader,
                    ADDR_IPV4_TYPE, ADDR_IPV4_TYPE, L4_SSP, 0, 0, 0);
            addProbeExtension(&packet.header, probeNum, 0);
            SSPPacket sp;
            packet.payload = &sp;
            SSPHeader &sh = sp.header;
            sh.headerLen = sizeof(sh);
            sp.setFlowID(flowID);
            int ret = p->sendPacket(&packet, mSendSocket);
            free(packet.header.extensions);
            if (ret) {
                DEBUG("terminate path %lu\n", i);
                refresh = true;
            }
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
    pthread_mutex_lock(&mPathMutex);
    for (size_t i = 0; i < mPaths.size(); i++) {
        if (mPaths[i] && mPaths[i]->timeUntilReady() == 0) {
            SCIONPacket *dup = cloneSSPPacket(packet);
            res |= mPaths[i]->sendPacket(dup, mSendSocket);
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
        ret = p->sendPacket(clone, mSendSocket);
        break;
    }
    pthread_mutex_unlock(&mPacketMutex);
    return ret;
}

int SSPConnectionManager::handlePacket(SCIONPacket *packet, bool receiver)
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
        if (!receiver) {
            DEBUG("sender should not add paths from remote end\n");
            pthread_mutex_unlock(&mPathMutex);
            return -1;
        }
        SCIONAddr saddr;
        saddr.isd_as = ntohl(*(uint32_t *)(packet->header.srcAddr));
        // TODO: IPv6?
        saddr.host.addr_len = ADDR_IPV4_LEN;
        memcpy(&(saddr.host.addr), packet->header.srcAddr + ISD_AS_LEN, ADDR_IPV4_LEN);

        SSPPath *p = (SSPPath *)createPath(saddr, packet->header.path, packet->header.pathLen);
        p->setFirstHop(ADDR_IPV4_LEN, (uint8_t *)&(packet->firstHop));
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
    mPaths[index]->setUp();
    int used = 0;
    for (size_t i = 0; i < mPaths.size(); i++)
        if (mPaths[i]->isUsed())
            used++;
    if (used < MAX_USED_PATHS)
        mPaths[index]->setUsed(true);
    if (sp->len > 0)
        ret = ((SSPPath *)(mPaths[index]))->handleData(packet);
    pthread_mutex_unlock(&mPathMutex);
    return ret;
}

void SSPConnectionManager::handlePacketAcked(bool match, SCIONPacket *ack, SCIONPacket *sent)
{
    SSPPacket *acksp = (SSPPacket *)(ack->payload);
    SSPPacket *sp = (SSPPacket *)(sent->payload);
    SSPHeader &sh = sp->header;
    uint64_t pn = sp->getOffset();
    uint64_t offset = acksp->getAckNum();
    if (match) {
        ack->sendTime = sent->sendTime;
        DEBUG("got ack for packet %lu (path %d), mark: %d|%d\n",
                pn, sent->pathIndex, sp->getMark(), acksp->getMark());
        bool sampleRtt = (pn == offset &&
                acksp->getMark() == sp->getMark() &&
                sent->pathIndex == ack->pathIndex);
        handleAckOnPath(ack, sampleRtt, sent->pathIndex);
    } else if (pn != 0) {
        DEBUG("no longer care about packet %lu (path %d): min is %lu\n",
                pn, sent->pathIndex, acksp->ack.L);
        sent->arrivalTime = ack->arrivalTime;
        sp->ack.L = pn;
        handleAckOnPath(sent, false, sent->pathIndex);
    }
    if (pn == 0)
        mInitAcked = true;
    DEBUG("notify scheduler: successful ack\n");
    pthread_cond_broadcast(&mPathCond);
    if (sh.flags & SSP_FIN) {
        DEBUG("FIN packet (%lu) acked, %lu more sent packets\n",
                sp->getOffset(), mSentPackets.size());
        mFinAcked = true;
    }
    if (sp->data.use_count() == 1) {
        mTotalSize -= sp->len;
        mProtocol->signalSelect();
    }
    destroySSPPacket(sp);
    destroySCIONPacket(sent);
}

bool SSPConnectionManager::handleDupAck(SCIONPacket *packet)
{
    SSPPacket *sp = (SSPPacket *)(packet->payload);
    bool dropped = false;
    DEBUG("out of order ack: packet %lu possibly dropped\n",
            sp->getOffset());
    ((SSPPath *)(mPaths[packet->pathIndex]))->handleDupAck();
    sp->skipCount++;
    if (sp->skipCount >= SSP_FR_THRESHOLD) {
        DEBUG("packet %lu dropped, add to resend list\n",
                sp->getOffset());
        sp->skipCount = 0;
        sp->setMark(sp->getMark() + 1);
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
        if (sp->getOffset() == 0 && (!mInitAcked && !mResendInit)) {
            mResendInit = true;
            mRetryPackets->push(p);
        } else if (sp->getOffset() > 0) {
            mRetryPackets->push(p);
        }
        ((SSPPath *)(mPaths[index]))->addLoss(sp->getOffset());
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
    uint64_t offset = spacket->getAckNum();

    DEBUG("got some acks on path %d: L = %lu, I = %d, O = %d, V = %#x\n",
            packet->pathIndex, spacket->getL(), spacket->getI(), spacket->getO(), spacket->getV());

    mHighestAcked = spacket->getL() - 1;

    std::vector<SCIONPacket *> retries;
    pthread_mutex_lock(&mPathMutex);
    pthread_mutex_lock(&mSentMutex);
    PacketList::iterator i = mSentPackets.begin();
    while (i != mSentPackets.end()) {
        SCIONPacket *p = *i;
        SSPPacket *sp = (SSPPacket *)(p->payload);
        SSPHeader &sh = sp->header;
        uint64_t pn = sp->getOffset();
        bool match = offset == pn &&
            (sh.flags & SSP_FIN ||
             (sp->getMark() == spacket->getMark() && p->pathIndex == packet->pathIndex));
        if (match || (pn > 0 && pn < spacket->getL())) {
            i = mSentPackets.erase(i);
            handlePacketAcked(match, packet, p);
            DEBUG("removed packet %lu (%p, path %d) from sent list\n",
                   pn, p, p->pathIndex);
            continue;
        } else {
            if (p->pathIndex == packet->pathIndex && pn < offset) {
                if (handleDupAck(p)) {
                    i = mSentPackets.erase(i);
                    retries.push_back(p);
                    continue;
                }
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
        DEBUG("everything acked\n");
        mProtocol->notifyFinAck();
        mRunning = false;
    }
}

int SSPConnectionManager::handleAckOnPath(SCIONPacket *packet, bool rttSample, int pathIndex)
{
    SSPPath *path = (SSPPath *)(mPaths[pathIndex]);
    SSPPacket *sp = (SSPPacket *)(packet->payload);

    if (!path) {
        DEBUG("got ack on null path %d\n", pathIndex);
        return -1;
    }

    if (sp->getAckNum() == 0) {
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
    DEBUG("%p: handleProbeAck\n", this);
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

    if (mFinSentTime.tv_sec != 0 &&
            elapsedTime(&mFinSentTime, &current) > SSP_FIN_THRESHOLD) {
        mProtocol->notifyFinAck();
        return;
    }

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
        if (timeout[index] > 0 ||
                sp->skipCount >= SSP_FR_THRESHOLD) {
            DEBUG("%p: put packet %lu (path %d) in retransmit list (%d dups, timeout = %d)\n",
                  this, sp->getOffset(), index, sp->skipCount, timeout[index]);
            SCIONPacket *p = *i;
            i = mSentPackets.erase(i);
            sp->skipCount = 0;
            sp->setMark(sp->getMark() + 1);
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
        DEBUG("everything acked\n");
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
    PathParams params;
    params.localAddr = &mLocalAddr;
    params.dstAddr = &dstAddr;
    params.rawPath = rawPath;
    params.pathLen = pathLen;
    params.type = CC_CUBIC;
    return new SSPPath(this, &params);
}

void SSPConnectionManager::startScheduler()
{
    pthread_create(&mWorker, NULL, &SSPConnectionManager::workerHelper, this);
}

void * SSPConnectionManager::workerHelper(void *arg)
{
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
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
            DEBUG("%p: wait until there is stuff to send\n", this);
            pthread_cond_wait(&mPacketCond, &mPacketMutex);
            DEBUG("%p: scheduler woken up\n", this);
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
            DEBUG("%p: no path ready yet, wait\n", this);
            if (!mPaths.empty() && mResendInit) {
                DEBUG("%p: need to resend init\n", this);
                break;
            }
            pthread_cond_wait(&mPathCond, &mPathMutex);
            DEBUG("%p: woke up from waiting\n", this);
            if (!mRunning) {
                pthread_mutex_unlock(&mPathMutex);
                return;
            }
        }
        pthread_mutex_unlock(&mPathMutex);
        SCIONPacket *packet = nextPacket();
        if (!packet) {
            DEBUG("%p: no packet to send\n", this);
            continue;
        }
        SSPPacket *sp = (SSPPacket *)(packet->payload);
        uint64_t offset = sp->getOffset();
        if (offset > 0 && offset <= mHighestAcked) {
            DEBUG("%p: packet %lu already received on remote end\n", this, offset);
            destroySSPPacketFull(packet);
            continue;
        }
        DEBUG("%p: try to send packet %lu\n", this, offset);
        if (offset == 0) {
            if (sp->header.flags & SSP_CON) {
                DEBUG("%p: send packet 0 on all paths\n", this);
                sendAllPaths(packet);
            } else {
                DEBUG("%p: send packet %lu on path %d\n", this,
                        offset, p->getIndex());
                p->sendPacket(packet, mSendSocket);
            }
            mResendInit = false;
        } else if (sp->header.flags & SSP_FIN) {
            DEBUG("%p: send FIN packet (%lu) on all paths\n", this, offset);
            if (mFinAttempts == 0)
                gettimeofday(&mFinSentTime, NULL);
            mFinAttempts++;
            sendAllPaths(packet);
        } else {
            if (!p)
                continue;
            DEBUG("%p: send packet %lu on path %d\n", this,
                    offset, p->getIndex());
            p->sendPacket(packet, mSendSocket);
            if (p->getLossRate() > SSP_HIGH_LOSS) {
                DEBUG("%p: loss rate high, duplicate on alternate path\n", this);
                sendAlternatePath(packet, p->getIndex());
            }
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
            fprintf(stderr, "duplicate packet in sent list: %" PRIu64 "|%" PRIu64 ", path %d|%d (%p)\n",
                    s->getOffset(), sp->getOffset(),
                    packet->pathIndex, p->pathIndex, packet);
            exit(0);
        }
    }
    mSentPackets.push_back(packet);
    pthread_mutex_unlock(&mSentMutex);
}

void SSPConnectionManager::threadCleanup()
{
    pthread_mutex_unlock(&mMutex);
    pthread_mutex_unlock(&mSentMutex);
    pthread_mutex_unlock(&mRetryMutex);
    pthread_mutex_unlock(&mFreshMutex);
    pthread_mutex_unlock(&mPacketMutex);
    pthread_mutex_unlock(&mDispatcherMutex);
    PathManager::threadCleanup();
}

// SUDP

SUDPConnectionManager::SUDPConnectionManager(int sock, const char *sciond)
    : PathManager(sock, sciond)
{
    memset(&mLastProbeTime, 0, sizeof(struct timeval));
}

SUDPConnectionManager::~SUDPConnectionManager()
{
}

int SUDPConnectionManager::sendPacket(SCIONPacket *packet)
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
        ret = p->sendPacket(packet, mSendSocket);
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
        pack_cmn_hdr((uint8_t *)&p.header.commonHeader, ADDR_IPV4_TYPE,
                ADDR_IPV4_TYPE, L4_UDP, 0, 0, 0);
        addProbeExtension(&p.header, probeNum, 0);
        SUDPPacket sp;
        memset(&sp, 0, sizeof(sp));
        p.payload = &sp;
        SUDPHeader &sh = sp.header;
        sh.srcPort = htons(srcPort);
        sh.dstPort = htons(dstPort);
        sh.len = htons(sizeof(SUDPHeader));
        ret |= mPaths[i]->sendPacket(&p, mSendSocket);
        free(p.header.extensions);
        if (probeNum > SUDP_PROBE_WINDOW && mLastProbeAcked[i] < probeNum - SUDP_PROBE_WINDOW) {
            DEBUG("last probe acked on path %lu was %d, now %d\n", i, mLastProbeAcked[i], probeNum);
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
        pack_cmn_hdr((uint8_t *)&p.header.commonHeader, ADDR_IPV4_TYPE,
                ADDR_IPV4_TYPE, L4_UDP, 0, 0, 0);
        addProbeExtension(&p.header, probeNum, 1);
        SUDPPacket ack;
        p.payload = &ack;
        memset(&ack, 0, sizeof(ack));
        SUDPHeader &sh = ack.header;
        sh.srcPort = htons(sp->header.dstPort);
        sh.dstPort = htons(sp->header.srcPort);
        sh.len = htons(sizeof(sh));
        mPaths[index]->sendPacket(&p, mSendSocket);
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
        saddr.isd_as = ntohl(*(uint32_t *)(packet->header.srcAddr));
        // TODO: IPv6?
        saddr.host.addr_len = ADDR_IPV4_LEN;
        memcpy(&(saddr.host.addr), packet->header.srcAddr + ISD_AS_LEN, ADDR_IPV4_LEN);

        SUDPPath *p = (SUDPPath *)createPath(saddr, packet->header.path, packet->header.pathLen);
        p->setFirstHop(ADDR_IPV4_LEN, (uint8_t *)&(packet->firstHop));
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

void SUDPConnectionManager::setRemoteAddress(SCIONAddr addr)
{
    PathManager::setRemoteAddress(addr);
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

Path * SUDPConnectionManager::createPath(SCIONAddr &dstAddr, uint8_t *rawPath, int pathLen)
{
    PathParams params;
    params.localAddr = &mLocalAddr;
    params.dstAddr = &dstAddr;
    params.rawPath = rawPath;
    params.pathLen = pathLen;
    return new SUDPPath(this, &params);
}
