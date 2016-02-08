#include <arpa/inet.h>

#include "ConnectionManager.h"
#include "Extensions.h"
#include "Path.h"
#include "Utils.h"

Path::Path(PathManager *manager, SCIONAddr &localAddr, SCIONAddr &dstAddr, uint8_t *rawPath, size_t pathLen)
    : mIndex(-1),
    mLocalAddr(localAddr),
    mDstAddr(dstAddr),
    mUp(false),
    mUsed(false),
    mValid(true),
    mProbeAttempts(0)
{
    mSocket = manager->getSocket();
    if (pathLen == 0) {
        // raw data is in daemon reply format
        uint8_t *ptr = rawPath;
        mPathLen = *rawPath * 8;
        ptr++;
        if (mPathLen == 0) {
            // empty path
            mPath = NULL;
            mFirstHop.addrLen = dstAddr.host.addrLen;
            memcpy(mFirstHop.addr, dstAddr.host.addr, mFirstHop.addrLen);
            mFirstHop.port = SCION_UDP_EH_DATA_PORT;
            mMTU = SCION_DEFAULT_MTU;
        } else {
            mPath = (uint8_t *)malloc(mPathLen);
            memcpy(mPath, ptr, mPathLen);
            ptr += mPathLen;
            // TODO: Don't assume IPv4
            mFirstHop.addrLen = SCION_HOST_ADDR_LEN;
            memcpy(mFirstHop.addr, ptr, SCION_HOST_ADDR_LEN);
            ptr += mFirstHop.addrLen;
            mFirstHop.port = *(uint16_t *)ptr;
            ptr += 2;
#ifdef BYPASS_ROUTERS
            mFirstHop.addrLen = dstAddr.host.addrLen;
            memcpy(mFirstHop.addr, dstAddr.host.addr, mFirstHop.addrLen);
            mFirstHop.port = SCION_UDP_EH_DATA_PORT;
#endif
            mMTU = *(uint16_t *)ptr;
            if (mMTU == 0)
                mMTU = SCION_DEFAULT_MTU;
            ptr += 2;
            int interfaces = *ptr;
            ptr++;
            for (int i = 0; i < interfaces; i++) {
                SCIONInterface sif;
                uint32_t isd_ad = *(uint32_t *)ptr;
                ptr += 4;
                sif.isd = isd_ad >> 20;
                sif.ad = isd_ad & 0xfffff;
                sif.interface = *(uint16_t *)ptr;
                ptr += 2;
                mInterfaces.push_back(sif);
            }
        }
    } else {
        // raw data contains path only
        mPathLen = pathLen;
        mPath = (uint8_t *)malloc(mPathLen);
        memcpy(mPath, rawPath, mPathLen);
        mMTU = SCION_DEFAULT_MTU;
    }
    gettimeofday(&mLastSendTime, NULL);
    pthread_mutex_init(&mMutex, NULL);
}

Path::~Path()
{
    if (mPath) {
        free(mPath);
        mPath = NULL;
    }
    pthread_mutex_destroy(&mMutex);
}

int Path::send(SCIONPacket *packet, int sock)
{
    return 0;
}

void Path::handleTimeout(struct timeval *current)
{
}

int Path::timeUntilReady()
{
    return 0;
}

int Path::getPayloadLen(bool ack)
{
    return 0;
}

int Path::getETA(SCIONPacket *packet)
{
    return mState->timeUntilReady() + mState->estimatedRTT() +
        mState->getLossRate() * (mState->getRTO() + mState->estimatedRTT());
}

int Path::getRTT()
{
    return mState->estimatedRTT();
}

int Path::getRTO()
{
    return mState->getRTO();
}

int Path::getMTU()
{
    return mMTU;
}

double Path::getLossRate()
{
    return mState->getLossRate();
}

long Path::getIdleTime(struct timeval *current)
{
    return elapsedTime(&mLastSendTime, current);
}

int Path::getIndex()
{
    return mIndex;
}

void Path::setIndex(int index)
{
    mIndex = index;
}

void Path::setRawPath(uint8_t *path, int len)
{
    free(mPath);
    mPath = (uint8_t *)malloc(len);
    memcpy(mPath, path, len);
}

void Path::setInterfaces(uint8_t *interfaces, size_t count)
{
    uint8_t *ptr;
    mInterfaces.clear();
    for (size_t i = 0; i < count; i++) {
        ptr = interfaces + SCION_IF_SIZE * i;
        SCIONInterface sif;
        uint32_t isd_ad = ntohl(*(uint32_t *)ptr);
        sif.isd = isd_ad >> 20;
        sif.ad = isd_ad & 0xfffff;
        sif.interface = ntohs(*(uint16_t *)(ptr + 4));
        mInterfaces.push_back(sif);
    }
}

std::vector<SCIONInterface> & Path::getInterfaces()
{
    return mInterfaces;
}

bool Path::isUp()
{
    bool ret;
    pthread_mutex_lock(&mMutex);
    ret = mUp;
    pthread_mutex_unlock(&mMutex);
    return ret;
}

void Path::setUp()
{
    pthread_mutex_lock(&mMutex);
    mUp = true;
    mValid = true;
    mProbeAttempts = 0;
    pthread_mutex_unlock(&mMutex);
}

bool Path::isUsed()
{
    bool ret;
    pthread_mutex_lock(&mMutex);
    ret = mUsed;
    pthread_mutex_unlock(&mMutex);
    return ret;
}

void Path::setUsed(bool used)
{
    pthread_mutex_lock(&mMutex);
    mUsed = used;
    pthread_mutex_unlock(&mMutex);
}

bool Path::isValid()
{
    bool ret;
    pthread_mutex_lock(&mMutex);
    ret = mValid;
    pthread_mutex_unlock(&mMutex);
    return ret;
}

void Path::setFirstHop(int len, uint8_t *addr)
{
#ifdef BYPASS_ROUTERS
    mFirstHop.addrLen = len;
    memcpy(mFirstHop.addr, addr, len);
    mFirstHop.port = SCION_UDP_EH_DATA_PORT;
#else
    mFirstHop.addrLen = len;
    memcpy(mFirstHop.addr, addr, len);
    mFirstHop.port = SCION_UDP_PORT;
#endif
}

bool Path::didTimeout(struct timeval *current)
{
    return false;
}

bool Path::usesSameInterfaces(uint8_t *interfaces, size_t count)
{
#ifdef SIMULATOR
    return false;
#else
    if (count != mInterfaces.size())
        return false;
    for (size_t i = 0; i < count; i++) {
        SCIONInterface sif = mInterfaces[i];
        uint8_t *ptr = interfaces + i * SCION_IF_SIZE;
        uint32_t isd_ad = ntohl(*(uint32_t *)ptr);
        uint16_t interface = ntohs(*(uint16_t *)(ptr + 4));
        if ((isd_ad >> 20) != sif.isd || (isd_ad & 0xfffff) != sif.ad ||
                interface != sif.interface)
            return false;
    }
    return true;
#endif
}

bool Path::isSamePath(uint8_t *path, size_t len)
{
    if (len != mPathLen)
        return false;

    for (size_t i = 0; i < mPathLen; i++) {
        if (path[i] != mPath[i])
            return false;
    }
    return true;
}

void Path::getStats(SCIONStats *stats)
{
}

void Path::copySCIONHeader(uint8_t *bufptr, SCIONHeader *sh)
{
    SCIONCommonHeader *sch = &sh->commonHeader;
    uint8_t *start = bufptr;
    uint8_t srcLen = SCION_ISD_AD_LEN + mLocalAddr.host.addrLen;
    uint8_t dstLen = SCION_ISD_AD_LEN + mDstAddr.host.addrLen;
    // SCION common header
    memcpy(bufptr, sch, sizeof(*sch));
    bufptr += sizeof(*sch);
    // src/dst SCION addresses
    *(uint32_t *)bufptr = htonl(mLocalAddr.isd_ad);
    bufptr += SCION_ISD_AD_LEN;
    memcpy(bufptr, mLocalAddr.host.addr, mLocalAddr.host.addrLen);
    bufptr += mLocalAddr.host.addrLen;
    memcpy(sh->srcAddr, bufptr - srcLen, srcLen);
    *(uint32_t *)bufptr = htonl(mDstAddr.isd_ad);
    bufptr += SCION_ISD_AD_LEN;
    memcpy(bufptr, mDstAddr.host.addr, mDstAddr.host.addrLen);
    bufptr += mDstAddr.host.addrLen;
    memcpy(sh->dstAddr, bufptr - dstLen, dstLen);

    if (mPathLen == 0)
        return;

    // path
    memcpy(bufptr, mPath, mPathLen);
    bufptr += mPathLen;

    uint8_t *hof = start + sch->currentOF;
    if (*hof == XOVR_POINT)
        ((SCIONCommonHeader *)(start))->currentOF += 8;
}

// SSP

SSPPath::SSPPath(SSPConnectionManager *manager, SCIONAddr &localAddr, SCIONAddr &dstAddr, uint8_t *rawPath, size_t pathLen)
    : Path(manager, localAddr, dstAddr, rawPath, pathLen),
    mManager(manager),
    mTotalReceived(0),
    mTotalSent(0),
    mTotalAcked(0),
    mTimeoutCount(0)
{
    mState = new CUBICPathState(SCION_DEFAULT_RTT, mMTU);

    gettimeofday(&mLastLossTime, NULL);

    pthread_mutex_init(&mTimeMutex, NULL);
    pthread_mutex_init(&mWindowMutex, NULL);
    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_REALTIME);
    pthread_cond_init(&mWindowCond, &ca);
}

SSPPath::~SSPPath()
{
    if (mState) {
        delete mState;
        mState = NULL;
    }
    pthread_mutex_destroy(&mTimeMutex);
    pthread_mutex_destroy(&mWindowMutex);
    pthread_cond_destroy(&mWindowCond);
}

uint8_t * SSPPath::copySSPPacket(SSPPacket *sp, uint8_t *bufptr, bool probe)
{
    SSPHeader &sh = sp->header;
    memcpy(bufptr, &sh, sizeof(SSPHeader));
    bufptr += sizeof(SSPHeader);
    if (sh.flags & SSP_WINDOW) {
        *(uint32_t *)bufptr = sp->windowSize;
        bufptr += 4;
    }
    if ((sh.flags & SSP_ACK) && !probe) {
        memcpy(bufptr, &(sp->ack), sizeof(SSPAck));
        bufptr += sizeof(SSPAck);
    }
    if (sh.flags & SSP_NEW_PATH) {
        size_t count = mInterfaces.size();
        *bufptr++ = count;
        DEBUG("path %d: %lu interfaces\n", mIndex, count);
        for (size_t i = 0; i < count; i++) {
            SCIONInterface sif = mInterfaces[count - 1 - i];
            uint32_t isd_ad = (sif.isd << 20) | (sif.ad & 0xfffff);
            *(uint32_t *)bufptr = htonl(isd_ad);
            bufptr += 4;
            *(uint16_t *)bufptr = htons(sif.interface);
            bufptr += 2;
            DEBUG("(%d,%d):%d\n", sif.isd, sif.ad, sif.interface);
        }
    }
    // payload
    if (sp->len) {
        memcpy(bufptr, sp->data.get(), sp->len);
        bufptr += sp->len;
    }
    return bufptr;
}

void SSPPath::postProcessing(SCIONPacket *packet, bool probe)
{
    SSPPacket *sp = (SSPPacket *)(packet->payload);
    SSPHeader &sh = sp->header;

    packet->pathIndex = mIndex;
    packet->rto = mState->getRTO();
    DEBUG("using rto %d us for path %d\n", packet->rto, mIndex);
    if (!(sh.flags & SSP_ACK) && !probe) {
        mState->handleSend(be64toh(sh.offset));
        mTotalSent++;
        pthread_mutex_lock(&mTimeMutex);
        gettimeofday(&mLastSendTime, NULL);
        packet->sendTime = mLastSendTime;
        pthread_mutex_unlock(&mTimeMutex);
        mManager->didSend(packet);
        DEBUG("%ld.%06ld: packet %lu(%p) sent on path %d: %d/%d packets in flight\n",
                mLastSendTime.tv_sec, mLastSendTime.tv_usec,
                be64toh(sh.offset), packet, mIndex, mState->packetsInFlight(), mState->window());
    } else if (probe) {
        mProbeAttempts++;
        if (mProbeAttempts >= SSP_PROBE_ATTEMPTS) {
            pthread_mutex_lock(&mMutex);
            mValid = false;
            pthread_mutex_unlock(&mMutex);
        }
    }
}

int SSPPath::send(SCIONPacket *packet, int sock)
{
    pthread_mutex_lock(&mMutex);
    bool wasValid = mValid;
    int acked = mTotalAcked;
    pthread_mutex_unlock(&mMutex);
    bool sendInterfaces = false;
    SSPPacket *sp = (SSPPacket *)(packet->payload);
    SSPHeader &sh = sp->header;
    if (acked == 0 && !(sh.flags & SSP_ACK)) {
        DEBUG("no packets sent on this path yet\n");
        DEBUG("interface list: %lu bytes\n", mInterfaces.size() * SCION_IF_SIZE + 1);
        sh.flags |= SSP_NEW_PATH;
        sh.headerLen += mInterfaces.size() * SCION_IF_SIZE + 1;
        sendInterfaces = true;
    }

    bool probe = findProbeExtension(&packet->header) != NULL;

    SCIONCommonHeader &ch = packet->header.commonHeader;
    ch.headerLen = sizeof(ch) + 2 * SCION_ADDR_LEN + mPathLen;
    uint16_t totalLen = ch.headerLen + sh.headerLen + sp->len;
    SCIONExtension *ext = packet->header.extensions;
    while (ext != NULL) {
        totalLen += getHeaderLen(ext);
        ext = ext->nextExt;
    }
    ch.totalLen = htons(totalLen);

    uint8_t *buf = (uint8_t *)malloc(totalLen);
    uint8_t *bufptr = buf;
    copySCIONHeader(bufptr, &packet->header);
    bufptr += ch.headerLen;
    bufptr = packExtensions(&packet->header, bufptr);
    bufptr = copySSPPacket(sp, bufptr, probe);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(mFirstHop.port);
    memcpy(&sa.sin_addr, mFirstHop.addr, mFirstHop.addrLen);
    sendto(sock, buf, totalLen, 0, (struct sockaddr *)&sa, sizeof(sa));
    free(buf);
    DEBUG("sent to first hop %s:%d\n", inet_ntoa(sa.sin_addr), mFirstHop.port);

    if (sendInterfaces) {
        sh.flags &= ~SSP_NEW_PATH;
        sh.headerLen -= mInterfaces.size() * SCION_IF_SIZE + 1;
    }

    postProcessing(packet, probe);

    int ret = 0;

    pthread_mutex_lock(&mMutex);
    if (wasValid && !mValid)
        ret = 1;
    pthread_mutex_unlock(&mMutex);
    return ret;
}

int SSPPath::handleData(SCIONPacket *packet)
{
    mTotalReceived++;
    return 0;
}

int SSPPath::handleAck(SCIONPacket *packet, bool rttSample)
{
    SSPPacket *sp = (SSPPacket *)(packet->payload);
    SSPAck &ack = sp->ack;
    DEBUG("path %d: packet %lu acked, %d packets in flight\n",
            mIndex, ack.L + ack.I, mState->packetsInFlight() - 1);
    int rtt = elapsedTime(&(packet->sendTime), &(packet->arrivalTime));
    if (!rttSample)
        rtt = 0;
    pthread_mutex_lock(&mWindowMutex);
    mState->addRTTSample(rtt, ack.L + ack.I);
    pthread_mutex_unlock(&mWindowMutex);
    if (mState->isWindowBased())
        pthread_cond_broadcast(&mWindowCond);
    pthread_mutex_lock(&mMutex);
    mTimeoutCount = 0;
    if (rtt > 0) // don't count acks on other paths
        mTotalAcked++;
    pthread_mutex_unlock(&mMutex);
    return 0;
}

void SSPPath::handleDupAck()
{
    mState->handleDupAck();
}

void SSPPath::handleTimeout(struct timeval *current)
{
    DEBUG("path %d: %d packets in flight, %ld us without activity\n",
            mIndex, mState->packetsInFlight(), elapsedTime(&mLastSendTime, current));
    DEBUG("timeout on path %d\n", mIndex);
    mState->handleTimeout();
    mTimeoutCount++;
    if (mTimeoutCount > SSP_MAX_RETRIES)
        mUp = false;
}

void SSPPath::addLoss(uint64_t packetNum)
{
    DEBUG("loss event on path %d\n", mIndex);
    pthread_mutex_lock(&mWindowMutex);
    mState->addLoss(packetNum);
    pthread_mutex_unlock(&mWindowMutex);
    if (mState->isWindowBased())
        pthread_cond_broadcast(&mWindowCond);
}

void SSPPath::addRetransmit()
{
    struct timeval t;
    gettimeofday(&t, NULL);
    if (elapsedTime(&mLastLossTime, &t) < mState->estimatedRTT())
        return;
    mLastLossTime = t;
    mState->addRetransmit();
}

bool SSPPath::didTimeout(struct timeval *current)
{
    pthread_mutex_lock(&mTimeMutex);
    int elapsed = elapsedTime(&mLastSendTime, current);
    bool res =  mState->packetsInFlight() > 0 &&
                elapsed > mState->getRTO();
    pthread_mutex_unlock(&mTimeMutex);
    return res;
}

int SSPPath::timeUntilReady()
{
    return mState->timeUntilReady();
}

int SSPPath::getPayloadLen(bool ack)
{
    int hlen = ack ? sizeof(SSPHeader) + sizeof(SSPAck) : sizeof(SSPHeader);
    return mMTU - (28 + sizeof(SCIONCommonHeader) + 2 * SCION_ADDR_LEN + mPathLen + hlen);
}

void SSPPath::setIndex(int index)
{
    Path::setIndex(index);
    mState->setIndex(index);
}

void SSPPath::setRemoteWindow(uint32_t window)
{
    mState->setRemoteWindow(window / mMTU);
}

void SSPPath::getStats(SCIONStats *stats)
{
    if (!(mTotalReceived > 0 || mTotalAcked > 0))
        return;
    stats->exists[mIndex] = 1;
    stats->receivedPackets[mIndex] = mTotalReceived;
    stats->sentPackets[mIndex] = mTotalSent;
    stats->ackedPackets[mIndex] = mTotalAcked;
    stats->rtts[mIndex] = mState->estimatedRTT();
    stats->lossRates[mIndex] = mState->getLossRate();
    if (!mUp)
        stats->lossRates[mIndex] = 1.0;
    size_t interfaces = mInterfaces.size();
    if (interfaces > 0) {
        stats->ifCounts[mIndex] = interfaces;
        stats->ifLists[mIndex] =
            (SCIONInterface *)malloc(sizeof(SCIONInterface) * interfaces);
        if (!stats->ifLists[mIndex]) {
            stats->ifCounts[mIndex] = 0;
        } else {
            for (size_t i = 0; i < interfaces; i++)
                stats->ifLists[mIndex][i] = mInterfaces[i];
        }
    }
}

// SUDP

SUDPPath::SUDPPath(SUDPConnectionManager *manager, SCIONAddr &localAddr, SCIONAddr &dstAddr, uint8_t *rawPath, size_t pathLen)
    : Path(manager, localAddr, dstAddr, rawPath, pathLen)
{
}

SUDPPath::~SUDPPath()
{
}

int SUDPPath::send(SCIONPacket *packet, int sock)
{
    int res;
    SCIONHeader &sh = packet->header;
    SCIONCommonHeader &sch = packet->header.commonHeader;
    SUDPPacket *sp = (SUDPPacket *)(packet->payload);
    sch.headerLen = sizeof(sch) + 2 * SCION_ADDR_LEN + mPathLen;

    uint16_t totalLen = sch.headerLen + sizeof(SUDPHeader) + sp->payloadLen;
    SCIONExtension *ext = packet->header.extensions;
    while (ext != NULL) {
        totalLen += getHeaderLen(ext);
        ext = ext->nextExt;
    }
    sch.totalLen = htons(totalLen);

    uint8_t *buf = (uint8_t *)malloc(totalLen);
    uint8_t *bufptr = buf;
    copySCIONHeader(bufptr, &sh);
    bufptr += sch.headerLen;
    bufptr = packExtensions(&packet->header, bufptr);
    sp->header.checksum = htons(checksum(packet));
    // SUDP header
    memcpy(bufptr, &(sp->header), sizeof(SUDPHeader));
    bufptr += sizeof(SUDPHeader);
    // SUDP payload
    memcpy(bufptr, sp->payload, sp->payloadLen);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(mFirstHop.port);
    memcpy(&sa.sin_addr, mFirstHop.addr, mFirstHop.addrLen);
    res = sendto(sock, buf, ntohs(sch.totalLen), 0, (struct sockaddr *)&sa, sizeof(sa));
    DEBUG("packet sent to first hop %s:%d\n", inet_ntoa(sa.sin_addr), mFirstHop.port);
    free(buf);

    return res;
}

int SUDPPath::getPayloadLen(bool ack)
{
    return mMTU -
        (28 + sizeof(SCIONCommonHeader) + 2 * SCION_ADDR_LEN
         + mPathLen + sizeof(SUDPHeader));
}

void SUDPPath::handleTimeout(struct timeval *current)
{
    mUp = false;
}
