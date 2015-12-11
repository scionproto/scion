#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <syscall.h>

#include "Path.h"
#include "ConnectionManager.h"
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
}

Path::~Path()
{
    if (mPath) {
        free(mPath);
        mPath = NULL;
    }
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

int Path::getMTU()
{
    return mMTU;
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

bool Path::isUp()
{
    return mUp;
}

void Path::setUp()
{
    mUp = true;
    mValid = true;
    mProbeAttempts = 0;
}

bool Path::isUsed()
{
    return mUsed;
}

void Path::setUsed(bool used)
{
    mUsed = used;
}

bool Path::isValid()
{
    return mValid;
}

void Path::setFirstHop(int len, uint8_t *addr)
{
    mFirstHop.addrLen = len;
    memcpy(mFirstHop.addr, addr, len);
    mFirstHop.port = SCION_UDP_PORT;
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

void Path::copySCIONHeader(uint8_t *bufptr, SCIONCommonHeader *ch)
{
    uint8_t *start = bufptr;
    // SCION common header
    memcpy(bufptr, ch, sizeof(*ch));
    bufptr += sizeof(*ch);
    // src/dst SCION addresses
    *(uint32_t *)bufptr = htonl(mLocalAddr.isd_ad);
    bufptr += SCION_ISD_AD_LEN;
    memcpy(bufptr, mLocalAddr.host.addr, mLocalAddr.host.addrLen);
    bufptr += mLocalAddr.host.addrLen;
    *(uint32_t *)bufptr = htonl(mDstAddr.isd_ad);
    bufptr += SCION_ISD_AD_LEN;
    memcpy(bufptr, mDstAddr.host.addr, mDstAddr.host.addrLen);
    bufptr += mDstAddr.host.addrLen;
    // path
    memcpy(bufptr, mPath, mPathLen);
    bufptr += mPathLen;

    uint8_t *hof = start + ch->currentOF;
    if (*hof == XOVR_POINT)
        ((SCIONCommonHeader *)(start))->currentOF += 8;
}

// SDAMP

SDAMPPath::SDAMPPath(SDAMPConnectionManager *manager, SCIONAddr &localAddr, SCIONAddr &dstAddr, uint8_t *rawPath, size_t pathLen)
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

SDAMPPath::~SDAMPPath()
{
    if (mState) {
        delete mState;
        mState = NULL;
    }
    pthread_mutex_destroy(&mTimeMutex);
    pthread_mutex_destroy(&mWindowMutex);
    pthread_cond_destroy(&mWindowCond);
}

int SDAMPPath::send(SCIONPacket *packet, int sock)
{
    bool wasValid = mValid;
    SDAMPPacket *sp = (SDAMPPacket *)(packet->payload);
    SDAMPHeader &sh = sp->header;
    if (mTotalAcked == 0 && !(sh.flags & SDAMP_ACK)) {
        DEBUG("no packets sent on this path yet\n");
        sh.flags |= SDAMP_NEW_PATH;
        sh.headerLen += mInterfaces.size() * SCION_IF_SIZE + 1;
    }

    size_t readyTime;
    if (!(sh.flags & SDAMP_ACK || sh.flags & SDAMP_PROBE)) {
        pthread_mutex_lock(&mWindowMutex);
        while ((readyTime = mState->timeUntilReady()) > 0) {
            struct timespec t;
            clock_gettime(CLOCK_REALTIME, &t);
            DEBUG("current time = %ld.%09ld\n", t.tv_sec, t.tv_nsec);
            DEBUG("path %d: %lu us until ready to send (%d in flight)\n", mIndex, readyTime, mState->packetsInFlight());
            struct timeval current;
            current.tv_sec = t.tv_sec;
            current.tv_usec = t.tv_nsec / 1000;
            if (elapsedTime(&mLastSendTime, &current) > mState->getRTO()) {
                DEBUG("path %d: %lu since last send, abort packet %lu\n",
                        mIndex, elapsedTime(&mLastSendTime, &current), be64toh(sh.packetNum));
                pthread_mutex_unlock(&mWindowMutex);
                mManager->abortSend(packet);
                return -1;
            }
            size_t nsec = t.tv_nsec + readyTime * 1000;
            while (nsec >= 1000000000) {
                nsec -= 1000000000;
                t.tv_sec++;
            }
            t.tv_nsec = nsec;
            pthread_cond_timedwait(&mWindowCond, &mWindowMutex, &t);
        }
        pthread_mutex_unlock(&mWindowMutex);
    }

    SCIONCommonHeader &ch = packet->header.commonHeader;
    ch.headerLen = sizeof(ch) + 2 * SCION_ADDR_LEN + mPathLen;
    uint16_t totalLen = ch.headerLen + sh.headerLen + sp->len;
    ch.totalLen = htons(totalLen);

    uint8_t *buf = (uint8_t *)malloc(totalLen);
    memset(buf, 0, totalLen);
    uint8_t *bufptr = buf;
    copySCIONHeader(bufptr, &ch);
    bufptr += ch.headerLen;
    // SDAMP header
    memcpy(bufptr, &sh, sizeof(SDAMPHeader));
    bufptr += sizeof(SDAMPHeader);
    if (sh.flags & SDAMP_INIT) {
        *(uint32_t *)bufptr = sp->windowSize;
        bufptr += 4;
    }
    if ((sh.flags & SDAMP_ACK) && !(sh.flags & SDAMP_PROBE)) {
        memcpy(bufptr, &(sp->ack), sizeof(SDAMPAck));
        bufptr += sizeof(SDAMPAck);
    }
    if (sh.flags & SDAMP_NEW_PATH) {
        size_t count = mInterfaces.size();
        *bufptr++ = count;
        for (size_t i = 0; i < count; i++) {
            SCIONInterface sif = mInterfaces[count - 1 - i];
            uint32_t isd_ad = (sif.isd << 20) | (sif.ad & 0xfffff);
            *(uint32_t *)bufptr = htonl(isd_ad);
            bufptr += 4;
            *(uint16_t *)bufptr = htons(sif.interface);
            bufptr += 2;
        }
    }
    // payload
    if (sp->len > 0)
        memcpy(bufptr, sp->data, sp->len);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(mFirstHop.port);
    memcpy(&sa.sin_addr, mFirstHop.addr, mFirstHop.addrLen);
    sendto(sock, buf, ntohs(ch.totalLen), 0, (struct sockaddr *)&sa, sizeof(sa));
    free(buf);
    DEBUG("sent to first hop %s:%d\n", inet_ntoa(sa.sin_addr), mFirstHop.port);

    if (mTotalSent == 0) {
        sh.flags &= ~SDAMP_NEW_PATH;
        sh.headerLen -= mInterfaces.size() * SCION_IF_SIZE + 1;
    }

    packet->pathIndex = mIndex;
    packet->rto = mState->getRTO();
    DEBUG("using rto %d us for path %d\n", packet->rto, mIndex);
    if (!(sh.flags & SDAMP_ACK || sh.flags & SDAMP_PROBE)) {
        mState->handleSend(be64toh(sh.packetNum));
        mTotalSent++;
        pthread_mutex_lock(&mTimeMutex);
        gettimeofday(&mLastSendTime, NULL);
        packet->sendTime = mLastSendTime;
        pthread_mutex_unlock(&mTimeMutex);
        mManager->didSend(packet);
        DEBUG("%ld.%06ld: packet %ld sent on path %d: %d packets in flight\n", mLastSendTime.tv_sec, mLastSendTime.tv_usec, be64toh(sh.packetNum), mIndex, mState->packetsInFlight());
    } else if (sh.flags & SDAMP_PROBE) {
        mProbeAttempts++;
        if (mProbeAttempts >= SDAMP_PROBE_ATTEMPTS)
            mValid = false;
    }

    if (wasValid && !mValid)
        return 1;
    return 0;

}

int SDAMPPath::handleData(SCIONPacket *packet)
{
    mTotalReceived++;
    return 0;
}

int SDAMPPath::handleAck(SCIONPacket *packet, bool rttSample)
{
    DEBUG("incoming ack on path %d: %d packets in flight\n", mIndex, mState->packetsInFlight() - 1);
    SDAMPPacket *sp = (SDAMPPacket *)(packet->payload);
    if (sp->header.flags & SDAMP_INIT)
        mState->setRemoteWindow(sp->windowSize / mMTU);
    int rtt = elapsedTime(&(packet->sendTime), &(packet->arrivalTime));
    if (!rttSample)
        rtt = 0;
    DEBUG("path %d: ack for packet %lu with rtt %d\n", mIndex, sp->header.packetNum, rtt);
    pthread_mutex_lock(&mWindowMutex);
    mState->addRTTSample(rtt, sp->header.packetNum);
    pthread_mutex_unlock(&mWindowMutex);
    if (mState->isWindowBased())
        pthread_cond_broadcast(&mWindowCond);
    mTimeoutCount = 0;
    mTotalAcked++;
    return 0;
}

void SDAMPPath::handleDupAck()
{
    mState->handleDupAck();
}

void SDAMPPath::handleTimeout(struct timeval *current)
{
    DEBUG("path %d: %d packets in flight, %ld us without activity\n",
            mIndex, mState->packetsInFlight(), elapsedTime(&mLastSendTime, current));
    DEBUG("timeout on path %d\n", mIndex);
    mState->handleTimeout();
    mTimeoutCount++;
    if (mTimeoutCount > SDAMP_MAX_RETRIES)
        mUp = false;
}

void SDAMPPath::addLoss(uint64_t packetNum)
{
    DEBUG("loss event on path %d\n", mIndex);
    pthread_mutex_lock(&mWindowMutex);
    mState->addLoss(packetNum);
    pthread_mutex_unlock(&mWindowMutex);
    if (mState->isWindowBased())
        pthread_cond_broadcast(&mWindowCond);
}

void SDAMPPath::addRetransmit()
{
    struct timeval t;
    gettimeofday(&t, NULL);
    if (elapsedTime(&mLastLossTime, &t) < mState->estimatedRTT())
        return;
    mLastLossTime = t;
    mState->addRetransmit();
}

bool SDAMPPath::didTimeout(struct timeval *current)
{
    pthread_mutex_lock(&mTimeMutex);
    int elapsed = elapsedTime(&mLastSendTime, current);
    bool res =  mState->packetsInFlight() > 0 &&
                elapsed > mState->getRTO();
    pthread_mutex_unlock(&mTimeMutex);
    return res;
}

int SDAMPPath::timeUntilReady()
{
    return mState->timeUntilReady();
}

int SDAMPPath::getPayloadLen(bool ack)
{
    int hlen = ack ? sizeof(SDAMPHeader) + sizeof(SDAMPAck) : sizeof(SDAMPHeader);
    return mMTU - (28 + sizeof(SCIONCommonHeader) + 2 * SCION_ADDR_LEN + mPathLen + hlen);
}

int SDAMPPath::getETA(SCIONPacket *packet)
{
    return mState->timeUntilReady() + mState->estimatedRTT() +
        mState->getLossRate() * (mState->getRTO() + mState->estimatedRTT());
}

int SDAMPPath::getRTT()
{
    return mState->estimatedRTT();
}

int SDAMPPath::getRTO()
{
    return mState->getRTO();
}

void SDAMPPath::setIndex(int index)
{
    Path::setIndex(index);
    mState->setIndex(index);
}

void SDAMPPath::setRemoteWindow(uint32_t window)
{
    mState->setRemoteWindow(window / mMTU);
}

void SDAMPPath::getStats(SCIONStats *stats)
{
    if (!(mTotalReceived > 0 || mTotalAcked > 0))
        return;
    stats->exists[mIndex] = true;
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

// SSP

SSPPath::SSPPath(SSPConnectionManager *manager, SCIONAddr &localAddr, SCIONAddr &dstAddr, uint8_t *rawPath, size_t pathLen)
    : SDAMPPath(manager, localAddr, dstAddr, rawPath, pathLen)
{
}

SSPPath::~SSPPath()
{
}

int SSPPath::send(SCIONPacket *packet, int sock)
{
    bool wasValid = mValid;
    bool sendInterfaces = false;
    SSPPacket *sp = (SSPPacket *)(packet->payload);
    SSPHeader &sh = sp->header;
    if (mTotalAcked == 0 && !(sh.flags & SSP_ACK)) {
        DEBUG("no packets sent on this path yet\n");
        DEBUG("interface list: %lu bytes\n", mInterfaces.size() * SCION_IF_SIZE + 1);
        sh.flags |= SSP_NEW_PATH;
        sh.headerLen += mInterfaces.size() * SCION_IF_SIZE + 1;
        sendInterfaces = true;
    }

    int readyTime;
    if (!(sh.flags & SSP_ACK || sh.flags & SSP_PROBE)) {
        pthread_mutex_lock(&mWindowMutex);
        while ((readyTime = mState->timeUntilReady()) > 0) {
            struct timespec t;
            clock_gettime(CLOCK_REALTIME, &t);
            DEBUG("current time = %ld.%09ld\n", t.tv_sec, t.tv_nsec);
            DEBUG("path %d: %d us until ready to send (%d in flight)\n", mIndex, readyTime, mState->packetsInFlight());
            struct timeval current;
            current.tv_sec = t.tv_sec;
            current.tv_usec = t.tv_nsec / 1000;
            if (elapsedTime(&mLastSendTime, &current) > mState->getRTO()) {
                DEBUG("path %d: loss occurred, abort send packet %u\n", mIndex, be64toh(sh.offset));
                pthread_mutex_unlock(&mWindowMutex);
                mManager->abortSend(packet);
                if (sendInterfaces) {
                    sh.flags &= ~SSP_NEW_PATH;
                    sh.headerLen -= mInterfaces.size() * SCION_IF_SIZE + 1;
                }
                return -1;
            }
            long nsec = t.tv_nsec + readyTime * 1000;
            while (nsec >= 1000000000) {
                nsec -= 1000000000;
                t.tv_sec++;
            }
            t.tv_nsec = nsec;
            pthread_cond_timedwait(&mWindowCond, &mWindowMutex, &t);
        }
        pthread_mutex_unlock(&mWindowMutex);
    }

    SCIONCommonHeader &ch = packet->header.commonHeader;
    ch.headerLen = sizeof(ch) + 2 * SCION_ADDR_LEN + mPathLen;
    uint16_t totalLen = ch.headerLen + sh.headerLen + sp->len;
    ch.totalLen = htons(totalLen);

    uint8_t *buf = (uint8_t *)malloc(totalLen);
    uint8_t *bufptr = buf;
    copySCIONHeader(bufptr, &ch);
    bufptr += ch.headerLen;
    // SSP header
    memcpy(bufptr, &sh, sizeof(SSPHeader));
    bufptr += sizeof(SSPHeader);
    if (sh.flags & SSP_WINDOW) {
        *(uint32_t *)bufptr = sp->windowSize;
        bufptr += 4;
    }
    if ((sh.flags & SSP_ACK) && !(sh.flags & SSP_PROBE)) {
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
    DEBUG("path %d: %lu bytes of payload at offset %lu\n",
            mIndex, sp->len, bufptr - buf);
    memcpy(bufptr, sp->data, sp->len);

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

    packet->pathIndex = mIndex;
    packet->rto = mState->getRTO();
    DEBUG("using rto %d us for path %d\n", packet->rto, mIndex);
    if (!(sh.flags & SSP_ACK || sh.flags & SSP_PROBE)) {
        mState->handleSend(be64toh(sh.offset));
        mTotalSent++;
        pthread_mutex_lock(&mTimeMutex);
        gettimeofday(&mLastSendTime, NULL);
        packet->sendTime = mLastSendTime;
        pthread_mutex_unlock(&mTimeMutex);
        mManager->didSend(packet);
        DEBUG("%ld.%06ld: packet %u sent on path %d: %d/%d packets in flight\n",
                mLastSendTime.tv_sec, mLastSendTime.tv_usec,
                be64toh(sh.offset), mIndex, mState->packetsInFlight(), mState->window());
    } else if (sh.flags & SSP_PROBE) {
        mProbeAttempts++;
        if (mProbeAttempts >= SDAMP_PROBE_ATTEMPTS)
            mValid = false;
    }

    if (wasValid && !mValid)
        return 1;
    return 0;
}

int SSPPath::getPayloadLen(bool ack)
{
    int hlen = ack ? sizeof(SSPHeader) + sizeof(SSPAck) : sizeof(SSPHeader);
    return mMTU - (28 + sizeof(SCIONCommonHeader) + 2 * SCION_ADDR_LEN + mPathLen + hlen);
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
    mTimeoutCount = 0;
    mTotalAcked++;
    return 0;
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
    SCIONCommonHeader &sch = packet->header.commonHeader;
    SUDPPacket *sp = (SUDPPacket *)(packet->payload);
    sch.headerLen = sizeof(sch) + 2 * SCION_ADDR_LEN + mPathLen;
    int totalLen = sch.headerLen + sizeof(SUDPHeader) + sp->payloadLen;
    sch.totalLen = htons(totalLen);
    uint8_t *buf = (uint8_t *)malloc(totalLen);
    uint8_t *bufptr = buf;
    copySCIONHeader(bufptr, &sch);
    bufptr += sch.headerLen;
    // SUDP header
    memcpy(bufptr, &(sp->header), sizeof(SUDPHeader));
    bufptr += sizeof(SUDPHeader);
    // SUDP payload
    if (!(sp->header.flags & SUDP_PROBE))
        memcpy(bufptr, sp->payload, sp->payloadLen);
    else
        memcpy(bufptr, &(sp->payload), 4);

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
