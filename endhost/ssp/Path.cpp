#include <arpa/inet.h>

#include "ConnectionManager.h"
#include "Extensions.h"
#include "Path.h"
#include "Utils.h"

Path::Path(PathManager *manager, PathParams *params)
    : mIndex(-1),
    mLocalAddr(*(params->localAddr)),
    mDstAddr(*(params->dstAddr)),
    mUp(false),
    mUsed(false),
    mValid(true),
    mProbeAttempts(0),
    mManager(manager)
{
    mSocket = manager->getSocket();
    if (params->pathLen == 0) {
        // raw data is in daemon reply format
        uint8_t *ptr = params->rawPath;
        if (ptr) {
            mPathLen = *ptr * 8;
            ptr++;
        } else {
            mPathLen = 0;
        }
        if (mPathLen == 0) {
            // empty path
            mPath = NULL;
            mFirstHop.addr_len = mDstAddr.host.addr_len;
            memcpy(mFirstHop.addr, mDstAddr.host.addr, mFirstHop.addr_len);
            mFirstHop.port = SCION_UDP_EH_DATA_PORT;
            mMTU = SCION_DEFAULT_MTU;
        } else {
            mPath = (uint8_t *)malloc(mPathLen);
            memcpy(mPath, ptr, mPathLen);
            ptr += mPathLen;
            // TODO: IPv6?
            mFirstHop.addr_len = ADDR_IPV4_LEN;
            memcpy(mFirstHop.addr, ptr, ADDR_IPV4_LEN);
            ptr += mFirstHop.addr_len;
            mFirstHop.port = ntohs(*(uint16_t *)ptr);
            ptr += 2;
#ifdef BYPASS_ROUTERS
            mFirstHop.addr_len = mDstAddr.host.addr_len;
            memcpy(mFirstHop.addr, mDstAddr.host.addr, mFirstHop.addr_len);
            mFirstHop.port = SCION_UDP_EH_DATA_PORT;
#endif
            mMTU = ntohs(*(uint16_t *)ptr);
            if (mMTU == 0)
                mMTU = SCION_DEFAULT_MTU;
            ptr += 2;
            int interfaces = *ptr;
            ptr++;
            for (int i = 0; i < interfaces; i++) {
                SCIONInterface sif;
                uint32_t isd_as = ntohl(*(uint32_t *)ptr);
                ptr += 4;
                sif.isd = isd_as >> 20;
                sif.as = isd_as & 0xfffff;
                sif.interface = ntohs(*(uint16_t *)ptr);
                ptr += 2;
                mInterfaces.push_back(sif);
            }
        }
    } else {
        // raw data contains path only
        mPathLen = params->pathLen;
        mPath = (uint8_t *)malloc(mPathLen);
        memcpy(mPath, params->rawPath, mPathLen);
        mMTU = SCION_DEFAULT_MTU;
    }
    gettimeofday(&mLastSendTime, NULL);
    pthread_mutex_init(&mMutex, NULL);

    switch (params->type) {
        case CC_CBR:
            mState = new CBRPathState(SCION_DEFAULT_RTT, mMTU);
            break;
        case CC_PCC:
            mState = new PCCPathState(SCION_DEFAULT_RTT, mMTU);
            break;
        case CC_RENO:
            mState = new RenoPathState(SCION_DEFAULT_RTT, mMTU);
            break;
        case CC_CUBIC:
        default:
            mState = new CUBICPathState(SCION_DEFAULT_RTT, mMTU);
            break;
    }
}

Path::~Path()
{
    if (mPath) {
        free(mPath);
        mPath = NULL;
    }
    pthread_mutex_destroy(&mMutex);
}

int Path::sendPacket(SCIONPacket *packet, int sock)
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
        ptr = interfaces + IF_TOTAL_LEN * i;
        SCIONInterface sif;
        uint32_t isd_as = ntohl(*(uint32_t *)ptr);
        sif.isd = isd_as >> 20;
        sif.as = isd_as & 0xfffff;
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
    mFirstHop.addr_len = len;
    memcpy(mFirstHop.addr, addr, len);
    mFirstHop.port = SCION_UDP_EH_DATA_PORT;
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
        uint8_t *ptr = interfaces + i * IF_TOTAL_LEN;
        uint32_t isd_as = ntohl(*(uint32_t *)ptr);
        uint16_t interface = ntohs(*(uint16_t *)(ptr + 4));
        if ((isd_as >> 20) != sif.isd || (isd_as & 0xfffff) != sif.as ||
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
    uint8_t srcLen = ISD_AS_LEN + mLocalAddr.host.addr_len;
    uint8_t dstLen = ISD_AS_LEN + mDstAddr.host.addr_len;
    // SCION common header
    memcpy(bufptr, sch, sizeof(*sch));
    bufptr += sizeof(*sch);
    // src/dst SCION addresses
    *(uint32_t *)bufptr = htonl(mLocalAddr.isd_as);
    bufptr += ISD_AS_LEN;
    memcpy(bufptr, mLocalAddr.host.addr, mLocalAddr.host.addr_len);
    bufptr += mLocalAddr.host.addr_len;
    memcpy(sh->srcAddr, bufptr - srcLen, srcLen);
    *(uint32_t *)bufptr = htonl(mDstAddr.isd_as);
    bufptr += ISD_AS_LEN;
    memcpy(bufptr, mDstAddr.host.addr, mDstAddr.host.addr_len);
    bufptr += mDstAddr.host.addr_len;
    memcpy(sh->dstAddr, bufptr - dstLen, dstLen);

    if (mPathLen == 0)
        return;

    // path
    memcpy(bufptr, mPath, mPathLen);
    bufptr += mPathLen;

    init_of_idx(start);
}

// SSP

SSPPath::SSPPath(SSPConnectionManager *manager, PathParams *params)
    : Path(manager, params),
    mTotalReceived(0),
    mTotalSent(0),
    mTotalAcked(0),
    mTimeoutCount(0)
{
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
            uint32_t isd_as = (sif.isd << 20) | (sif.as & 0xfffff);
            *(uint32_t *)bufptr = htonl(isd_as);
            bufptr += 4;
            *(uint16_t *)bufptr = htons(sif.interface);
            bufptr += 2;
            DEBUG("(%d,%d):%d\n", sif.isd, sif.as, sif.interface);
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

int SSPPath::sendPacket(SCIONPacket *packet, int sock)
{
    DEBUG("path %d: sendPacket\n", mIndex);
    pthread_mutex_lock(&mMutex);
    bool wasValid = mValid;
    int acked = mTotalAcked;
    pthread_mutex_unlock(&mMutex);
    bool sendInterfaces = false;
    SSPPacket *sp = (SSPPacket *)(packet->payload);
    SSPHeader &sh = sp->header;
    if (acked == 0 && !(sh.flags & SSP_ACK)) {
        DEBUG("no packets sent on this path yet\n");
        DEBUG("interface list: %lu bytes\n", mInterfaces.size() * IF_TOTAL_LEN + 1);
        sh.flags |= SSP_NEW_PATH;
        sh.headerLen += mInterfaces.size() * IF_TOTAL_LEN + 1;
        sendInterfaces = true;
    }

    bool probe = findProbeExtension(&packet->header) != NULL;

    SCIONCommonHeader &sch = packet->header.commonHeader;
    int src_len = get_src_len((uint8_t *)&sch) + ISD_AS_LEN;
    int dst_len = get_dst_len((uint8_t *)&sch) + ISD_AS_LEN;
    sch.header_len = sizeof(sch) + src_len + dst_len + mPathLen;
    uint16_t packet_len = sch.header_len + sh.headerLen + sp->len;
    SCIONExtension *ext = packet->header.extensions;
    while (ext != NULL) {
        packet_len += getHeaderLen(ext);
        ext = ext->nextExt;
    }
    sch.total_len = htons(packet_len);

    // TODO: Don't assume IPv4 (5 = 1 byte len + 4 byte addr)
    uint8_t *buf = (uint8_t *)malloc(packet_len);
    uint8_t *bufptr = buf;
    copySCIONHeader(bufptr, &packet->header);
    bufptr += sch.header_len;
    bufptr = packExtensions(&packet->header, bufptr);
    bufptr = copySSPPacket(sp, bufptr, probe);

    mManager->sendRawPacket(buf, packet_len, &mFirstHop);
    free(buf);

    if (sendInterfaces) {
        sh.flags &= ~SSP_NEW_PATH;
        sh.headerLen -= mInterfaces.size() * IF_TOTAL_LEN + 1;
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
    return mMTU - (28 + sizeof(SCIONCommonHeader) + 2 * (ISD_AS_LEN + MAX_HOST_ADDR_LEN) + mPathLen + hlen);
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

SUDPPath::SUDPPath(SUDPConnectionManager *manager, PathParams *params)
    : Path(manager, params)
{
}

SUDPPath::~SUDPPath()
{
}

int SUDPPath::sendPacket(SCIONPacket *packet, int sock)
{
    int res;
    SCIONHeader &sh = packet->header;
    SCIONCommonHeader &sch = packet->header.commonHeader;
    SUDPPacket *sp = (SUDPPacket *)(packet->payload);
    int src_len = get_src_len((uint8_t *)&sch) + ISD_AS_LEN;
    int dst_len = get_dst_len((uint8_t *)&sch) + ISD_AS_LEN;
    sch.header_len = sizeof(sch) + src_len + dst_len + mPathLen;

    uint16_t packet_len = sch.header_len + sizeof(SUDPHeader) + sp->payloadLen;
    SCIONExtension *ext = packet->header.extensions;
    while (ext != NULL) {
        packet_len += getHeaderLen(ext);
        ext = ext->nextExt;
    }
    sch.total_len = htons(packet_len);

    // TODO: Don't assume IPv4 (5 = 1 byte len + 4 byte addr)
    uint8_t *buf = (uint8_t *)malloc(packet_len);
    uint8_t *bufptr = buf;
    copySCIONHeader(bufptr, &sh);
    bufptr += sch.header_len;
    bufptr = packExtensions(&packet->header, bufptr);
    // SUDP header
    memcpy(bufptr, &(sp->header), sizeof(SUDPHeader));
    bufptr += sizeof(SUDPHeader);
    // SUDP payload
    memcpy(bufptr, sp->payload, sp->payloadLen);
    bufptr += sp->payloadLen;
    // Calculate checksum
    update_scion_udp_checksum(buf);

    res = mManager->sendRawPacket(buf, packet_len, &mFirstHop);
    free(buf);

    return res;
}

int SUDPPath::getPayloadLen(bool ack)
{
    return mMTU -
        (28 + sizeof(SCIONCommonHeader) + 2 * (ISD_AS_LEN + MAX_HOST_ADDR_LEN) +
         mPathLen + sizeof(SUDPHeader));
}

void SUDPPath::handleTimeout(struct timeval *current)
{
    mUp = false;
}
