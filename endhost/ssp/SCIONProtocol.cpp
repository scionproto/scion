#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <time.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <semaphore.h>
#include <fcntl.h>
#include <errno.h>

#include <algorithm>
#include <set>

#include "ProtocolConfigs.h"
#include "SCIONProtocol.h"
#include "Utils.h"

void * timerThread(void *arg)
{
    SCIONProtocol *p = (SCIONProtocol *)arg;
    while (p->isRunning()) {
        usleep(SCION_TIMER_INTERVAL);
        p->handleTimerEvent();
    }
    return NULL;
}

SCIONProtocol::SCIONProtocol(std::vector<SCIONAddr> &dstAddrs, short srcPort, short dstPort)
    : mSrcPort(srcPort),
    mDstPort(dstPort),
    mIsReceiver(false),
    mReadyToRead(false),
    mRunning(true),
    mDstAddrs(dstAddrs),
    mProbeNum(0)
{
    gettimeofday(&mLastProbeTime, NULL);
    mSocket = socket(AF_INET, SOCK_DGRAM, 0);
    pthread_mutex_init(&mReadMutex, NULL);
    pthread_cond_init(&mReadCond, NULL);
}

SCIONProtocol::SCIONProtocol(const SCIONProtocol &p)
    : mSocket(p.mSocket),
    mSrcPort(p.mSrcPort),
    mDstPort(p.mDstPort),
    mIsReceiver(false),
    mReadyToRead(false),
    mRunning(true),
    mDstAddrs(p.mDstAddrs)
{
    pthread_mutex_init(&mReadMutex, NULL);
    pthread_cond_init(&mReadCond, NULL);
}

SCIONProtocol::~SCIONProtocol()
{
    close(mSocket);
}

SCIONProtocol & SCIONProtocol::operator=(const SCIONProtocol &p)
{
    mSocket = p.mSocket;
    mSrcPort = p.mSrcPort;
    mDstPort = p.mDstPort;
    mIsReceiver = p.mIsReceiver;
    mReadyToRead = false;
    mRunning = p.mRunning;
    mDstAddrs = p.mDstAddrs;
    pthread_mutex_init(&mReadMutex, NULL);
    pthread_cond_init(&mReadCond, NULL);
    return *this;
}

int SCIONProtocol::send(uint8_t *buf, size_t len, DataProfile profile)
{
    return 0;
}

int SCIONProtocol::recv(uint8_t *buf, size_t len, SCIONAddr *srcAddr)
{
    return 0;
}

int SCIONProtocol::handlePacket(SCIONPacket *packet, uint8_t *buf)
{
    return 0;
}

void SCIONProtocol::handleTimerEvent()
{
}

bool SCIONProtocol::isReceiver()
{
    return mIsReceiver;
}

bool SCIONProtocol::isRunning()
{
    return mRunning;
}

void SCIONProtocol::setReceiver(bool receiver)
{
    mIsReceiver = receiver;
}

bool SCIONProtocol::claimPacket(SCIONPacket *packet, uint8_t *buf)
{
    return false;
}

void SCIONProtocol::createManager(std::vector<SCIONAddr> &dstAddrs)
{
}

void SCIONProtocol::start(SCIONPacket *packet, uint8_t *buf, int sock)
{
}

void SCIONProtocol::getStats(SCIONStats *stats)
{
}

bool SCIONProtocol::readyToRead()
{
    return false;
}

bool SCIONProtocol::readyToWrite()
{
    return false;
}

int SCIONProtocol::registerSelect(Notification *n, int mode)
{
    return 0;
}

void SCIONProtocol::deregisterSelect(int index)
{
}

// SSP

SSPProtocol::SSPProtocol(std::vector<SCIONAddr> &dstAddrs, short srcPort, short dstPort)
    : SCIONProtocol(dstAddrs, srcPort, dstPort),
    mInitialized(false),
    mFlowID(0),
    mInitAckCount(0),
    mLowestPending(0),
    mHighestReceived(0),
    mAckVectorOffset(0),
    mNextSendByte(0),
    mTotalReceived(0),
    mNextPacket(0),
    mSelectCount(0)
{
    mProtocolID = SCION_PROTO_SSP;
    mProbeInterval = SSP_PROBE_INTERVAL;
    mReadyPackets = new OrderedList<L4Packet *>(NULL, destroySSPPacket);
    mOOPackets = new OrderedList<L4Packet *>(compareOffset, destroySSPPacket);

    if (dstAddrs.size() > 0) {
        while (mFlowID == 0)
            mFlowID = createRandom(64);
    }

    getWindowSize();

    pthread_mutex_init(&mSelectMutex, NULL);
}

SSPProtocol::~SSPProtocol()
{
    mRunning = false;
    pthread_join(mTimerThread, NULL);
    DEBUG("timer thread joined\n");
    mReadyPackets->clean();
    delete mReadyPackets;
    mOOPackets->clean();
    delete mOOPackets;
    if (mConnectionManager) {
        delete mConnectionManager;
        mConnectionManager = NULL;
    }
    pthread_mutex_destroy(&mSelectMutex);
}

void SSPProtocol::createManager(std::vector<SCIONAddr> &dstAddrs)
{
    mConnectionManager = new SSPConnectionManager(dstAddrs, mSocket, this);
    mConnectionManager->startScheduler();
    pthread_create(&mTimerThread, NULL, timerThread, this);
}

bool SSPProtocol::isFirstPacket()
{
    return mNextSendByte == 0;
}

void SSPProtocol::didRead(L4Packet *packet)
{
    mNextPacket += packet->len;
    mTotalReceived -= sizeof(SSPPacket) + packet->len;
    DEBUG("%u bytes in receive buffer\n", mTotalReceived);
    destroySSPPacket((SSPPacket *)packet);
}

int SSPProtocol::send(uint8_t *buf, size_t len, DataProfile profile)
{
    uint8_t *ptr = buf;
    size_t totalLen = len;
    size_t packetMax = mConnectionManager->maxPayloadSize();
    bool sendAll = isFirstPacket();
    while (len > 0) {
        size_t packetLen = packetMax > len ? len : packetMax;
        len -= packetLen;
        mConnectionManager->waitForSendBuffer(packetLen, mLocalSendWindow);
        SCIONPacket *packet = createPacket(ptr, packetLen);
        if (sendAll)
            mConnectionManager->sendAllPaths(packet);
        else
            mConnectionManager->queuePacket(packet);
        ptr += packetLen;
    }
    return totalLen;
}

int SSPProtocol::recv(uint8_t *buf, size_t len, SCIONAddr *srcAddr)
{
    int total = 0;
    uint8_t *ptr = buf;
    bool missing = false;

    pthread_mutex_lock(&mReadMutex);
    while (!mReadyToRead) {
        DEBUG("no data to read yet\n");
        pthread_cond_wait(&mReadCond, &mReadMutex);
    }

    DEBUG("start recv\n");
    while (!mReadyPackets->empty()) {
        L4Packet *sp = mReadyPackets->front();
        if (sp->number() != mNextPacket) {
            DEBUG("missing packet %lu\n", mNextPacket);
            missing = true;
            break;
        }
        if (sp->len + total > len) {
            DEBUG("not enough buffer space: %d + %d > %d\n",
                    sp->len, total, len);
            break;
        }
        DEBUG("reading %lu bytes\n", sp->len);
        mReadyPackets->pop();
        memcpy(ptr, sp->data, sp->len);
        ptr += sp->len;
        total += sp->len;
        didRead(sp);
    }
    if (mReadyPackets->empty() || missing) {
        DEBUG("no more data ready\n");
        mReadyToRead = false;
    }
    pthread_mutex_unlock(&mReadMutex);
    return total;
}

bool SSPProtocol::claimPacket(SCIONPacket *packet, uint8_t *buf)
{
    uint64_t flowID = be64toh(*(uint64_t *)buf);
    DEBUG("mFlowID = %lu, incoming flowID = %lu\n", mFlowID, flowID);
    return flowID == mFlowID;
}

void SSPProtocol::start(SCIONPacket *packet, uint8_t *buf, int sock)
{
    mSrcPort = 0;
    mIsReceiver = (buf != NULL);
    if (buf)
        mFlowID = be64toh(*(uint64_t *)buf);
    SSPEntry se;
    se.flowID = mFlowID;
    se.port = 0;
    registerFlow(SCION_PROTO_SSP, &se, sock);
    DEBUG("start protocol for flow %lu\n", mFlowID);
    if (packet && buf)
        handlePacket(packet, buf);
}

void SSPProtocol::getWindowSize()
{
    // Eventually determine based on system resources
    mLocalReceiveWindow = SSP_DEFAULT_WINDOW_SIZE;
    mLocalSendWindow = SSP_DEFAULT_WINDOW_SIZE;
}

int SSPProtocol::getDeadlineFromProfile(DataProfile profile)
{
    return 50000;
}

int SSPProtocol::handlePacket(SCIONPacket *packet, uint8_t *buf)
{
    DEBUG("incoming SSP packet\n");
    uint8_t *ptr = buf;
    SCIONCommonHeader &sch = packet->header.commonHeader;
    // Build SSP incoming packet
    SSPPacket *sp = new SSPPacket();
    memcpy(&sp->header, ptr, sizeof(SSPHeader));
    sp->header.flowID = be64toh(sp->header.flowID);
    sp->header.port = ntohs(sp->header.port);
    sp->header.offset = be64toh(sp->header.offset);
    int payloadLen = sch.totalLen - sch.headerLen - sp->header.headerLen;
    DEBUG("payload len = %d\n", payloadLen);
    sp->len = payloadLen;
    ptr += sizeof(SSPHeader);
    if (sp->header.flags & SSP_WINDOW) {
        mRemoteWindow = ntohl(*(uint32_t *)ptr);
        mConnectionManager->setRemoteWindow(mRemoteWindow);
        DEBUG("remote window = %d\n", mRemoteWindow);
        ptr += 4;
    }
    if (sp->header.flags & SSP_NEW_PATH) {
        sp->interfaceCount = *ptr++;
        DEBUG("%lu interfaces in new path\n", sp->interfaceCount);
        int interfaceLen = SCION_IF_SIZE * sp->interfaceCount;
        sp->interfaces = (uint8_t *)malloc(interfaceLen);
        memcpy(sp->interfaces, ptr, interfaceLen);
        ptr += interfaceLen;
    }

    packet->payload = sp;
    mConnectionManager->handlePacket(packet);

    if (sp->header.flags & SSP_ACK) {
        DEBUG("incoming packet is ACK\n");
        if (sp->header.flags & SSP_PROBE) {
            if (sp->header.offset == mProbeNum)
                mConnectionManager->handleProbeAck(packet);
        } else {
            SSPAck &ack = sp->ack;
            ack.L = be64toh(*(uint64_t *)ptr);
            ptr += 8;
            ack.I = ntohl(*(int32_t *)ptr);
            ptr += 4;
            ack.H = ntohl(*(int32_t *)ptr);
            ptr += 4;
            ack.O = ntohl(*(int32_t *)ptr);
            ptr += 4;
            ack.V = ntohl(*(uint32_t *)ptr);
            ptr += 4;
            DEBUG("incoming ACK: L = %lu, I = %d, H = %d, O = %d, V = %#x\n",
                    ack.L, ack.I, ack.H, ack.O, ack.V);
            mConnectionManager->handleAck(packet, mInitAckCount, mIsReceiver);
        }
    }

    if (sp->header.flags & SSP_PROBE && !(sp->header.flags & SSP_ACK))
        handleProbe(sp, packet->pathIndex);
    if (payloadLen > 0) {
        sp->data = (uint8_t *)malloc(payloadLen);
        memcpy(sp->data, ptr, payloadLen);
        sp->len = payloadLen;
        handleData(sp, packet->pathIndex);
    } else {
        destroySSPPacket(sp);
    }
    destroySCIONPacket(packet);
    return 0;
}

void SSPProtocol::handleProbe(SSPPacket *packet, int pathIndex)
{
    DEBUG("incoming probe\n");
    SCIONPacket p;
    memset(&p, 0, sizeof(p));
    buildCommonHeader(p.header.commonHeader, SCION_PROTO_SSP);
    p.pathIndex = pathIndex;
    SSPPacket sp;
    p.payload = &sp;
    sp.header.offset = htobe64(packet->header.offset + 1);
    sp.header.flags = SSP_PROBE | SSP_ACK;
    sp.header.flowID = htobe64(mFlowID);
    sp.header.headerLen = sizeof(sp.header);
    mConnectionManager->sendAck(&p);
}

void SSPProtocol::handleData(SSPPacket *packet, int pathIndex)
{
    uint32_t start = packet->header.offset;
    uint32_t end = start + packet->len;
    int len = end - start;
    DEBUG("Incoming SSP packet %u ~ %u\n", start, end);
    if (end <= mLowestPending) {
        DEBUG("Obsolete packet\n");
        sendAck(packet, pathIndex);
        packet->data = NULL;
        destroySSPPacket(packet);
        return;
    }

    struct timeval now;
    gettimeofday(&now, NULL);

    int maxPayload = mConnectionManager->maxPayloadSize();
    int packetSize = len + sizeof(SSPPacket);
    if (start == mLowestPending) {
        DEBUG("in-order packet\n");
        pthread_mutex_lock(&mReadMutex);
        if (packetSize + mTotalReceived > mLocalReceiveWindow) {
            DEBUG("%lu.%06lu: in-order packet %u: "
                    "Receive window too full: %u/%u\n",
                    now.tv_sec, now.tv_usec,
                    packet->header.offset, mTotalReceived, mLocalReceiveWindow);
            packet->header.offset = mHighestReceived;
            sendAck(packet, pathIndex, true);
            packet->data = NULL;
            destroySSPPacket(packet);
            pthread_mutex_unlock(&mReadMutex);
            return;
        }
        if (end - 1 > mHighestReceived)
            mHighestReceived = end - 1;
        DEBUG("%u bytes in receive buffer\n", mTotalReceived);
        bool pushed = false;
        if (mOOPackets->empty()) {
            mReadyPackets->push(packet);
            mLowestPending = end;
            pushed = true;
        } else {
            while (!mOOPackets->empty()) {
                DEBUG("check out-of-order queue\n");
                SSPPacket *sp = (SSPPacket *)mOOPackets->front();
                if (sp->header.offset < end)
                    break;
                if (!pushed) {
                    mReadyPackets->push(packet);
                    mLowestPending = end;
                    pushed = true;
                }
                start = sp->header.offset;
                end = start + sp->len;
                DEBUG("packet: %u ~ %u\n", start, end);
                if (start <= mLowestPending && end > mLowestPending) {
                    mOOPackets->pop();
                    mReadyPackets->push(sp);
                    mLowestPending = end;
                } else {
                    break;
                }
            }
        }
        if (pushed) {
            DEBUG("lowest pending now %lu\n", mLowestPending);
            mTotalReceived += packetSize;
            sendAck(packet, pathIndex);
            mReadyToRead = true;
            pthread_mutex_lock(&mSelectMutex);
            std::map<int, Notification>::iterator i;
            for (i = mSelectRead.begin(); i != mSelectRead.end(); i++) {
                Notification &n = i->second;
                pthread_mutex_lock(n.mutex);
                pthread_cond_signal(n.cond);
                pthread_mutex_unlock(n.mutex);
            }
            pthread_mutex_unlock(&mSelectMutex);
        } else {
            DEBUG("packet was resent on smaller path(s), discard original\n");
        }
        pthread_mutex_unlock(&mReadMutex);
        pthread_cond_signal(&mReadCond);
    } else {
        DEBUG("out-of-order packet %u (%lu)\n", packet->header.offset, mLowestPending);
        pthread_mutex_lock(&mReadMutex);
        if (packetSize + mTotalReceived > mLocalReceiveWindow - maxPayload) {
            DEBUG("%lu.%06lu: out-of-order packet %u (%lu): "
                    "Receive window too full: %d/%u\n",
                    now.tv_sec, now.tv_usec,
                    packet->header.offset, mLowestPending,
                    mTotalReceived, mLocalReceiveWindow);
            packet->header.offset = mHighestReceived;
            sendAck(packet, pathIndex, true);
            packet->data = NULL;
            destroySSPPacket(packet);
            pthread_mutex_unlock(&mReadMutex);
            return;
        }
        if (end - 1 > mHighestReceived)
            mHighestReceived = end - 1;
        bool found = mOOPackets->push(packet);
        if (found) {
            DEBUG("duplicate packet: discard\n");
            pthread_mutex_unlock(&mReadMutex);
            sendAck(packet, pathIndex);
            destroySSPPacket(packet);
        } else {
            DEBUG("added to out-of-order queue\n");
            mTotalReceived += packetSize;
            pthread_mutex_unlock(&mReadMutex);
            sendAck(packet, pathIndex);
        }
    }
}

void SSPProtocol::sendAck(SSPPacket *inPacket, int pathIndex, bool full)
{
    uint64_t packetNum = inPacket->header.offset;
    DEBUG("send ack for %ld (path %d)\n", packetNum, pathIndex);

    SCIONPacket packet;
    memset(&packet, 0, sizeof(SCIONPacket));
    buildCommonHeader(packet.header.commonHeader, SCION_PROTO_SSP);
    packet.pathIndex = pathIndex;

    SSPPacket sp;
    packet.payload = &sp;
    // basic header stuff
    SSPHeader &sh = sp.header;
    sh.flags |= SSP_ACK;
    if (full)
        sh.flags |= SSP_FULL;
    sh.headerLen = sizeof(SSPHeader) + sizeof(SSPAck);
    if (!mInitialized) {
        sh.flags |= SSP_WINDOW;
        sh.headerLen += 4;
        sp.windowSize = htonl(mLocalReceiveWindow);
        mRemoteWindow = inPacket->windowSize;
        mInitialized = true;
    }
    sh.flowID = htobe64(mFlowID);
    sh.mark = inPacket->header.mark;

    // ack stuff
    SSPAck &sa = sp.ack;
    sa.L = htobe64(mLowestPending);
    sa.I = htonl((int)(packetNum - mLowestPending));
    sa.H = htonl((int)(mHighestReceived - mLowestPending));
    DEBUG("outgoing ACK: L = %lu, I = %d, H = %d, O = %d, V = %u\n",
            be64toh(sa.L), ntohl(sa.I), ntohl(sa.H), ntohl(sa.O), ntohl(sa.V));

    mConnectionManager->sendAck(&packet);
}

SCIONPacket * SSPProtocol::createPacket(uint8_t *buf, size_t len)
{
    SCIONPacket *packet = (SCIONPacket *)malloc(sizeof(SCIONPacket));
    memset(packet, 0, sizeof(SCIONPacket));
    buildCommonHeader(packet->header.commonHeader, SCION_PROTO_SSP);

    SSPPacket *sp = new SSPPacket();
    packet->payload = sp;
    sp->header.headerLen = sizeof(SSPHeader);
    sp->header.flowID = htobe64(mFlowID);
    sp->header.port = htons(mDstPort);
    sp->header.offset = htobe64(mNextSendByte);
    if (!mInitialized) {
        DEBUG("include window size for initial packet\n");
        sp->header.flags |= SSP_WINDOW;
        sp->windowSize = htonl(mLocalReceiveWindow);
        sp->header.headerLen += 4;
        mInitialized = true;
    }
    sp->data = (uint8_t *)malloc(len);
    memcpy(sp->data, buf, len);
    sp->len = len;
    mNextSendByte += len;

    return packet;
}

void SSPProtocol::handleTimerEvent()
{
    struct timeval current;
    gettimeofday(&current, NULL);
    mConnectionManager->handleTimeout();
    if (!mIsReceiver && elapsedTime(&mLastProbeTime, &current) >= mProbeInterval) {
        mConnectionManager->sendProbes(mProbeNum++, mFlowID);
        mLastProbeTime = current;
    }
}

void SSPProtocol::getStats(SCIONStats *stats)
{
    if (mConnectionManager)
        mConnectionManager->getStats(stats);
}

bool SSPProtocol::readyToRead()
{
    bool ready = false;
    pthread_mutex_lock(&mReadMutex);
    ready = mReadyToRead;
    pthread_mutex_unlock(&mReadMutex);
    return ready;
}

bool SSPProtocol::readyToWrite()
{
    return !mConnectionManager->bufferFull(mLocalSendWindow);
}

int SSPProtocol::registerSelect(Notification *n, int mode)
{
    pthread_mutex_lock(&mSelectMutex);
    if (mode == SCION_SELECT_READ)
        mSelectRead[++mSelectCount] = *n;
    else
        mSelectWrite[++mSelectCount] = *n;
    pthread_mutex_unlock(&mSelectMutex);
    DEBUG("registered index %d\n", mSelectCount);
    return mSelectCount;
}

void SSPProtocol::deregisterSelect(int index)
{
    pthread_mutex_lock(&mSelectMutex);
    if (mSelectRead.find(index) != mSelectRead.end()) {
        DEBUG("erase index %d from read list\n", index);
        mSelectRead.erase(index);
    } else {
        DEBUG("erase index %d from write list\n", index);
        mSelectWrite.erase(index);
    }
    pthread_mutex_unlock(&mSelectMutex);
}

void SSPProtocol::notifySender()
{
    pthread_mutex_lock(&mSelectMutex);
    std::map<int, Notification>::iterator i;
    for (i = mSelectWrite.begin(); i != mSelectWrite.end(); i++) {
        Notification &n = i->second;
        pthread_mutex_lock(n.mutex);
        pthread_cond_signal(n.cond);
        pthread_mutex_unlock(n.mutex);
    }
    pthread_mutex_unlock(&mSelectMutex);
}

// SUDP

SUDPProtocol::SUDPProtocol(std::vector<SCIONAddr> &dstAddrs, short srcPort, short dstPort)
    : SCIONProtocol(dstAddrs, srcPort, dstPort),
    mTotalReceived(0)
{
}

SUDPProtocol::~SUDPProtocol()
{
    delete mConnectionManager;
}

void SUDPProtocol::createManager(std::vector<SCIONAddr> &dstAddrs)
{
    mConnectionManager = new SUDPConnectionManager(dstAddrs, mSocket);
    pthread_create(&mTimerThread, NULL, timerThread, this);
}

int SUDPProtocol::send(uint8_t *buf, size_t len, DataProfile profile)
{
    DEBUG("send %lu byte packet\n", len);
    SCIONPacket packet;
    memset(&packet, 0, sizeof(packet));
    buildCommonHeader(packet.header.commonHeader, SCION_PROTO_SUDP);
    SUDPPacket sp;
    memset(&sp, 0, sizeof(sp));
    packet.payload = &sp;
    SUDPHeader &sh = sp.header;
    sh.srcPort = htons(mSrcPort);
    sh.dstPort = htons(mDstPort);
    sp.payload = malloc(len);
    sp.payloadLen = len;
    memcpy(sp.payload, buf, len);
    return mConnectionManager->send(&packet);
}

int SUDPProtocol::recv(uint8_t *buf, size_t len, SCIONAddr *srcAddr)
{
    DEBUG("recv max %lu bytes\n", len);
    int size = 0;
    pthread_mutex_lock(&mReadMutex);
    while (mReceivedPackets.empty())
        pthread_cond_wait(&mReadCond, &mReadMutex);
    SUDPPacket *sp = mReceivedPackets.front();
    DEBUG("queued packet with len %lu bytes\n", sp->payloadLen);
    if (sp->payloadLen > len) {
        DEBUG("user buffer too short to read\n");
        pthread_mutex_unlock(&mReadMutex);
        return -1;
    }
    mReceivedPackets.pop_front();
    memcpy(buf, sp->payload, sp->payloadLen);
    size = sp->payloadLen;
    mTotalReceived -= sp->payloadLen + sizeof(SUDPPacket);
    pthread_mutex_unlock(&mReadMutex);
    DEBUG("recvd total %d bytes\n", size);
    return size;
}

int SUDPProtocol::handlePacket(SCIONPacket *packet, uint8_t *buf)
{
    DEBUG("SUDP packet\n");
    SCIONCommonHeader &sch = packet->header.commonHeader;
    uint8_t *ptr = buf;
    // SUDP header
    packet->payload = malloc(sizeof(SUDPPacket));
    memset(packet->payload, 0, sizeof(SUDPPacket));
    SUDPPacket *sp = (SUDPPacket *)(packet->payload);
    sp->header.srcPort = ntohs(*(uint16_t *)ptr);
    ptr += 2;
    mDstPort = sp->header.srcPort;
    sp->header.dstPort = ntohs(*(uint16_t *)ptr);
    ptr += 2;
    sp->header.flags = *ptr;
    ptr++;
    sp->payloadLen = sch.totalLen - sch.headerLen - sizeof(SUDPHeader);
    DEBUG("payload %lu bytes\n", sp->payloadLen);
    if (sp->payloadLen > 0) {
        if (sp->header.flags & SUDP_PROBE) {
            DEBUG("probe packet\n");
            memcpy(&(sp->payload), ptr, 4);
        } else {
            sp->payload = malloc(sp->payloadLen);
            memcpy(sp->payload, ptr, sp->payloadLen);
        }
        mConnectionManager->handlePacket(packet);
        if (!(sp->header.flags & SUDP_PROBE)) {
            DEBUG("data packet\n");
            int size = sp->payloadLen + sizeof(SUDPPacket);
            if (mTotalReceived + size > SUDP_RECV_BUFFER) {
                destroySUDPPacket(sp);
            } else {
                pthread_mutex_lock(&mReadMutex);
                mTotalReceived += size;
                mReceivedPackets.push_back(sp);
                pthread_mutex_unlock(&mReadMutex);
                pthread_cond_signal(&mReadCond);
            }
        } else {
            sp->payload = NULL;
            destroySUDPPacket(sp);
        }
        destroySCIONPacket(packet);
    }
    return 0;
}

void SUDPProtocol::handleTimerEvent()
{
    struct timeval t;
    gettimeofday(&t, NULL);
    if (elapsedTime(&mLastProbeTime, &t) >= SUDP_PROBE_INTERVAL) {
        mConnectionManager->sendProbes(mProbeNum++, mSrcPort, mDstPort);
        mLastProbeTime = t;
    }
}

bool SUDPProtocol::claimPacket(SCIONPacket *packet, uint8_t *buf)
{
    return false;
}

void SUDPProtocol::start(SCIONPacket *packet, uint8_t *buf, int sock)
{
}

void SUDPProtocol::getStats(SCIONStats *stats)
{
}
