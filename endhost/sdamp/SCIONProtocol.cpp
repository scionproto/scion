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

void * SUDPTimerThread(void *arg)
{
    SUDPProtocol *p = (SUDPProtocol *)arg;
    while (p->isRunning()) {
        usleep(SCION_TIMER_INTERVAL);
        p->handleTimerEvent();
    }
    return NULL;
}

void * SDAMPTimerThread(void *arg)
{
    SDAMPProtocol *p = (SDAMPProtocol *)arg;
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

// SDAMP

SDAMPProtocol::SDAMPProtocol(std::vector<SCIONAddr> &dstAddrs, short srcPort, short dstPort)
    : SCIONProtocol(dstAddrs, srcPort, dstPort),
    mInitialized(false),
    mFlowID(0),
    mInitAckCount(0),
    mLowestPending(0),
    mHighestReceived(0),
    mAckVectorOffset(0),
    mNextSendByte(0),
    mLastPacketNum(0),
    mTotalReceived(0),
    mNextPacket(0)
{
    mProtocolID = SCION_PROTO_SDAMP;
    mProbeInterval = SDAMP_PROBE_INTERVAL;
    mReadyPackets = new OrderedList<SDAMPPacket *>(NULL, destroySDAMPPacket);
    mOOPackets = new OrderedList<SDAMPPacket *>(comparePacketNum, destroySDAMPPacket);

    if (dstAddrs.size() > 0) {
        while (mFlowID == 0)
            mFlowID = createRandom(64);
    }

    getWindowSize();

    pthread_mutex_init(&mPacketMutex, NULL);
}

SDAMPProtocol::~SDAMPProtocol()
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
    pthread_mutex_destroy(&mPacketMutex);
}

int SDAMPProtocol::send(uint8_t *buf, size_t len, DataProfile profile)
{
    uint8_t *ptr = buf;
    size_t totalLen = len;
    size_t packetMax = mConnectionManager->maxPayloadSize();
    while (len > 0) {
        size_t packetLen = packetMax > len ? len : packetMax;
        len -= packetLen;
        mConnectionManager->waitForSendBuffer(packetLen, mLocalSendWindow);
        SCIONPacket *packet = createPacket(ptr, packetLen);
        SDAMPPacket *sp = (SDAMPPacket *)(packet->payload);
        if (sp->header.packetNum == 0)
            mConnectionManager->sendAllPaths(packet);
        else
            mConnectionManager->queuePacket(packet);
        ptr += packetLen;
        DEBUG("added packet %lu to send queue\n", be64toh(sp->header.packetNum));
    }
    return totalLen;
}

int SDAMPProtocol::recv(uint8_t *buf, size_t len, SCIONAddr *srcAddr)
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
        SDAMPPacket *sp = mReadyPackets->front();
        uint64_t packetNum = sp->header.packetNum;
        if (packetNum != mNextPacket) {
            DEBUG("missing packet %lu\n", mNextPacket);
            missing = true;
            break;
        }
        if (sp->size + total > (int)len) {
            DEBUG("not enough buffer space\n");
            break;
        }
        DEBUG("reading %d bytes from packet %lu\n", sp->size, packetNum);
        memcpy(ptr, sp->payload, sp->size);
        ptr += sp->size;
        total += sp->size;
        mNextPacket++;
        mTotalReceived -= sizeof(SDAMPPacket) + sp->size;
        mReadyPackets->pop();
        destroySDAMPPacket(sp);
    }
    if (mReadyPackets->empty() || missing) {
        DEBUG("no more data ready\n");
        mReadyToRead = false;
    }
    pthread_mutex_unlock(&mReadMutex);
    return total;
}

bool SDAMPProtocol::claimPacket(SCIONPacket *packet, uint8_t *buf)
{
    uint64_t flowID = be64toh(*(uint64_t *)buf);
    DEBUG("mFlowID = %lu, incoming flowID = %lu\n", mFlowID, flowID);
    return flowID == mFlowID;
}

void SDAMPProtocol::createManager(std::vector<SCIONAddr> &dstAddrs)
{
    mConnectionManager = new SDAMPConnectionManager(dstAddrs, mSocket, this);
    mConnectionManager->startPaths();
    pthread_create(&mTimerThread, NULL, SDAMPTimerThread, this);
}

void SDAMPProtocol::start(SCIONPacket *packet, uint8_t *buf, int sock)
{
    mSrcPort = 0;
    mIsReceiver = (buf != NULL);
    if (buf)
        mFlowID = be64toh(*(uint64_t *)buf);
    SDAMPEntry se;
    se.flowID = mFlowID;
    se.port = 0;
    registerFlow(SCION_PROTO_SDAMP, &se, sock);
    DEBUG("start protocol for flow %lu\n", mFlowID);
    if (packet && buf)
        handlePacket(packet, buf);
}

int SDAMPProtocol::handlePacket(SCIONPacket *packet, uint8_t *buf)
{
    SCIONCommonHeader &sch = packet->header.commonHeader;
    // build SDAMP packet
    // SDAMP header
    uint8_t *ptr = buf;
    packet->payload = malloc(sizeof(SDAMPPacket));
    memset(packet->payload, 0, sizeof(SDAMPPacket));
    SDAMPPacket *sp = (SDAMPPacket *)packet->payload;
    memcpy(sp, ptr, sizeof(SDAMPHeader));
    SDAMPHeader &header = sp->header;
    // deal with endianness
    header.version = ntohl(header.version);
    header.srcPort = ntohs(header.srcPort);
    header.dstPort = ntohs(header.dstPort);
    header.flowID = be64toh(header.flowID);
    header.packetNum = be64toh(header.packetNum);
    ptr += sizeof(SDAMPHeader);
    int payloadLen = sch.totalLen - sch.headerLen - header.headerLen;
    if (sp->header.flags & SDAMP_INIT) {
        sp->windowSize = ntohl(*(uint32_t *)ptr);
        ptr += 4;
    }
    if (sp->header.flags & SDAMP_ACK) {
        memcpy(&(sp->ack), ptr, sizeof(SDAMPAck));
        // deal with endianness
        SDAMPAck &ack = sp->ack;
        ack.L = be64toh(ack.L);
        ack.I = ntohl(ack.I);
        ack.H = ntohl(ack.H);
        ack.O = ntohl(ack.O);
        ack.V = ntohl(ack.V);
        ptr += sizeof(SDAMPAck);
    }
    if (sp->header.flags & SDAMP_NEW_PATH) {
        sp->interfaceCount = *ptr++;
        int interfaceLen = SCION_IF_SIZE * sp->interfaceCount;
        sp->interfaces = (uint8_t *)malloc(interfaceLen);
        memcpy(sp->interfaces, ptr, interfaceLen);
        ptr += interfaceLen;
    }
    DEBUG("SDAMP payload %d bytes\n", payloadLen);

    if (payloadLen > 0) {
        sp->payload = (uint8_t *)malloc(payloadLen);
        sp->size = payloadLen;
        memcpy(sp->payload, ptr, payloadLen);
    }

    // add new path, record congestion info, etc
    mConnectionManager->handlePacket(packet);

    if (sp->header.flags & SDAMP_PROBE) {
        if (sp->header.flags & SDAMP_ACK)
            handleProbeAck(packet);
        else
            handleProbe(packet);
        destroySDAMPPacket((SDAMPPacket *)(packet->payload));
        destroySCIONPacket(packet);
        return 0;
    }
    if (sp->header.flags & SDAMP_ACK)
        handleAck(packet);
    if (sp->size == 0) {
        destroySDAMPPacket(sp);
        destroySCIONPacket(packet);
    } else {
        handleData(packet);
    }
    return 0;
}

SCIONPacket * SDAMPProtocol::createPacket(uint8_t *buf, size_t len)
{
    pthread_mutex_lock(&mPacketMutex);
    SCIONPacket *p = (SCIONPacket *)malloc(sizeof(SCIONPacket));
    memset(p, 0, sizeof(SCIONPacket));
    SCIONCommonHeader &ch = p->header.commonHeader;
    buildCommonHeader(ch, SCION_PROTO_SDAMP);
    SDAMPPacket *sp = (SDAMPPacket *)malloc(sizeof(SDAMPPacket));
    memset(sp, 0, sizeof(SDAMPPacket));
    p->payload = sp;
    p->rto = SCION_DEFAULT_RTO;
    SDAMPHeader &sh = sp->header;
    sh.headerLen = sizeof(sh);
    if (mLastPacketNum == 0) {
        sh.flags |= SDAMP_INIT;
        sp->windowSize = htonl(mLocalReceiveWindow);
        sh.headerLen += 4;
    }
    sh.srcPort = htons(mSrcPort);
    sh.dstPort = htons(mDstPort);
    sh.flowID = htobe64(mFlowID);
    sh.packetNum = htobe64(mLastPacketNum++);
    sp->payload = (uint8_t *)malloc(len);
    memcpy(sp->payload, buf, len);
    sp->size = len;
    pthread_mutex_unlock(&mPacketMutex);
    return p;
}

void SDAMPProtocol::handleTimerEvent()
{
    struct timeval current;
    gettimeofday(&current, NULL);
    mConnectionManager->handleTimeout();
    if (!mIsReceiver && elapsedTime(&mLastProbeTime, &current) >= mProbeInterval) {
        mConnectionManager->sendProbes(mProbeNum++, mFlowID);
        mLastProbeTime = current;
    }
}

void SDAMPProtocol::getWindowSize()
{
    // Eventually determine based on system resources
    mLocalReceiveWindow = SDAMP_DEFAULT_WINDOW_SIZE;
    mLocalSendWindow = SDAMP_DEFAULT_WINDOW_SIZE;
}

int SDAMPProtocol::getDeadlineFromProfile(DataProfile profile)
{
    return 50000;
}

void SDAMPProtocol::handleProbe(SCIONPacket *packet)
{
    DEBUG("incoming probe\n");
    SDAMPPacket *sdampPacket = (SDAMPPacket *)(packet->payload);
    SCIONPacket p;
    memset(&p, 0, sizeof(p));
    buildCommonHeader(p.header.commonHeader, SCION_PROTO_SDAMP);
    p.pathIndex = packet->pathIndex;
    SDAMPPacket sp;
    memset(&sp, 0, sizeof(sp));
    p.payload = &sp;
    sp.header.packetNum = htobe64(sdampPacket->header.packetNum + 1);
    sp.header.flags = SDAMP_PROBE | SDAMP_ACK;
    sp.header.flowID = htobe64(mFlowID);
    sp.header.dstPort = htons(mDstPort);
    sp.header.headerLen = sizeof(sp.header);
    mConnectionManager->sendAck(&p);
}

void SDAMPProtocol::handleProbeAck(SCIONPacket *packet)
{
    DEBUG("ack for probe\n");
    SDAMPPacket *sp = (SDAMPPacket *)(packet->payload);
    if (sp->header.packetNum == mProbeNum)
        mConnectionManager->handleProbeAck(packet);
}

void SDAMPProtocol::handleAck(SCIONPacket *packet)
{
    SDAMPPacket *sdampPacket = (SDAMPPacket *)(packet->payload);
    if (sdampPacket->header.flags & SDAMP_INIT) {
        DEBUG("remote host window size: %d\n", sdampPacket->windowSize);
        mRemoteWindow = sdampPacket->windowSize;
        mDstPort = sdampPacket->header.srcPort;
        DEBUG("dst port = %d\n", mDstPort);
        mInitAckCount++;
    }

    mConnectionManager->handleAck(packet, mInitAckCount, mIsReceiver);
}

void SDAMPProtocol::handleData(SCIONPacket *packet)
{
    SDAMPPacket *sp = (SDAMPPacket *)(packet->payload);
    DEBUG("incoming packet %lu with payload of %d bytes\n",
            sp->header.packetNum, sp->size);

    uint64_t packetNum = sp->header.packetNum;
    if (packetNum > mLowestPending + mHighestReceived)
        mHighestReceived = packetNum;

    if (packetNum < mLowestPending) {
        DEBUG("outdated packet %lu\n", packetNum);
        sendAck(packet);
        destroySDAMPPacket(sp);
        destroySCIONPacket(packet);
        return;
    }

    pthread_mutex_lock(&mReadMutex);
    int totalSize = sizeof(SDAMPPacket) + sp->size;
    if (packetNum == mLowestPending) {
        DEBUG("in-order packet %lu\n", packetNum);
        if (mTotalReceived + totalSize > mLocalReceiveWindow) {
            DEBUG("receive window too full (%lu/%lu)\n",
                    mTotalReceived, mLocalReceiveWindow);
            pthread_mutex_unlock(&mReadMutex);
            destroySDAMPPacket(sp);
            destroySCIONPacket(packet);
            return;
        }
        mReadyPackets->push(sp);
        mTotalReceived += totalSize;
        mLowestPending++;
        while (!mOOPackets->empty()) {
            DEBUG("check out-of-order packets\n");
            sp = mOOPackets->front();
            DEBUG("packet %lu at head of OOP\n", sp->header.packetNum);
            if (sp->header.packetNum != mLowestPending)
                break;
            mOOPackets->pop();
            mLowestPending++;
            mReadyPackets->push(sp);
        }
        mReadyToRead = true;
    } else {
        DEBUG("out-of-order packet %lu (%lu)\n", packetNum, mLowestPending);
        int spare = mConnectionManager->maxPayloadSize() + sizeof(SDAMPPacket);
        if (mTotalReceived + totalSize > mLocalReceiveWindow - spare) {
            DEBUG("receive window too full (%lu/%lu)\n",
                    mTotalReceived, mLocalReceiveWindow);
            pthread_mutex_unlock(&mReadMutex);
            destroySDAMPPacket(sp);
            destroySCIONPacket(packet);
            return;
        }
        bool dup = mOOPackets->push(sp);
        if (!dup) {
            DEBUG("insert packet %lu into out-of-order queue\n", packetNum);
            mTotalReceived += totalSize;
        }
    }
    sendAck(packet);
    pthread_mutex_unlock(&mReadMutex);
    if (mReadyToRead)
        pthread_cond_broadcast(&mReadCond);
    destroySCIONPacket(packet);
}

void SDAMPProtocol::sendAck(SCIONPacket *packet)
{
    SDAMPPacket *sdampPacket = (SDAMPPacket *)(packet->payload);
    uint64_t packetNum = sdampPacket->header.packetNum;
    DEBUG("send ack for %ld\n", packetNum);

    SCIONPacket ackPacket;
    memset(&ackPacket, 0, sizeof(SCIONPacket));
    buildCommonHeader(ackPacket.header.commonHeader, SCION_PROTO_SDAMP);
    ackPacket.pathIndex = packet->pathIndex;

    SDAMPPacket sp;
    memset(&sp, 0, sizeof(SDAMPPacket));
    ackPacket.payload = &sp;
    // basic header stuff
    SDAMPHeader &sh = sp.header;
    sh.flags |= SDAMP_ACK;
    sh.headerLen = sizeof(SDAMPHeader) + sizeof(SDAMPAck);
    if (sdampPacket->header.flags & SDAMP_INIT) {
        sh.flags |= SDAMP_INIT;
        sh.headerLen += 4;
        sp.windowSize = htonl(mLocalReceiveWindow);
        DEBUG("remote host window size: %d\n", sdampPacket->windowSize);
        mRemoteWindow = sdampPacket->windowSize;
        mInitialized = true;
        mDstPort = sdampPacket->header.srcPort;
    }
    sh.srcPort = htons(mSrcPort);
    sh.dstPort = htons(mDstPort);
    sh.flowID = htobe64(mFlowID);
    // ack stuff
    SDAMPAck &sa = sp.ack;
    sa.L = htobe64(mLowestPending);
    sa.I = htonl(packetNum > mLowestPending ?
                    packetNum - mLowestPending :
                    -(mLowestPending - packetNum));
    if (mHighestReceived > mLowestPending)
        sa.H = htonl((int)(mHighestReceived - mLowestPending));
    else
        sa.H = htonl(-(int)(mLowestPending - mHighestReceived));
    uint32_t ackVector = 0;
    uint64_t start = mLowestPending + mAckVectorOffset;
    DEBUG("start ack vector at %lu\n", start);
    std::list<SDAMPPacket *>::iterator i;
    for (i = mReadyPackets->begin(); i != mReadyPackets->end(); i++) {
        if ((*i)->header.packetNum > start + 31)
            break;
        if ((*i)->header.packetNum < start)
            continue;
        ackVector |= 1 << ((*i)->header.packetNum - start);
    }
    for (i = mOOPackets->begin(); i != mOOPackets->end(); i++) {
        if ((*i)->header.packetNum > start + 31)
            break;
        if ((*i)->header.packetNum < start)
            continue;
        ackVector |= 1 << ((*i)->header.packetNum - start);
    }
    sa.V = htonl(ackVector);

    mConnectionManager->sendAck(&ackPacket);
}

void SDAMPProtocol::getStats(SCIONStats *stats)
{
    if (mConnectionManager)
        mConnectionManager->getStats(stats);
}

// SSP

SSPProtocol::SSPProtocol(std::vector<SCIONAddr> &dstAddrs, short srcPort, short dstPort)
    : SDAMPProtocol(dstAddrs, srcPort, dstPort),
    mNextOffset(0)
{
    mReceiveBuffer = new RingBuffer(mLocalReceiveWindow);
    mOOPackets = new OrderedList<SSPInPacket *>(compareOffset, destroySSPInPacket);
}

SSPProtocol::~SSPProtocol()
{
    delete mReceiveBuffer;
    mOOPackets->clean();
    delete mOOPackets;
}

void SSPProtocol::createManager(std::vector<SCIONAddr> &dstAddrs)
{
    mConnectionManager = new SSPConnectionManager(dstAddrs, mSocket, this);
    mConnectionManager->startPaths();
    pthread_create(&mTimerThread, NULL, SDAMPTimerThread, this);
}

int SSPProtocol::send(uint8_t *buf, size_t len, DataProfile profile)
{
    DEBUG("queue %lu bytes to send\n", len);
    bool firstSend = (mNextSendByte == 0);
    SSPConnectionManager *manager = (SSPConnectionManager *)mConnectionManager;
    manager->waitForSendBuffer(len, mLocalSendWindow);
    if (firstSend)
        manager->sendAllPaths(buf, len);
    else
        manager->queueData(buf, len);
    mNextSendByte += len;
    return len;
}

int SSPProtocol::recv(uint8_t *buf, size_t len, SCIONAddr *srcAddr)
{
    DEBUG("wait for recv buffer (%lu)\n", mNextPacket);
    pthread_mutex_lock(&mReadMutex);
    while (!mReadyToRead)
        pthread_cond_wait(&mReadCond, &mReadMutex);
    DEBUG("ready to recv\n");
    int total = 0;
    total = mReceiveBuffer->read(buf, len);
    mTotalReceived -= total;
    mNextPacket += total;
    if (mReceiveBuffer->size() == 0)
        mReadyToRead = false;
    pthread_mutex_unlock(&mReadMutex);
    return total;
}

int SSPProtocol::handlePacket(SCIONPacket *packet, uint8_t *buf)
{
    DEBUG("incoming SSP packet\n");
    uint8_t *ptr = buf;
    SCIONCommonHeader &sch = packet->header.commonHeader;
    // Build SSP incoming packet
    SSPInPacket *sip = (SSPInPacket *)malloc(sizeof(SSPInPacket));
    memset(sip, 0, sizeof(SSPInPacket));
    ptr += 10; // skip flowID, port
    uint8_t headerLen = *ptr;
    ptr ++;
    int payloadLen = sch.totalLen - sch.headerLen - headerLen;
    DEBUG("payload len = %d\n", payloadLen);
    sip->offset = ntohl(*(uint32_t *)ptr);
    sip->len = payloadLen;
    ptr += 4;
    uint8_t flags = *ptr;
    ptr++;
    sip->mark = *ptr;
    ptr++;
    if (flags & SSP_WINDOW) {
        mRemoteWindow = ntohl(*(uint32_t *)ptr);
        mConnectionManager->setRemoteWindow(mRemoteWindow);
        DEBUG("remote window = %d\n", mRemoteWindow);
        ptr += 4;
    }
    if (flags & SSP_NEW_PATH) {
        sip->interfaceCount = *ptr++;
        DEBUG("%d interfaces in new path\n", sip->interfaceCount);
        int interfaceLen = SCION_IF_SIZE * sip->interfaceCount;
        sip->interfaces = (uint8_t *)malloc(interfaceLen);
        memcpy(sip->interfaces, ptr, interfaceLen);
        ptr += interfaceLen;
    }

    packet->payload = sip;
    mConnectionManager->handlePacket(packet);

    if (flags & SSP_ACK) {
        DEBUG("incoming packet is ACK\n");
        if (flags & SSP_PROBE) {
            if (sip->offset == mProbeNum)
                mConnectionManager->handleProbeAck(packet);
        } else {
            SSPAck ack;
            memset(&ack, 0, sizeof(ack));
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
            ack.full = (flags & SSP_FULL);
            ack.mark = sip->mark;
            packet->payload = &ack;
            DEBUG("incoming ACK: L = %lu, I = %d, H = %d, O = %d, V = %#x\n",
                    ack.L, ack.I, ack.H, ack.O, ack.V);
            mConnectionManager->handleAck(packet, mInitAckCount, mIsReceiver);
        }
    }

    if (flags & SSP_PROBE && !(flags & SSP_ACK))
        handleProbe(sip, packet->pathIndex);
    if (payloadLen > 0) {
        sip->data = ptr;
        sip->len = payloadLen;
        handleData(sip, packet->pathIndex);
    } else {
        destroySSPInPacket(sip);
    }
    destroySCIONPacket(packet);
    return 0;
}

void SSPProtocol::handleProbe(SSPInPacket *packet, int pathIndex)
{
    DEBUG("incoming probe\n");
    SCIONPacket p;
    memset(&p, 0, sizeof(p));
    buildCommonHeader(p.header.commonHeader, SCION_PROTO_SSP);
    p.pathIndex = pathIndex;
    SSPOutPacket sp;
    p.payload = &sp;
    memset(&sp, 0, sizeof(sp));
    sp.header.offset = htonl(packet->offset + 1);
    sp.header.flags = SSP_PROBE | SSP_ACK;
    sp.header.flowID = htobe64(mFlowID);
    sp.header.headerLen = sizeof(sp.header);
    mConnectionManager->sendAck(&p);
}

void SSPProtocol::handleData(SSPInPacket *packet, int pathIndex)
{
    DEBUG("Incoming SSP packet %lu ~ %lu\n", packet->offset, packet->offset + packet->len);
    uint32_t start = packet->offset;
    uint32_t end = start + packet->len;
    int len = end - start;
    if (end <= mLowestPending) {
        DEBUG("Obsolete packet\n");
        sendAck(packet, pathIndex);
        packet->data = NULL;
        destroySSPInPacket(packet);
        return;
    }

    struct timeval now;
    gettimeofday(&now, NULL);

    int maxPayload = mConnectionManager->maxPayloadSize();
    if (start <= mLowestPending && end > mLowestPending) {
        DEBUG("in-order packet\n");
        pthread_mutex_lock(&mReadMutex);
        if (len + mTotalReceived > mLocalReceiveWindow) {
            DEBUG("%lu.%06lu: in-order packet %u:\nReceive window too full: %lu/%lu\n",
                    now.tv_sec, now.tv_usec, packet->offset, mTotalReceived, mLocalReceiveWindow);
            packet->offset = mHighestReceived;
            sendAck(packet, pathIndex, true);
            packet->data = NULL;
            destroySSPInPacket(packet);
            pthread_mutex_unlock(&mReadMutex);
            return;
        }
        if (end - 1> mHighestReceived)
            mHighestReceived = end - 1;
        int readOffset = mLowestPending - start;
        mReceiveBuffer->write(packet->data + readOffset, len - readOffset);
        mTotalReceived += len - readOffset;
        mLowestPending = end;
        while (!mOOPackets->empty()) {
            DEBUG("check out-of-order queue\n");
            SSPInPacket *sip = mOOPackets->front();
            start = sip->offset;
            end = start + sip->len;
            DEBUG("packet: %u ~ %u\n", start, end);
            if (start <= mLowestPending && end > mLowestPending) {
                mOOPackets->pop();
                readOffset = mLowestPending - start;
                mReceiveBuffer->write(sip->data + readOffset, end - start - readOffset);
                mLowestPending = end;
                destroySSPInPacket(sip);
            } else {
                break;
            }
        }
        DEBUG("lowest pending now %lu\n", mLowestPending);
        sendAck(packet, pathIndex);
        packet->data = NULL;
        destroySSPInPacket(packet);
        mReadyToRead = true;
        pthread_mutex_unlock(&mReadMutex);
        pthread_cond_signal(&mReadCond);
    } else {
        DEBUG("out-of-order packet %u (%lu)\n", packet->offset, mLowestPending);
        int packetSize = len + sizeof(SSPInPacket);
        pthread_mutex_lock(&mReadMutex);
        if (packetSize + mTotalReceived > mLocalReceiveWindow - maxPayload) {
            DEBUG("%lu.%06lu: out-of-order packet %lu (%lu):\nReceive window too full: %d/%u\n",
                    now.tv_sec, now.tv_usec, packet->offset, mLowestPending, mTotalReceived, mLocalReceiveWindow);
            packet->offset = mHighestReceived;
            sendAck(packet, pathIndex, true);
            packet->data = NULL;
            destroySSPInPacket(packet);
            pthread_mutex_unlock(&mReadMutex);
            return;
        }
        if (end - 1 > mHighestReceived)
            mHighestReceived = end - 1;
        uint8_t *data = (uint8_t *)malloc(len);
        memcpy(data, packet->data, len);
        packet->data = data;
        bool found = mOOPackets->push(packet);
        if (found) {
            DEBUG("duplicate packet: discard\n");
            pthread_mutex_unlock(&mReadMutex);
            sendAck(packet, pathIndex);
            destroySSPInPacket(packet);
        } else {
            DEBUG("added to out-of-order queue\n");
            mTotalReceived += packetSize;
            pthread_mutex_unlock(&mReadMutex);
            sendAck(packet, pathIndex);
        }
    }
}

void SSPProtocol::sendAck(SSPInPacket *sip, int pathIndex, bool full)
{
    uint64_t packetNum = sip->offset;
    DEBUG("send ack for %ld (path %d)\n", packetNum, pathIndex);

    SCIONPacket packet;
    memset(&packet, 0, sizeof(SCIONPacket));
    buildCommonHeader(packet.header.commonHeader, SCION_PROTO_SSP);
    packet.pathIndex = pathIndex;

    SSPOutPacket sp;
    memset(&sp, 0, sizeof(SSPOutPacket));
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
        mRemoteWindow = sip->windowSize;
        mInitialized = true;
    }
    sh.flowID = htobe64(mFlowID);
    sh.mark = sip->mark;

    // ack stuff
    SSPAck &sa = sp.ack;
    sa.L = htobe64(mLowestPending);
    sa.I = htonl(packetNum > mLowestPending ? packetNum - mLowestPending : -(mLowestPending - packetNum));
    sa.H = htonl(mHighestReceived);
    DEBUG("outgoing ACK: L = %lu, I = %d, H = %d, O = %d, V = %u\n",
            be64toh(sa.L), ntohl(sa.I), ntohl(sa.H), ntohl(sa.O), ntohl(sa.V));

    mConnectionManager->sendAck(&packet);
}

SCIONPacket * SSPProtocol::createPacket(uint8_t *buf, size_t len)
{
    SCIONPacket *packet = (SCIONPacket *)malloc(sizeof(SCIONPacket));
    memset(packet, 0, sizeof(SCIONPacket));
    buildCommonHeader(packet->header.commonHeader, SCION_PROTO_SSP);

    SSPOutPacket *sp = (SSPOutPacket *)malloc(sizeof(SSPOutPacket));
    memset(sp, 0, sizeof(SSPOutPacket));
    packet->payload = sp;
    sp->header.headerLen = sizeof(SSPHeader);
    sp->header.flowID = htobe64(mFlowID);
    sp->header.port = htons(mDstPort);
    sp->header.offset = htonl(mNextOffset);
    if (!mInitialized) {
        DEBUG("include window size for initial packet\n");
        sp->header.flags |= SSP_WINDOW;
        sp->windowSize = htonl(mLocalReceiveWindow);
        sp->header.headerLen += 4;
        mInitialized = true;
    }
    sp->data = buf;
    sp->len = len;
    mNextOffset += len;

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
    pthread_create(&mTimerThread, NULL, SUDPTimerThread, this);
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
