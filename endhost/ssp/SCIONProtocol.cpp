#include <unistd.h>
#include <arpa/inet.h>

#include "Extensions.h"
#include "ProtocolConfigs.h"
#include "SCIONProtocol.h"
#include "Utils.h"

void * timerThread(void *arg)
{
    SCIONProtocol *p = (SCIONProtocol *)arg;
    while (p->isRunning()) {
        p->handleTimerEvent();
        usleep(SCION_TIMER_INTERVAL);
    }
    return NULL;
}

SCIONProtocol::SCIONProtocol(std::vector<SCIONAddr> &dstAddrs, short srcPort, short dstPort)
    : mPathManager(NULL),
    mSrcPort(srcPort),
    mDstPort(dstPort),
    mIsReceiver(false),
    mReadyToRead(false),
    mBlocking(true),
    mState(SCION_RUNNING),
    mDstAddrs(dstAddrs),
    mProbeNum(0)
{
    gettimeofday(&mLastProbeTime, NULL);
    mSocket = socket(AF_INET, SOCK_DGRAM, 0);
    pthread_mutex_init(&mReadMutex, NULL);
    pthread_cond_init(&mReadCond, NULL);
    pthread_mutex_init(&mStateMutex, NULL);
}

SCIONProtocol::~SCIONProtocol()
{
    close(mSocket);
    pthread_mutex_destroy(&mReadMutex);
    pthread_cond_destroy(&mReadCond);
    pthread_mutex_destroy(&mStateMutex);
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
    return mState != SCION_CLOSED;
}

void SCIONProtocol::setReceiver(bool receiver)
{
    mIsReceiver = receiver;
}

void SCIONProtocol::setBlocking(bool blocking)
{
    mBlocking = blocking;
}

bool SCIONProtocol::isBlocking()
{
    return mBlocking;
}

bool SCIONProtocol::claimPacket(SCIONPacket *packet, uint8_t *buf)
{
    return false;
}

void SCIONProtocol::createManager(std::vector<SCIONAddr> &dstAddrs, bool paths)
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

int SCIONProtocol::setStayISD(uint16_t isd)
{
    if (!mPathManager)
        return -EPERM;
    return mPathManager->setStayISD(isd);
}

int SCIONProtocol::shutdown()
{
    return 0;
}

void SCIONProtocol::removeDispatcher(int sock)
{
}

// SSP

SSPProtocol::SSPProtocol(std::vector<SCIONAddr> &dstAddrs, short srcPort, short dstPort)
    : SCIONProtocol(dstAddrs, srcPort, dstPort),
    mFlowID(0),
    mInitialized(false),
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
    mReadyPackets = new OrderedList<SSPPacket *>(NULL, destroySSPPacket);
    mOOPackets = new OrderedList<SSPPacket *>(compareOffset, destroySSPPacket);

    if (dstAddrs.size() > 0) {
        while (mFlowID == 0)
            mFlowID = createRandom(64);
    }

    getWindowSize();

    pthread_mutex_init(&mSelectMutex, NULL);
}

SSPProtocol::~SSPProtocol()
{
    mState = SCION_CLOSED;
    pthread_cancel(mTimerThread);
    if (mConnectionManager) {
        delete mConnectionManager;
        mConnectionManager = NULL;
    }
    mReadyPackets->clean();
    delete mReadyPackets;
    mOOPackets->clean();
    delete mOOPackets;
    pthread_mutex_destroy(&mSelectMutex);
}

void SSPProtocol::createManager(std::vector<SCIONAddr> &dstAddrs, bool paths)
{
    mConnectionManager = new SSPConnectionManager(dstAddrs, mSocket, this);
    mPathManager = mConnectionManager;
    if (paths)
        mConnectionManager->getPaths();
    else
        mConnectionManager->getLocalAddress();
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
    size_t room = mLocalSendWindow - mConnectionManager->totalQueuedSize();

    if (mBlocking) {
        mConnectionManager->waitForSendBuffer(len, mLocalSendWindow);
    } else if (room < len) {
        return -EWOULDBLOCK;
    }

    while (len > 0) {
        bool sendAll = isFirstPacket();
        size_t packetLen = packetMax > len ? len : packetMax;
        len -= packetLen;
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
        if (!mBlocking) {
            pthread_mutex_unlock(&mReadMutex);
            return -EWOULDBLOCK;
        }
        pthread_cond_wait(&mReadCond, &mReadMutex);
    }
    pthread_mutex_lock(&mStateMutex);
    if (mState == SCION_CLOSED || mState == SCION_FIN_READ) {
        pthread_mutex_unlock(&mStateMutex);
        pthread_mutex_unlock(&mReadMutex);
        DEBUG("%lu: connection has already terminated\n", mFlowID);
        return 0;
    }
    pthread_mutex_unlock(&mStateMutex);

    DEBUG("start recv\n");
    while (!mReadyPackets->empty()) {
        if (total >= (int)len) {
            DEBUG("filled user buffer\n");
            break;
        }
        SSPPacket *sp = mReadyPackets->front();
        if (sp->header.offset != mNextPacket) {
            DEBUG("missing packet %lu\n", mNextPacket);
            missing = true;
            break;
        }
        size_t currentPacket = sp->len - sp->dataOffset;
        size_t toRead = len - total > currentPacket ? currentPacket : len - total;
        DEBUG("reading %lu bytes\n", toRead);
        if (sp->header.flags & SSP_FIN) {
            DEBUG("%lu: recv'd FIN packet\n", mFlowID);
            pthread_mutex_lock(&mStateMutex);
            mState = SCION_FIN_READ;
            pthread_mutex_unlock(&mStateMutex);
        } else {
            memcpy(ptr, sp->data.get() + sp->dataOffset, toRead);
            ptr += toRead;
            total += toRead;
            sp->dataOffset += toRead;
        }
        if (sp->dataOffset == sp->len) {
            DEBUG("%lu: done with packet %lu\n", mFlowID, sp->header.offset);
            mReadyPackets->pop();
            didRead(sp);
        }
    }
    if (mReadyPackets->empty() || missing) {
        DEBUG("no more data ready\n");
        pthread_mutex_lock(&mStateMutex);
        if (mState != SCION_CLOSED && mState != SCION_FIN_READ)
            mReadyToRead = false;
        pthread_mutex_unlock(&mStateMutex);
    }
    pthread_mutex_unlock(&mReadMutex);
    if (!total)
        DEBUG("%lu: connection has terminated\n", mFlowID);
    DEBUG("%lu: recv'd total %d bytes\n", mFlowID, total);
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
    DEBUG("%lu created\n", mFlowID);
    SSPEntry se;
    se.flowID = mFlowID;
    se.port = 0;
    registerFlow(SCION_PROTO_SSP, &se, sock, 1);
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
    buildSSPHeader(&(sp->header), ptr);

    int payloadLen = sch.totalLen - sch.headerLen - sp->header.headerLen;
    SCIONExtension *ext = packet->header.extensions;
    while (ext != NULL) {
        payloadLen -= (ext->headerLen + 1) * 8;
        ext = ext->nextExt;
    }
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
        buildSSPAck(&(sp->ack), ptr);
        mConnectionManager->handleAck(packet, mInitAckCount, mIsReceiver);
    }

    ext = findProbeExtension(&packet->header);
    if (ext != NULL) {
        uint32_t probeNum = getProbeNum(ext);
        if (isProbeAck(ext)) {
            if (probeNum == mProbeNum)
                mConnectionManager->handleProbeAck(packet);
        } else {
            handleProbe(packet);
        }
    }

    if (payloadLen > 0 || sp->header.flags & SSP_FIN) {
        if (payloadLen > 0) {
            sp->data = std::shared_ptr<uint8_t>((uint8_t *)malloc(payloadLen), free);
            memcpy(sp->data.get(), ptr, payloadLen);
            sp->len = payloadLen;
        }
        handleData(sp, packet->pathIndex);
    } else {
        destroySSPPacket(sp);
    }

    destroySCIONPacket(packet);
    return 0;
}

void SSPProtocol::handleProbe(SCIONPacket *packet)
{
    DEBUG("incoming probe\n");
    SCIONExtension *ext = findProbeExtension(&packet->header);
    uint32_t probeNum = getProbeNum(ext);
    SCIONPacket p;
    memset(&p, 0, sizeof(p));
    buildCommonHeader(p.header.commonHeader, SCION_PROTO_SSP);
    addProbeExtension(&p.header, probeNum, 1);
    p.pathIndex = packet->pathIndex;
    SSPPacket sp;
    p.payload = &sp;
    sp.header.flowID = htobe64(mFlowID);
    sp.header.headerLen = sizeof(sp.header);
    mConnectionManager->sendAck(&p);
}

SSPPacket * SSPProtocol::checkOutOfOrderQueue(SSPPacket *sp)
{
    uint64_t start = sp->header.offset;
    uint64_t end = start + sp->len;
    bool pushed = false;
    SSPPacket *last = sp;
    if (mOOPackets->empty()) {
        mReadyPackets->push(sp);
        mLowestPending = end;
        pushed = true;
    } else {
        while (!mOOPackets->empty()) {
            DEBUG("check out-of-order queue\n");
            last = (SSPPacket *)mOOPackets->front();
            if (last->header.offset < end)
                break;
            if (!pushed) {
                mReadyPackets->push(sp);
                mLowestPending = end;
                pushed = true;
            }
            start = last->header.offset;
            end = start + last->len;
            DEBUG("packet: %lu ~ %lu\n", start, end);
            if (start <= mLowestPending && end > mLowestPending) {
                mOOPackets->pop();
                mReadyPackets->push(last);
                mLowestPending = end;
            } else {
                break;
            }
        }
    }
    return pushed ? last : NULL;
}

void SSPProtocol::signalSelect()
{
    pthread_mutex_lock(&mSelectMutex);
    std::map<int, Notification>::iterator i;
    for (i = mSelectRead.begin(); i != mSelectRead.end(); i++) {
        Notification &n = i->second;
        pthread_mutex_lock(n.mutex);
        pthread_cond_signal(n.cond);
        pthread_mutex_unlock(n.mutex);
    }
    pthread_mutex_unlock(&mSelectMutex);
}

void SSPProtocol::handleInOrder(SSPPacket *sp, int pathIndex)
{
    DEBUG("in-order packet: %lu\n", sp->header.offset);

    uint64_t start = sp->header.offset;
    uint64_t end = start + sp->len;
    int packetSize = end - start + sizeof(SSPPacket);

    pthread_mutex_lock(&mReadMutex);

    if (!(sp->header.flags & SSP_FIN) &&
            packetSize + mTotalReceived > mLocalReceiveWindow) {
        DEBUG("in-order packet %lu: Receive window too full: %u/%u\n",
                sp->header.offset, mTotalReceived, mLocalReceiveWindow);
        sp->header.offset = mHighestReceived;
        sendAck(sp, pathIndex, true);
        sp->data = NULL;
        destroySSPPacket(sp);
        pthread_mutex_unlock(&mReadMutex);
        return;
    }

    if (end - 1 > mHighestReceived)
        mHighestReceived = end - 1;

    SSPPacket *last = checkOutOfOrderQueue(sp);
    if (last) {
        DEBUG("lowest pending now %lu\n", mLowestPending);
        mTotalReceived += packetSize;
        DEBUG("receive window now %u/%u\n", mTotalReceived, mLocalReceiveWindow);
        sendAck(sp, pathIndex);
        mReadyToRead = true;
        signalSelect();
        if (last->header.flags & SSP_FIN) {
            DEBUG("%lu: Read up to FIN flag, connection done\n", mFlowID);
            pthread_mutex_lock(&mStateMutex);
            mState = SCION_FIN_RCVD;
            pthread_mutex_unlock(&mStateMutex);
        }
    } else {
        DEBUG("packet was resent on smaller path(s), discard original\n");
    }
    pthread_mutex_unlock(&mReadMutex);
    pthread_cond_signal(&mReadCond);
}

void SSPProtocol::handleOutOfOrder(SSPPacket *sp, int pathIndex)
{
    DEBUG("out-of-order packet %lu (%lu)\n", sp->header.offset, mLowestPending);

    uint64_t start = sp->header.offset;
    uint64_t end = start + sp->len;
    int maxPayload = mConnectionManager->maxPayloadSize();
    int packetSize = end - start + sizeof(SSPPacket);

    pthread_mutex_lock(&mReadMutex);

    if (!(sp->header.flags & SSP_FIN) &&
            packetSize + mTotalReceived > mLocalReceiveWindow - maxPayload) {
        DEBUG("out-of-order packet %lu(%lu): Receive window too full: %d/%u\n",
                sp->header.offset, mLowestPending,
                mTotalReceived, mLocalReceiveWindow);
        sp->header.offset = mHighestReceived;
        sendAck(sp, pathIndex, true);
        sp->data = NULL;
        destroySSPPacket(sp);
        pthread_mutex_unlock(&mReadMutex);
        return;
    }

    if (end - 1 > mHighestReceived)
        mHighestReceived = end - 1;

    bool found = mOOPackets->push(sp);
    if (found) {
        DEBUG("duplicate packet: discard\n");
        pthread_mutex_unlock(&mReadMutex);
        sendAck(sp, pathIndex);
        destroySSPPacket(sp);
    } else {
        DEBUG("added to out-of-order queue\n");
        mTotalReceived += packetSize;
        DEBUG("receive window now %u/%u\n", mTotalReceived, mLocalReceiveWindow);
        pthread_mutex_unlock(&mReadMutex);
        sendAck(sp, pathIndex);
    }
}

void SSPProtocol::handleData(SSPPacket *sp, int pathIndex)
{
    uint64_t start = sp->header.offset;
    uint64_t end = start + sp->len;
    DEBUG("Incoming SSP packet %lu ~ %lu\n", start, end);
    if (end <= mLowestPending && !(sp->header.flags & SSP_FIN)) {
        DEBUG("Obsolete packet\n");
        sendAck(sp, pathIndex);
        destroySSPPacket(sp);
        return;
    }

    if (sp->header.flags & SSP_FIN)
        DEBUG("%lu: handleData for FIN packet %lu (%lu)\n", mFlowID, start, mLowestPending);

    struct timeval now;
    gettimeofday(&now, NULL);

    if (start == mLowestPending) {
        handleInOrder(sp, pathIndex);
    } else {
        handleOutOfOrder(sp, pathIndex);
    }
}

void SSPProtocol::sendAck(SSPPacket *inPacket, int pathIndex, bool full)
{
    uint64_t packetNum = inPacket->header.offset;
    DEBUG("send ack for %lu (path %d)\n", packetNum, pathIndex);

    if (inPacket->header.flags & SSP_FIN)
        DEBUG("%lu: send ack for FIN packet %lu\n", mFlowID, packetNum);

    SCIONPacket packet;
    memset(&packet, 0, sizeof(SCIONPacket));
    buildCommonHeader(packet.header.commonHeader, SCION_PROTO_SSP);
    packet.pathIndex = pathIndex;

    SSPPacket sp;
    packet.payload = &sp;
    // basic header stuff
    SSPHeader &sh = sp.header;
    sh.flags |= SSP_ACK;
    if (inPacket->header.flags & SSP_FIN)
        sh.flags |= SSP_FIN;
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
    DEBUG("%s: created packet %lu at %p\n", __func__, be64toh(sp->header.offset), packet);
    if (!mInitialized) {
        DEBUG("include window size for initial packet\n");
        sp->header.flags |= SSP_WINDOW;
        sp->windowSize = htonl(mLocalReceiveWindow);
        sp->header.headerLen += 4;
        mInitialized = true;
    }
    if (len > 0) {
        sp->data = std::shared_ptr<uint8_t>((uint8_t *)malloc(len), free);
        memcpy(sp->data.get(), buf, len);
    }
    sp->len = len;
    mNextSendByte += len;

    return packet;
}

void SSPProtocol::handleTimerEvent()
{
    struct timeval current;
    gettimeofday(&current, NULL);
    mConnectionManager->handleTimeout();
    if (elapsedTime(&mLastProbeTime, &current) >= mProbeInterval) {
        mConnectionManager->sendProbes(++mProbeNum, mFlowID);
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

int SSPProtocol::shutdown()
{
    pthread_mutex_lock(&mStateMutex);
    DEBUG("%lu: shutdown\n", mFlowID);
    if (mState == SCION_CLOSED) {
        pthread_mutex_unlock(&mStateMutex);
        return 0;
    }
    if (mState == SCION_FIN_READ ||
            mState == SCION_FIN_RCVD ||
            (!mIsReceiver && mNextSendByte == 0)) {
        if (mState == SCION_RUNNING)
            mState = SCION_CLOSED;
        pthread_mutex_unlock(&mStateMutex);
        pthread_mutex_lock(&mReadMutex);
        mReadyToRead = true;
        pthread_cond_broadcast(&mReadCond);
        pthread_mutex_unlock(&mReadMutex);
        return 0;
    }
    mState = SCION_SHUTDOWN;
    pthread_mutex_unlock(&mStateMutex);

    SCIONPacket *packet = createPacket(NULL, 0);
    SSPPacket *sp = (SSPPacket *)(packet->payload);
    sp->header.flags |= SSP_FIN;
    mConnectionManager->queuePacket(packet);
    DEBUG("%lu: FIN packet (%lu) sent\n", mFlowID, be64toh(sp->header.offset));
    return 0;
}

void SSPProtocol::notifyFinAck()
{
    pthread_mutex_lock(&mStateMutex);
    mState = SCION_CLOSED;
    pthread_mutex_unlock(&mStateMutex);
    pthread_mutex_lock(&mReadMutex);
    mReadyToRead = true;
    pthread_cond_broadcast(&mReadCond);
    pthread_mutex_unlock(&mReadMutex);
}

void SSPProtocol::removeDispatcher(int sock)
{
    SSPEntry se;
    se.flowID = mFlowID;
    se.port = 0;
    registerFlow(SCION_PROTO_SSP, &se, sock, 0);
}

// SUDP

SUDPProtocol::SUDPProtocol(std::vector<SCIONAddr> &dstAddrs, short srcPort, short dstPort)
    : SCIONProtocol(dstAddrs, srcPort, dstPort),
    mTotalReceived(0)
{
}

SUDPProtocol::~SUDPProtocol()
{
    mState = SCION_CLOSED;
    pthread_join(mTimerThread, NULL);
    delete mConnectionManager;
}

void SUDPProtocol::createManager(std::vector<SCIONAddr> &dstAddrs, bool paths)
{
    mConnectionManager = new SUDPConnectionManager(dstAddrs, mSocket);
    mPathManager = mConnectionManager;
    pthread_create(&mTimerThread, NULL, timerThread, this);
}

int SUDPProtocol::send(uint8_t *buf, size_t len, DataProfile profile)
{
    DEBUG("send %lu byte packet\n", len);
    SCIONPacket packet;
    memset(&packet, 0, sizeof(packet));
    buildCommonHeader(packet.header.commonHeader, SCION_PROTO_UDP);
    SUDPPacket sp;
    memset(&sp, 0, sizeof(sp));
    packet.payload = &sp;
    SUDPHeader &sh = sp.header;
    sh.srcPort = htons(mSrcPort);
    sh.dstPort = htons(mDstPort);
    sh.len = htons(sizeof(SUDPHeader) + len);
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
    while (mReceivedPackets.empty()) {
        if (!mBlocking) {
            pthread_mutex_unlock(&mReadMutex);
            return -1;
        }
        pthread_cond_wait(&mReadCond, &mReadMutex);
    }
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
    sp->header.len = ntohs(*(uint16_t *)ptr);
    ptr += 2;
    sp->header.checksum = ntohs(*(uint16_t *)ptr);
    ptr += 2;
    sp->payloadLen = sch.totalLen - sch.headerLen - sizeof(SUDPHeader);
    SCIONExtension *ext = packet->header.extensions;
    while (ext != NULL) {
        sp->payloadLen -= (ext->headerLen + 1) * SCION_EXT_LINE;
        ext = ext->nextExt;
    }
    bool isProbe = findProbeExtension(&packet->header) != NULL;
    DEBUG("payload %lu bytes\n", sp->payloadLen);
    if (sp->payloadLen > 0) {
        sp->payload = malloc(sp->payloadLen);
        memcpy(sp->payload, ptr, sp->payloadLen);
    }
    mConnectionManager->handlePacket(packet);
    if (!isProbe && sp->payloadLen > 0) {
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
    } else if (isProbe) {
        sp->payload = NULL;
        destroySUDPPacket(sp);
    }
    destroySCIONPacket(packet);
    return 0;
}

void SUDPProtocol::handleTimerEvent()
{
    struct timeval t;
    gettimeofday(&t, NULL);
    if (elapsedTime(&mLastProbeTime, &t) >= SUDP_PROBE_INTERVAL) {
        mConnectionManager->sendProbes(++mProbeNum, mSrcPort, mDstPort);
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
