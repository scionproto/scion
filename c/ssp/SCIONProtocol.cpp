/* Copyright 2015 ETH Zurich
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <unistd.h>
#include <arpa/inet.h>

#include "Extensions.h"
#include "Mutex.h"
#include "ProtocolConfigs.h"
#include "SCIONProtocol.h"
#include "Utils.h"

void timerCleanup(void *arg)
{
    SCIONProtocol *p = (SCIONProtocol *)arg;
    p->threadCleanup();
}

void * timerThread(void *arg)
{
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    SCIONProtocol *p = (SCIONProtocol *)arg;
    pthread_cleanup_push(timerCleanup, arg);
    while (p->isRunning()) {
        p->handleTimerEvent();
        usleep(SCION_TIMER_INTERVAL);
    }
    pthread_cleanup_pop(1);
    return NULL;
}

SCIONProtocol::SCIONProtocol(int sock, const char *sciond)
    : mPathManager(NULL),
    mSrcPort(0),
    mDstPort(0),
    mIsReceiver(false),
    mReadyToRead(false),
    mBlocking(true),
    mState(SCION_RUNNING),
    mNextSendByte(0),
    mProbeNum(0)
{
    mSocket = sock; // gets closed by SCIONSocket
    memset(&mDstAddr, 0, sizeof(mDstAddr));
    gettimeofday(&mLastProbeTime, NULL);
    Mutex mReadMutex;
    Mutex mStateMutex;
    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_REALTIME);
    pthread_cond_init(&mReadCond, &ca);
}

SCIONProtocol::~SCIONProtocol() EXCLUDES(mReadMutex, mStateMutex)
{
    mState = SCION_CLOSED;
    pthread_cond_destroy(&mReadCond);
}

int SCIONProtocol::bind(SCIONAddr addr, int sock)
{
    mSrcPort = addr.host.port;
    return mPathManager->setLocalAddress(addr);
}

int SCIONProtocol::connect(SCIONAddr addr, double timeout)
{
    return 0;
}

int SCIONProtocol::listen(int sock)
{
    return 0;
}

int SCIONProtocol::send(uint8_t *buf, size_t len, SCIONAddr *dstAddr, double timeout)
{
    return 0;
}

int SCIONProtocol::recv(uint8_t *buf, size_t len, SCIONAddr *srcAddr, double timeout)
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

void SCIONProtocol::handlePathError(SCIONPacket *packet)
{
    mPathManager->handlePathError(packet);
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

int SCIONProtocol::registerDispatcher(uint64_t flowID, uint16_t port, int sock)
{
    return 0;
}

int SCIONProtocol::setISDWhitelist(void *data, size_t len)
{
    if (!mPathManager)
        return -EPERM;
    // Disallow changing policy if connection is already active
    if (mNextSendByte != 1)
        return -EPERM;
    return mPathManager->setISDWhitelist(data, len);
}

int SCIONProtocol::shutdown(bool force)
{
    return 0;
}

uint32_t SCIONProtocol::getLocalIA()
{
    if (!mPathManager)
        return 0;
    SCIONAddr *addr = mPathManager->localAddress();
    if (addr->isd_as == 0)
        mPathManager->queryLocalAddress();
    return addr->isd_as;
}

void SCIONProtocol::threadCleanup() EXCLUDES(mReadMutex, mStateMutex)
{
    if (mPathManager)
        mPathManager->threadCleanup();
}

int SCIONProtocol::getPort()
{
    return mSrcPort;
}

int SCIONProtocol::maxPayloadSize(double timeout)
{
    if (!mPathManager)
        return -1;
    return mPathManager->maxPayloadSize(timeout);
}

// SSP

SSPProtocol::SSPProtocol(int sock, const char *sciond)
    : SCIONProtocol(sock, sciond),
    mInitialized(false),
    mInitAckCount(0),
    mFlowID(0),
    mLowestPending(0),
    mHighestReceived(0),
    mAckVectorOffset(0),
    mTotalReceived(0),
    mNextPacket(0),
    mSelectCount(0)
{
    mProtocolID = L4_SSP;
    mProbeInterval = SSP_PROBE_INTERVAL;
    mReadyPackets = new OrderedList<SSPPacket *>(NULL, destroySSPPacket);
    mOOPackets = new OrderedList<SSPPacket *>(compareOffset, destroySSPPacket);

    getWindowSize();

    Mutex mSelectMutex;

    mConnectionManager = new SSPConnectionManager(mSocket, sciond, this);
    mPathManager = mConnectionManager;
    pthread_create(&mTimerThread, NULL, timerThread, this);
}

SSPProtocol::~SSPProtocol() EXCLUDES(mSelectMutex)
{
    mState = SCION_CLOSED;
    pthread_cancel(mTimerThread);
    pthread_join(mTimerThread, NULL);
    if (mConnectionManager) {
        delete mConnectionManager;
        mConnectionManager = NULL;
    }
    mReadyPackets->clean();
    delete mReadyPackets;
    mOOPackets->clean();
    delete mOOPackets;
}

int SSPProtocol::connect(SCIONAddr addr, double timeout)
{
    if (mNextSendByte != 0) {
        DEBUG("connection already established\n");
        return -1;
    }

    int ret = mConnectionManager->setRemoteAddress(addr, timeout);
    if (ret < 0) {
        DEBUG("setRemoteAddress failed: %d\n", ret);
        return ret;
    }
    mDstAddr = addr;
    mDstPort = addr.host.port;

    uint8_t buf = 0;
    SCIONPacket *packet = createPacket(&buf, 1);
    SSPPacket *sp = (SSPPacket *)packet->payload;
    sp->header.flags |= SSP_CON;
    mConnectionManager->queuePacket(packet);
    return 0;
}

int SSPProtocol::listen(int sock)
{
    SCIONAddr *addr = mConnectionManager->localAddress();
    if (addr->isd_as == 0) {
        DEBUG("socket not bound yet\n");
        return -1;
    }

    mSrcPort = registerDispatcher(0, 0, sock);
    return 0;
}

int SSPProtocol::send(uint8_t *buf, size_t len, SCIONAddr *dstAddr, double timeout)
{
    uint8_t *ptr = buf;
    size_t total_len = len;
    size_t room = mLocalSendWindow - mConnectionManager->totalQueuedSize();
    int packetMax = mConnectionManager->maxPayloadSize(timeout);

    if (packetMax < 0)
        return packetMax;

    if (!mBlocking && room < len) {
        DEBUG("non-blocking socket not ready to send\n");
        return -EWOULDBLOCK;
    }

    while (len > 0) {
        size_t packetLen = (size_t)packetMax > len ? len : packetMax;
        len -= packetLen;
        SCIONPacket *packet = createPacket(ptr, packetLen);
        if (mConnectionManager->waitForSendBuffer(packetLen, mLocalSendWindow, timeout) == -ETIMEDOUT) {
            DEBUG("timed out in send\n");
            return -ETIMEDOUT;
        }
        mConnectionManager->queuePacket(packet);
        ptr += packetLen;
    }
    return total_len;
}

int SSPProtocol::recv(uint8_t *buf, size_t len, SCIONAddr *srcAddr, double timeout) EXCLUDES(mReadMutex, mStateMutex)
{
    int total = 0;
    uint8_t *ptr = buf;
    bool missing = false;

    mReadMutex.Lock();
    while (!mReadyToRead) {
        DEBUG("%p: no data to read yet\n", this);
        if (!mBlocking) {
            mReadMutex.Unlock();
            DEBUG("non-blocking socket not ready to recv\n");
            return -EWOULDBLOCK;
        }
        if (timeout > 0.0) {
            if (timedWaitMutex(&mReadCond, &mReadMutex, timeout) == ETIMEDOUT) {
                mReadMutex.Unlock();
                DEBUG("%p: timeout in recv\n", this);
                return -ETIMEDOUT;
            }
        } else {
            mReadMutex.condWait(&mReadCond);
        }
    }
    mStateMutex.Lock();
    if (mState == SCION_CLOSED || mState == SCION_FIN_READ) {
        mStateMutex.Unlock();
        mReadMutex.Unlock();
        DEBUG("%p: connection has already terminated (%d)\n", this, mState);
        return 0;
    }
    mStateMutex.Unlock();

    DEBUG("%p: start recv\n", this);
    while (!mReadyPackets->empty()) {
        if (total >= (int)len) {
            DEBUG("filled user buffer\n");
            break;
        }
        SSPPacket *sp = mReadyPackets->front();
        if (sp->getOffset() != mNextPacket) {
            DEBUG("missing packet %lu\n", mNextPacket);
            missing = true;
            break;
        }
        size_t currentPacket = sp->len - sp->dataOffset;
        size_t toRead = len - total > currentPacket ? currentPacket : len - total;
        DEBUG("reading %lu bytes\n", toRead);
        if (sp->header.flags & SSP_FIN) {
            DEBUG("%p: recv'd FIN packet\n", this);
            mStateMutex.Lock();
            mState = SCION_FIN_READ;
            mStateMutex.Unlock();
        } else {
            memcpy(ptr, sp->data.get() + sp->dataOffset, toRead);
            ptr += toRead;
            total += toRead;
            sp->dataOffset += toRead;
        }
        if (sp->dataOffset == sp->len) {
            DEBUG("%p: done with packet %lu\n", this, sp->getOffset());
            mReadyPackets->pop();
            mNextPacket += sp->len;
            mTotalReceived -= sizeof(SSPPacket) + sp->len;
            DEBUG("%u bytes in receive buffer\n", mTotalReceived);
            destroySSPPacket(sp);
        }
    }
    if (mReadyPackets->empty() || missing) {
        DEBUG("no more data ready\n");
        mStateMutex.Lock();
        if (mState != SCION_CLOSED && mState != SCION_FIN_READ)
            mReadyToRead = false;
        mStateMutex.Unlock();
    }
    mReadMutex.Unlock();
    if (!total)
        DEBUG("%p: connection has terminated\n", this);
    DEBUG("%p: recv'd total %d bytes\n", this, total);
    return total;
}

bool SSPProtocol::claimPacket(SCIONPacket *packet, uint8_t *buf)
{
    uint64_t flowID = be64toh(*(uint64_t *)buf) & ~1;
    DEBUG("mFlowID = %lu, incoming flowID = %lu\n", mFlowID, flowID);
    return flowID == mFlowID;
}

void SSPProtocol::start(SCIONPacket *packet, uint8_t *buf, int sock)
{
    if (buf) {
        mIsReceiver = true;
        mFlowID = be64toh(*(uint64_t *)buf) & ~1;
    } else {
        mIsReceiver = false;
        mFlowID = createRandom(64) & ~1;
    }
    DEBUG("%lu created\n", mFlowID);

    mSrcPort = registerDispatcher(0, 0, sock);
    DEBUG("start protocol for flow %lu\n", mFlowID);
    if (packet && buf)
        handlePacket(packet, buf);
}

void SSPProtocol::getWindowSize()
{
    // Eventually determine based on system resources
    mLocalReceiveWindow = SSP_DEFAULT_SEND_WINDOW_SIZE;
    mLocalSendWindow = SSP_DEFAULT_RECV_WINDOW_SIZE;
}

int SSPProtocol::getDeadlineFromProfile(DataProfile profile)
{
    return 50000;
}

int SSPProtocol::handlePacket(SCIONPacket *packet, uint8_t *buf)
{
    DEBUG("incoming SSP packet\n");

    uint8_t *ptr = buf;
    SCIONCommonHeader *sch = &packet->header.commonHeader;
    if (mDstAddr.isd_as == 0) {
        mDstAddr.isd_as = ntohl(*(uint32_t *)(packet->header.srcAddr));
        mDstAddr.host.addr_type = SRC_TYPE(sch);
        memcpy(mDstAddr.host.addr, packet->header.srcAddr + ISD_AS_LEN, get_addr_len(mDstAddr.host.addr_type));
    }

    // Build SSP incoming packet
    SSPPacket *sp = new SSPPacket();
    buildSSPHeader(&(sp->header), ptr);
    int payloadLen = sch->total_len - sch->header_len - sp->header.headerLen;
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
        int interfaceLen = IF_TOTAL_LEN * sp->interfaceCount;
        sp->interfaces = (uint8_t *)malloc(interfaceLen);
        memcpy(sp->interfaces, ptr, interfaceLen);
        ptr += interfaceLen;
    }

    packet->payload = sp;
    mConnectionManager->handlePacket(packet, mIsReceiver);

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

    if (payloadLen > 0 ||
            ((sp->header.flags & SSP_FIN) && !(sp->header.flags & SSP_ACK))) {
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
    SCIONAddr *localAddr = mConnectionManager->localAddress();
    SCIONPacket p;
    memset(&p, 0, sizeof(p));
    pack_cmn_hdr((uint8_t *)&p.header.commonHeader,
            localAddr->host.addr_type, mDstAddr.host.addr_type, L4_SSP, 0, 0, 0);
    addProbeExtension(&p.header, probeNum, 1);
    p.pathIndex = packet->pathIndex;
    SSPPacket sp;
    p.payload = &sp;
    if (mIsReceiver)
        sp.setFlowID(mFlowID);
    else
        sp.setFlowID(mFlowID | 1);
    sp.header.headerLen = sizeof(sp.header);
    mConnectionManager->sendAck(&p);
}

SSPPacket * SSPProtocol::checkOutOfOrderQueue(SSPPacket *sp)
{
    uint64_t start = sp->getOffset();
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
            if (last->getOffset() < end)
                break;
            if (!pushed) {
                mReadyPackets->push(sp);
                mLowestPending = end;
                pushed = true;
            }
            start = last->getOffset();
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

void SSPProtocol::signalSelect() EXCLUDES(mSelectMutex)
{
    DEBUG("signalSelect\n");
    mSelectMutex.Lock();
    std::map<int, Notification>::iterator i;
    for (i = mSelectRead.begin(); i != mSelectRead.end(); i++) {
        Notification &n = i->second;
        p_m_lock(n.mutex, __FILE__, __LINE__);
        pthread_cond_signal(n.cond);
        p_m_unlock(n.mutex, __FILE__, __LINE__);
        DEBUG("signalled select cond %d\n", i->first);
    }
    for (i = mSelectWrite.begin(); i != mSelectWrite.end(); i++) {
        Notification &n = i->second;
        p_m_lock(n.mutex, __FILE__, __LINE__);
        pthread_cond_signal(n.cond);
        p_m_unlock(n.mutex, __FILE__, __LINE__);
        DEBUG("signalled select cond %d\n", i->first);
    }
    mSelectMutex.Unlock();
}

void SSPProtocol::handleInOrder(SSPPacket *sp, int pathIndex) EXCLUDES(mReadMutex)
{
    DEBUG("in-order packet: %lu\n", sp->getOffset());

    uint64_t start = sp->getOffset();
    uint64_t end = start + sp->len;
    int packetSize = end - start + sizeof(SSPPacket);

    mReadMutex.Lock();

    if (!(sp->header.flags & SSP_FIN) &&
            packetSize + mTotalReceived > mLocalReceiveWindow) {
        DEBUG("in-order packet %lu: Receive window too full: %u/%u\n",
                sp->getOffset(), mTotalReceived, mLocalReceiveWindow);
        sp->setOffset(mHighestReceived);
        sendAck(sp, pathIndex);
        sp->data = NULL;
        destroySSPPacket(sp);
        mReadMutex.Unlock();
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
        if (last->header.flags & SSP_FIN) {
            DEBUG("%p: Read up to FIN flag, connection done\n", this);
            mStateMutex.Lock();
            mState = SCION_FIN_RCVD;
            mStateMutex.Unlock();
        }
    } else {
        DEBUG("packet was resent on smaller path(s), discard original\n");
    }
    mReadMutex.Unlock();
    pthread_cond_signal(&mReadCond);
    signalSelect();
}

void SSPProtocol::handleOutOfOrder(SSPPacket *sp, int pathIndex) EXCLUDES(mReadMutex)
{
    DEBUG("out-of-order packet %lu (%lu)\n", sp->getOffset(), mLowestPending);

    uint64_t start = sp->getOffset();
    uint64_t end = start + sp->len;
    int maxPayload = mConnectionManager->maxPayloadSize();
    int packetSize = end - start + sizeof(SSPPacket);

    mReadMutex.Lock();

    if (!(sp->header.flags & SSP_FIN) &&
            packetSize + mTotalReceived > mLocalReceiveWindow - maxPayload) {
        DEBUG("out-of-order packet %lu(%lu): Receive window too full: %d/%u\n",
                sp->getOffset(), mLowestPending,
                mTotalReceived, mLocalReceiveWindow);
        sp->setOffset(mHighestReceived);
        sendAck(sp, pathIndex);
        sp->data = NULL;
        destroySSPPacket(sp);
        mReadMutex.Unlock();
        return;
    }

    if (end - 1 > mHighestReceived)
        mHighestReceived = end - 1;

    bool found = mOOPackets->push(sp);
    if (found) {
        DEBUG("duplicate packet: discard\n");
        mReadMutex.Unlock();
        sendAck(sp, pathIndex);
        destroySSPPacket(sp);
    } else {
        DEBUG("added to out-of-order queue\n");
        mTotalReceived += packetSize;
        DEBUG("receive window now %u/%u\n", mTotalReceived, mLocalReceiveWindow);
        mReadMutex.Unlock();
        sendAck(sp, pathIndex);
    }
}

void SSPProtocol::handleData(SSPPacket *sp, int pathIndex)
{
    uint64_t start = sp->getOffset();
    uint64_t end = start + sp->len;
    DEBUG("Incoming SSP packet %lu ~ %lu\n", start, end);

    if (mIsReceiver && start == 0) {
        DEBUG("Connect packet received\n");
        mLowestPending = mLowestPending > end ? mLowestPending : end;
        mNextPacket = mNextPacket > end ? mNextPacket : end;
        sendAck(sp, pathIndex);
        destroySSPPacket(sp);
        return;
    }

    if (end <= mLowestPending && !(sp->header.flags & SSP_FIN)) {
        DEBUG("Obsolete packet\n");
        sendAck(sp, pathIndex);
        destroySSPPacket(sp);
        return;
    }

    if (sp->header.flags & SSP_FIN)
        DEBUG("%p: handleData for FIN packet %lu (%lu)\n", this, start, mLowestPending);

    struct timeval now;
    gettimeofday(&now, NULL);

    if (start == mLowestPending) {
        handleInOrder(sp, pathIndex);
    } else {
        handleOutOfOrder(sp, pathIndex);
    }
}

void SSPProtocol::sendAck(SSPPacket *inPacket, int pathIndex)
{
    uint64_t packetNum = inPacket->getOffset();
    DEBUG("%lu: send ack for %lu (path %d)\n", mFlowID, packetNum, pathIndex);

    if (inPacket->header.flags & SSP_FIN)
        DEBUG("%lu: send ack for FIN packet %lu\n", mFlowID, packetNum);

    SCIONAddr *localAddr = mConnectionManager->localAddress();
    SCIONPacket packet;
    memset(&packet, 0, sizeof(SCIONPacket));
    pack_cmn_hdr((uint8_t *)&packet.header.commonHeader,
            localAddr->host.addr_type, mDstAddr.host.addr_type, L4_SSP, 0, 0, 0);
    packet.pathIndex = pathIndex;

    SSPPacket sp;
    packet.payload = &sp;
    // basic header stuff
    SSPHeader &sh = sp.header;
    sh.flags |= SSP_ACK;
    if (inPacket->header.flags & SSP_FIN)
        sh.flags |= SSP_FIN;
    sh.headerLen = sizeof(SSPHeader) + sizeof(SSPAck);
    if (!mInitialized) {
        sh.flags |= SSP_WINDOW;
        sh.headerLen += 4;
        sp.windowSize = htonl(mLocalReceiveWindow);
        mRemoteWindow = inPacket->windowSize;
        mInitialized = true;
    }
    if (mIsReceiver)
        sp.setFlowID(mFlowID);
    else
        sp.setFlowID(mFlowID | 1);
    sp.setMark(inPacket->getMark());

    // ack stuff
    sp.setL(mLowestPending);
    sp.setI(packetNum - mLowestPending);
    sp.setH(mHighestReceived - mLowestPending);
    DEBUG("outgoing ACK: L = %lu, I = %d, H = %d, O = %d, V = %u\n",
            sp.getL(), sp.getI(), sp.getH(), sp.getO(), sp.getV());

    mConnectionManager->sendAck(&packet);
}

SCIONPacket * SSPProtocol::createPacket(uint8_t *buf, size_t len)
{
    SCIONAddr *localAddr = mConnectionManager->localAddress();
    SCIONPacket *packet = (SCIONPacket *)malloc(sizeof(SCIONPacket));
    memset(packet, 0, sizeof(SCIONPacket));
    pack_cmn_hdr((uint8_t *)&packet->header.commonHeader,
            localAddr->host.addr_type, mDstAddr.host.addr_type, L4_SSP, 0, 0, 0);

    SSPPacket *sp = new SSPPacket();
    packet->payload = sp;
    sp->header.headerLen = sizeof(SSPHeader);
    // Server's LSb is 1, so client sets outgoing LSb to 1
    if (mIsReceiver)
        sp->setFlowID(mFlowID);
    else
        sp->setFlowID(mFlowID | 1);
    sp->setPort(mInitialized ? 0 : mDstPort);
    sp->setOffset(mNextSendByte);
    DEBUG("%s: created packet %lu at %p\n", __func__, sp->getOffset(), packet);
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
    if (mDstAddr.isd_as != 0 && elapsedTime(&mLastProbeTime, &current) >= (int32_t)mProbeInterval) {
        mConnectionManager->sendProbes(++mProbeNum, mIsReceiver ? mFlowID : mFlowID | 1);
        mLastProbeTime = current;
    }
}

void SSPProtocol::getStats(SCIONStats *stats)
{
    if (mConnectionManager)
        mConnectionManager->getStats(stats);
}

bool SSPProtocol::readyToRead() EXCLUDES(mReadMutex)
{
    bool ready = false;
    mReadMutex.Lock();
    ready = mReadyToRead;
    mReadMutex.Unlock();
    return ready;
}

bool SSPProtocol::readyToWrite()
{
    return !mConnectionManager->bufferFull(mLocalSendWindow);
}

int SSPProtocol::registerSelect(Notification *n, int mode) EXCLUDES(mSelectMutex)
{
    mSelectMutex.Lock();
    if (mode == SCION_SELECT_READ)
        mSelectRead[++mSelectCount] = *n;
    else
        mSelectWrite[++mSelectCount] = *n;
    mSelectMutex.Unlock();
    DEBUG("registered index %d for mode %d\n", mSelectCount, mode);
    return mSelectCount;
}

void SSPProtocol::deregisterSelect(int index) EXCLUDES(mSelectMutex)
{
    mSelectMutex.Lock();
    if (mSelectRead.find(index) != mSelectRead.end()) {
        DEBUG("erase index %d from read list\n", index);
        mSelectRead.erase(index);
    } else {
        DEBUG("erase index %d from write list\n", index);
        mSelectWrite.erase(index);
    }
    mSelectMutex.Unlock();
}

void SSPProtocol::notifySender() EXCLUDES(mSelectMutex)
{
    mSelectMutex.Lock();
    std::map<int, Notification>::iterator i;
    for (i = mSelectWrite.begin(); i != mSelectWrite.end(); i++) {
        Notification &n = i->second;
        p_m_lock(n.mutex, __FILE__, __LINE__);
        pthread_cond_signal(n.cond);
        p_m_unlock(n.mutex, __FILE__, __LINE__);
    }
    mSelectMutex.Unlock();
}

int SSPProtocol::shutdown(bool force) EXCLUDES(mStateMutex)
{
    mStateMutex.Lock();
    DEBUG("%p: shutdown\n", this);
    if (mState == SCION_CLOSED) {
        mStateMutex.Unlock();
        return 0;
    }
    if (force ||
            mState == SCION_FIN_READ ||
            mState == SCION_FIN_RCVD ||
            (!mIsReceiver && mNextSendByte == 0)) {
        if (mState == SCION_RUNNING)
            mState = SCION_CLOSED;
        mStateMutex.Unlock();
        mReadMutex.Lock();
        mReadyToRead = true;
        pthread_cond_broadcast(&mReadCond);
        mReadMutex.Unlock();
        return 0;
    }
    mState = SCION_SHUTDOWN;
    mStateMutex.Unlock();

    SCIONPacket *packet = createPacket(NULL, 0);
    SSPPacket *sp = (SSPPacket *)(packet->payload);
    sp->header.flags |= SSP_FIN;
    mConnectionManager->queuePacket(packet);
    DEBUG("%lu: FIN packet (%lu) queued\n", mFlowID, sp->getOffset());
    return 0;
}

void SSPProtocol::notifyFinAck() EXCLUDES(mStateMutex, mReadMutex)
{
    mStateMutex.Lock();
    mState = SCION_CLOSED;
    mStateMutex.Unlock();
    mReadMutex.Lock();
    mReadyToRead = true;
    pthread_cond_broadcast(&mReadCond);
    mReadMutex.Unlock();
}

int SSPProtocol::registerDispatcher(uint64_t flowID, uint16_t port, int sock)
{
    SCIONAddr *localAddr = mConnectionManager->localAddress();
    if (localAddr->isd_as == 0)
        mConnectionManager->queryLocalAddress();
    DispatcherEntry de;
    memset(&de, 0, sizeof(de));
    de.flow_id = flowID > 0 ? flowID : mFlowID;
    if (mIsReceiver)
        de.flow_id = de.flow_id | 1;
    de.port = port > 0 ? port : htons(mSrcPort);
    de.isd_as = htonl(localAddr->isd_as);
    de.addr_type = localAddr->host.addr_type;
    memcpy(de.addr, localAddr->host.addr, MAX_HOST_ADDR_LEN);
    int ret = registerFlow(L4_SSP, &de, sock);
    if (mSrcPort > 0 && ret == 0)
        return mSrcPort;
    return ret;
}

void SSPProtocol::threadCleanup() EXCLUDES(mSelectMutex)
{
    SCIONProtocol::threadCleanup();
}

// SUDP

SUDPProtocol::SUDPProtocol(int sock, const char *sciond)
    : SCIONProtocol(sock, sciond),
    mTotalReceived(0)
{
    mConnectionManager = new SUDPConnectionManager(mSocket, sciond);
    mPathManager = mConnectionManager;
    pthread_create(&mTimerThread, NULL, timerThread, this);
}

SUDPProtocol::~SUDPProtocol()
{
    mState = SCION_CLOSED;
    pthread_join(mTimerThread, NULL);
    delete mConnectionManager;
}

int SUDPProtocol::bind(SCIONAddr addr, int sock)
{
    int ret = SCIONProtocol::bind(addr, sock);
    if (ret < 0)
        return ret;
    mSrcPort = registerDispatcher(0, addr.host.port, sock);
    if (mSrcPort < 0)
        return mSrcPort;
    return 0;
}

int SUDPProtocol::send(uint8_t *buf, size_t len, SCIONAddr *dstAddr, double timeout)
{
    if (dstAddr && mDstAddr.isd_as != dstAddr->isd_as) {
        memcpy(&mDstAddr, dstAddr, sizeof(SCIONAddr));
        mDstPort = mDstAddr.host.port;
        mConnectionManager->setRemoteAddress(mDstAddr);
    }
    DEBUG("send %lu byte packet\n", len);
    SCIONAddr *localAddr = mConnectionManager->localAddress();
    SCIONPacket packet;
    memset(&packet, 0, sizeof(packet));
    pack_cmn_hdr((uint8_t *)&packet.header.commonHeader,
            localAddr->host.addr_type, mDstAddr.host.addr_type, L4_UDP, 0, 0, 0);
    SUDPPacket sp;
    memset(&sp, 0, sizeof(sp));
    packet.payload = &sp;
    SUDPHeader &sh = sp.header;
    sh.srcPort = htons(mSrcPort);
    sh.dstPort = htons(mDstAddr.host.port);
    sh.len = htons(sizeof(SUDPHeader) + len);
    sp.payload = malloc(len);
    sp.payloadLen = len;
    memcpy(sp.payload, buf, len);
    int ret = mConnectionManager->sendPacket(&packet);
    if (ret < 0)
        return ret;
    return len;
}

int SUDPProtocol::recv(uint8_t *buf, size_t len, SCIONAddr *srcAddr, double timeout) EXCLUDES(mReadMutex)
{
    DEBUG("recv max %lu bytes\n", len);
    int size = 0;
    mReadMutex.Lock();
    while (mReceivedPackets.empty()) {
        if (!mBlocking) {
            mReadMutex.Unlock();
            return -1;
        }
        if (timeout > 0.0) {
            if (timedWaitMutex(&mReadCond, &mReadMutex, timeout) == ETIMEDOUT) {
                mReadMutex.Unlock();
                DEBUG("%p: timeout in recv\n", this);
                return -ETIMEDOUT;
            }
        } else {
            mReadMutex.condWait(&mReadCond);
        }
    }
    SCIONPacket *packet = mReceivedPackets.front();
    SUDPPacket *sp = (SUDPPacket *)(packet->payload);
    DEBUG("queued packet with len %lu bytes\n", sp->payloadLen);
    if (sp->payloadLen > len) {
        DEBUG("user buffer too short to read\n");
        mReadMutex.Unlock();
        return -1;
    }
    mReceivedPackets.pop_front();
    memcpy(buf, sp->payload, sp->payloadLen);
    size = sp->payloadLen;
    mTotalReceived -= sp->payloadLen + sizeof(SUDPPacket);
    mReadMutex.Unlock();
    DEBUG("recvd total %d bytes\n", size);
    if (srcAddr) {
        srcAddr->isd_as = ntohl(*(uint32_t *)packet->header.srcAddr);
        srcAddr->host.addr_type = SRC_TYPE(&(packet->header.commonHeader));
        memcpy(srcAddr->host.addr, packet->header.srcAddr + ISD_AS_LEN, MAX_HOST_ADDR_LEN);
        srcAddr->host.port = sp->header.srcPort;
    }
    destroySUDPPacket(sp);
    destroySCIONPacket(packet);
    return size;
}

int SUDPProtocol::handlePacket(SCIONPacket *packet, uint8_t *buf) EXCLUDES(mReadMutex)
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
    sp->payloadLen = sch.total_len - sch.header_len - sizeof(SUDPHeader);
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
            DEBUG("recv buffer full, discard new packet\n");
            destroySUDPPacket(sp);
        } else {
            DEBUG("signal recv\n");
            mReadMutex.Lock();
            mTotalReceived += size;
            mReceivedPackets.push_back(packet);
            mReadMutex.Unlock();
            pthread_cond_signal(&mReadCond);
        }
    } else if (isProbe) {
        sp->payload = NULL;
        destroySUDPPacket(sp);
        destroySCIONPacket(packet);
    }
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

int SUDPProtocol::registerDispatcher(uint64_t flowID, uint16_t port, int sock)
{
    SCIONAddr *addr = mConnectionManager->localAddress();

    DispatcherEntry e;
    e.flow_id = flowID;
    e.port = port > 0 ? htons(port) : htons(mSrcPort);
    e.addr_type = addr->host.addr_type;
    e.isd_as = htonl(addr->isd_as);
    memcpy(e.addr, addr->host.addr, MAX_HOST_ADDR_LEN);
    return registerFlow(L4_UDP, &e, sock);
}

void SUDPProtocol::getStats(SCIONStats *stats)
{
}
