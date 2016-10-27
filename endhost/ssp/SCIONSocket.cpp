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
#include <signal.h>
#include <sys/un.h>

#include "Extensions.h"
#include "Mutex.h"
#include "SCIONSocket.h"
#include "Path.h"

void signalHandler(int signum)
{
    switch (signum) {
    case SIGINT:
        fprintf(stderr, "Stop program\n");
        exit(1);
    default:
        printf("Signal %d\n", signum);
    }
}

static void receiverCleanup(void *arg)
{
    SCIONSocket *ss = (SCIONSocket *)arg;
    ss->threadCleanup();
}

void *dispatcherThread(void *arg)
{
    SCIONSocket *ss = (SCIONSocket *)arg;
    int sock = ss->getReliableSocket();
    uint8_t buf[DISPATCHER_BUF_SIZE];
    HostAddr addr;
    memset(&addr, 0, sizeof(addr));
    ss->waitForRegistration();
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_cleanup_push(receiverCleanup, arg);
    while (ss->isRunning()) {
        DEBUG("call recv on fd %d for SCIONSocket %p\n", sock, ss);
        int len = recv_all(sock, buf, DP_HEADER_LEN);
        if (len < 0) {
            DEBUG("error (%d) in dispatcher connection (fd %d): %s\n", len, sock, strerror(errno));
            ss->shutdown(true);
            return NULL;
        }
        uint8_t addr_type = 0;
        int packet_len = 0;
        parse_dp_header(buf, &addr_type, &packet_len);
        if (packet_len == 0) {
            fprintf(stderr, "invalid dispatcher header\n");
            exit(1);
        }
        int addr_len = get_addr_len(addr_type);
        len = recv_all(sock, buf, addr_len + 2 + packet_len);
        if (len > 0) {
            DEBUG("received %d bytes from dispatcher, addr_len = %d\n", len, addr_len);
            addr.addr_type = addr_type;
            memcpy(&addr.addr, buf, addr_len);
            addr.port = *(uint16_t *)(buf + addr_len);
            ss->handlePacket(buf + addr_len + 2, packet_len, &addr);
        }
    }
    pthread_cleanup_pop(1);
    return NULL;
}

int setupSocket()
{
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    return sock;
}

SCIONSocket::SCIONSocket(int protocol, const char *sciond)
    : mProtocolID(protocol),
    mRegistered(false),
    mState(SCION_RUNNING),
    mLastAccept(-1),
    mIsListener(false),
    mBound(false),
    mTimeout(0.0),
    mParent(NULL),
    mDataProfile(SCION_PROFILE_DEFAULT)
{
    struct sigaction signew, sigold;
    memset(&sigold, 0, sizeof(sigold));
    memset(&signew, 0, sizeof(signew));
    signew.sa_handler = signalHandler;
    sigaction(SIGINT, NULL, &sigold);
    if (!sigold.sa_handler) {
        DEBUG("install SIGINT handler as none exists\n");
        sigaction(SIGINT, &signew, NULL);
    }

    strcpy(mSCIONDAddr, sciond);
    memset(&mLocalAddr, 0, sizeof(mLocalAddr));

    Mutex mAcceptMutex;
    Mutex mRegisterMutex;
    Mutex mSelectMutex;
    // init pthread variables
    pthread_cond_init(&mAcceptCond, NULL);
    pthread_cond_init(&mRegisterCond, NULL);

    // open dispatcher socket
    mReliableSocket = setupSocket();

    switch (protocol) {
        case L4_SSP: {
            mProtocol = new SSPProtocol(mReliableSocket, sciond);
            break;
        }
        case L4_UDP: {
            mProtocol = new SUDPProtocol(mReliableSocket, sciond);
            break;
        }
        default:
            break;
    }

    pthread_create(&mReceiverThread, NULL, dispatcherThread, this);
}

SCIONSocket::~SCIONSocket() EXCLUDES(mAcceptMutex, mRegisterMutex)
{
    mState = SCION_CLOSED;
    pthread_cancel(mReceiverThread);
    pthread_join(mReceiverThread, NULL);
    delete mProtocol;
    mProtocol = NULL;
    close(mReliableSocket);
    pthread_cond_destroy(&mAcceptCond);
    pthread_cond_destroy(&mRegisterCond);
    if (mParent)
        mParent->removeChild(this);
}

SCIONSocket * SCIONSocket::accept() EXCLUDES(mAcceptMutex)
{
    if (mState == SCION_CLOSED)
        return NULL;
    SCIONSocket *s;
    mAcceptMutex.Lock();
    while (mLastAccept >= (int)mAcceptedSockets.size() - 1)
        mAcceptMutex.condWait(&mAcceptCond);
    if (mState == SCION_CLOSED) {
        mAcceptMutex.Unlock();
        return NULL;
    }
    s = mAcceptedSockets[++mLastAccept];
    mAcceptMutex.Unlock();
    return s;
}

int SCIONSocket::bind(SCIONAddr addr) EXCLUDES(mRegisterMutex)
{
    if (mBound) {
        DEBUG("already bound\n");
        return -EPERM;
    }

    if (addr.host.addr_type == 0 || addr.host.addr_type > MAX_HOST_ADDR_LEN) {
        DEBUG("invalid addr type: %d\n", addr.host.addr_type);
        return -EINVAL;
    }

    mBound = true;
    mLocalAddr = addr;

    int ret = mProtocol->bind(addr, mReliableSocket);
    if (mProtocolID == L4_UDP) {
        mRegisterMutex.Lock();
        mRegistered = true;
        pthread_cond_signal(&mRegisterCond);
        mRegisterMutex.Unlock();
    }
    return ret;
}

int SCIONSocket::connect(SCIONAddr addr) EXCLUDES(mRegisterMutex)
{
    mProtocol->start(NULL, NULL, mReliableSocket);
    mRegisterMutex.Lock();
    mRegistered = true;
    pthread_cond_signal(&mRegisterCond);
    mRegisterMutex.Unlock();
    return mProtocol->connect(addr, mTimeout);
}

int SCIONSocket::listen() EXCLUDES(mRegisterMutex)
{
    int ret = mProtocol->listen(mReliableSocket);
    if (ret < 0)
        return ret;
    mIsListener = true;
    mRegisterMutex.Lock();
    mRegistered = true;
    pthread_cond_signal(&mRegisterCond);
    mRegisterMutex.Unlock();
    return 0;
}

int SCIONSocket::recv(uint8_t *buf, size_t len, SCIONAddr *srcAddr)
{
    if (mState == SCION_CLOSED)
        return 0;
    return mProtocol->recv(buf, len, srcAddr, mTimeout);
}

int SCIONSocket::send(uint8_t *buf, size_t len)
{
    if (mState == SCION_CLOSED)
        return 0;
    return send(buf, len, NULL);
}

int SCIONSocket::send(uint8_t *buf, size_t len, SCIONAddr *dstAddr)
{
    return mProtocol->send(buf, len, dstAddr, mTimeout);
}

int SCIONSocket::setSocketOption(SCIONOption *option)
{
    if (!option)
        return -EINVAL;

    switch (option->type) {
    case SCION_OPTION_BLOCKING:
        mProtocol->setBlocking(option->val);
        return 0;
    case SCION_OPTION_ISD_WLIST:
        return mProtocol->setISDWhitelist(option->data, option->len);
    default:
        break;
    }
    return 0;
}

int SCIONSocket::getSocketOption(SCIONOption *option)
{
    if (!option)
        return -1;

    switch (option->type) {
    case SCION_OPTION_BLOCKING:
        option->val = mProtocol->isBlocking();
        return 0;
    default:
        break;
    }
    return 0;
}

uint32_t SCIONSocket::getLocalIA()
{
    if (!mProtocol)
        return 0;
    return mProtocol->getLocalIA();
}

void SCIONSocket::setTimeout(double timeout)
{
    mTimeout = timeout;
}

double SCIONSocket::getTimeout()
{
    return mTimeout;
}

bool SCIONSocket::checkChildren(SCIONPacket *packet, uint8_t *ptr) EXCLUDES(mAcceptMutex)
{
    bool claimed = false;
    mAcceptMutex.Lock();
    std::vector<SCIONSocket *>::iterator it = mAcceptedSockets.begin();
    for (; it != mAcceptedSockets.end(); it++) {
        SCIONSocket *sock = *it;
        if (!sock)
            continue;
        SCIONProtocol *proto = (*it)->mProtocol;
        if (proto && proto->claimPacket(packet, ptr)) {
            DEBUG("socket %p claims packet\n", (*it));
            proto->handlePacket(packet, ptr);
            claimed = true;
            break;
        }
    }
    mAcceptMutex.Unlock();
    return claimed;
}

void SCIONSocket::signalSelect() EXCLUDES(mSelectMutex)
{
    mSelectMutex.Lock();
    std::map<int, Notification>::iterator i;
    for (i = mSelectRead.begin(); i != mSelectRead.end(); i++) {
        Notification &n = i->second;
        p_m_lock(n.mutex, __FILE__, __LINE__);
        pthread_cond_signal(n.cond);
        p_m_unlock(n.mutex, __FILE__, __LINE__);
    }
    mSelectMutex.Unlock();
}

void SCIONSocket::handlePacket(uint8_t *buf, size_t len, HostAddr *addr) EXCLUDES(mAcceptMutex)
{
    DEBUG("received SCION packet: %lu bytes\n", len);
    DEBUG("sent from %s:%d\n", addr_to_str(addr->addr, addr->addr_type, NULL), addr->port);
    // SCION header
    SCIONPacket *packet = (SCIONPacket *)malloc(sizeof(SCIONPacket));
    memset(packet, 0, sizeof(SCIONPacket));
    gettimeofday(&(packet->arrivalTime), NULL);
    SCIONHeader &sh = packet->header;
    SCIONCommonHeader *sch = &sh.commonHeader;
    memcpy(&sh, buf, sizeof(SCIONCommonHeader));
    sch->total_len = ntohs(sch->total_len);

    memcpy(sh.srcAddr, buf + sizeof(SCIONCommonHeader), ISD_AS_LEN);
    memcpy(sh.srcAddr + ISD_AS_LEN, get_src_addr(buf), get_src_len(buf));
    memcpy(sh.dstAddr, get_dst_addr(buf) - ISD_AS_LEN, ISD_AS_LEN);
    memcpy(sh.dstAddr + ISD_AS_LEN, get_dst_addr(buf), get_dst_len(buf));
    DEBUG("SCION header len = %d bytes\n", sch->header_len);
    DEBUG("total packet len = %d bytes\n", sch->total_len);

    // path
    sh.pathLen = get_path_len(buf);
    if (sh.pathLen > 0) {
        sh.path = (uint8_t *)malloc(sh.pathLen);
#ifdef SIMULATOR
        memcpy(sh.path, buf + sch->header_len - sh.pathLen, sh.pathLen);
#else
        int res = reverse_path(buf, sh.path);
        if (res < 0) {
            DEBUG("reverse_path failed\n");
            free(packet);
            return;
        }
#endif
    }
    parseExtensions(&packet->header, buf + sch->header_len);
    uint8_t *ptr = buf;
    uint8_t l4 = get_l4_proto(&ptr);

    packet->firstHop = *addr;

    if (mIsListener) {
        if (l4 == L4_SCMP) {
            DEBUG("SCMP packet on listener socket\n");
            return;
        }
        bool claimed = checkChildren(packet, ptr);
        if (!claimed) {
            // accept: create new socket to handle connection
            DEBUG("create new socket to handle incoming flow\n");
            SCIONSocket *s = new SCIONSocket(mProtocolID, mSCIONDAddr);
            SCIONAddr addr = mLocalAddr;
            addr.host.port = 0;
            s->bind(addr);
            s->mParent = this;
            s->mProtocol->start(packet, buf + sch->header_len, s->mReliableSocket);
            s->mRegistered = true;
            pthread_cond_signal(&s->mRegisterCond);
            mAcceptMutex.Lock();
            mAcceptedSockets.push_back(s);
            mAcceptMutex.Unlock();
            pthread_cond_signal(&mAcceptCond);
            signalSelect();
        }
        return;
    }

    if (l4 == L4_SCMP)
        handleSCMP(packet, ptr);
    else
        mProtocol->handlePacket(packet, ptr);
}

void SCIONSocket::handleSCMP(SCIONPacket *packet, uint8_t *l4ptr)
{
    SCMPPacket scmp;
    memset(&scmp, 0, sizeof(scmp));
    scmp.header = (SCMPL4Header *)l4ptr;
    scmp.payload = scmp_parse_payload(scmp.header);
    packet->payload = &scmp;
    switch (htons(scmp.header->class_)) {
        case SCMP_PATH_CLASS:
            mProtocol->handlePathError(packet);
            break;
        case SCMP_GENERAL_CLASS:
        case SCMP_ROUTING_CLASS:
        case SCMP_CMNHDR_CLASS:
        case SCMP_EXT_CLASS:
        default:
            DEBUG("SCMP class %d type %d\n", htons(scmp.header->class_), htons(scmp.header->type));
            break;
    }
    free(scmp.payload);
}

void SCIONSocket::setDataProfile(DataProfile profile)
{
    if (profile < SCION_PROFILE_DEFAULT || profile > SCION_PROFILE_MAX)
        return;
    mDataProfile = profile;
}

bool SCIONSocket::isListener()
{
    return mIsListener;
}

bool SCIONSocket::isRunning()
{
    return mState != SCION_CLOSED;
}

void SCIONSocket::waitForRegistration() EXCLUDES(mRegisterMutex)
{
    DEBUG("wait for registration\n");
    mRegisterMutex.Lock();
    while (!mRegistered)
        mRegisterMutex.condWait(&mRegisterCond);
    mRegisterMutex.Unlock();
    DEBUG("registered\n");
}

int SCIONSocket::getReliableSocket()
{
    return mReliableSocket;
}

void * SCIONSocket::getStats(void *buf, int len)
{
    if (mIsListener)
        return NULL;

    SCIONStats *stats = (SCIONStats *)malloc(sizeof(SCIONStats));
    memset(stats, 0, sizeof(SCIONStats));
    if (!stats)
        return NULL;
    mProtocol->getStats(stats);
    if (!buf || len <= 0)
        return stats;
    int pathLen;
    uint8_t *ptr = (uint8_t *)buf;
    for (int i = 0; i < MAX_TOTAL_PATHS; i++) {
        if (!stats->exists[i])
            continue;
        int offset = ptr - (uint8_t *)buf;
        pathLen = sizeof(int) * SERIAL_INT_FIELDS + sizeof(double);
        pathLen +=  (ISD_AS_LEN + IFID_LEN) * stats->ifCounts[i];
        if (pathLen + offset > len) {
            free(stats);
            return NULL;
        }
        *(int *)ptr = stats->receivedPackets[i];
        ptr += sizeof(int);
        *(int *)ptr = stats->sentPackets[i];
        ptr += sizeof(int);
        *(int *)ptr = stats->ackedPackets[i];
        ptr += sizeof(int);
        *(int *)ptr = stats->rtts[i];
        ptr += sizeof(int);
        *(double *)ptr = stats->lossRates[i];
        ptr += sizeof(double);
        *(int *)ptr = stats->ifCounts[i];
        ptr += sizeof(int);
        for (int j = 0; j < stats->ifCounts[i]; j++) {
            SCIONInterface sif = stats->ifLists[i][j];
            /* Python ISD_AS class expects network byte order */
            *(uint32_t *)ptr = htonl(ISD_AS(sif.isd, sif.as));
            ptr += 4;
            *(uint16_t *)ptr = htons(sif.interface);
            ptr += 2;
        }
    }
    free(stats);
    return (void *)(ptr - (uint8_t *)buf);
}

bool SCIONSocket::readyToRead() EXCLUDES(mAcceptMutex)
{
    if (mIsListener) {
        bool ready = false;
        mAcceptMutex.Lock();
        ready = mLastAccept < (int)mAcceptedSockets.size() - 1;
        mAcceptMutex.Unlock();
        DEBUG("accept socket: ready? %d\n", ready);
        return ready;
    }
    return mProtocol->readyToRead();
}

bool SCIONSocket::readyToWrite()
{
    if (mIsListener)
        return false;
    return mProtocol->readyToWrite();
}

int SCIONSocket::registerSelect(Notification *n, int mode) EXCLUDES(mSelectMutex)
{
    if (mIsListener && mode == SCION_SELECT_WRITE)
        return -1;
    if (mIsListener && mode == SCION_SELECT_READ) {
        mSelectMutex.Lock();
        mSelectRead[++mSelectCount] = *n;
        mSelectMutex.Unlock();
        return mSelectCount;
    }
    return mProtocol->registerSelect(n, mode);
}

void SCIONSocket::deregisterSelect(int index) EXCLUDES(mSelectMutex)
{
    if (index == 0)
        return;
    mSelectMutex.Lock();
    if (mIsListener) {
        if (mSelectRead.find(index) != mSelectRead.end())
            mSelectRead.erase(index);
    } else {
        mProtocol->deregisterSelect(index);
    }
    mSelectMutex.Unlock();
}

int SCIONSocket::shutdown(bool force)
{
    int ret = 0;
    if (mIsListener) {
        mState = SCION_CLOSED;
        pthread_cond_broadcast(&mAcceptCond);
    } else {
        mState = force ? SCION_CLOSED : SCION_SHUTDOWN;
        ret = mProtocol->shutdown(force);
    }
    return ret;
}

void SCIONSocket::removeChild(SCIONSocket *child)
{
    DEBUG("remove child socket %p from parent %p\n", child, this);
    mAcceptMutex.Lock();
    for (size_t i = 0; i < mAcceptedSockets.size(); i++) {
        if (mAcceptedSockets[i] == child) {
            mAcceptedSockets[i] = NULL;
            break;
        }
    }
    mAcceptMutex.Unlock();
}

void SCIONSocket::threadCleanup() EXCLUDES(mAcceptMutex, mRegisterMutex, mSelectMutex)
{
    if (mProtocol) {
        mProtocol->threadCleanup();
    }
}

int SCIONSocket::getPort()
{
    if (mProtocol)
        return mProtocol->getPort();
    return 0;
}

int SCIONSocket::maxPayloadSize(double timeout)
{
    if (!mProtocol)
        return -1;
    return mProtocol->maxPayloadSize(timeout);
}
