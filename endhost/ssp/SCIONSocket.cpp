#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>

#include "Extensions.h"
#include "SCIONSocket.h"

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

void *dispatcherThread(void *arg)
{
    SCIONSocket *ss = (SCIONSocket *)arg;
    int sock = ss->getDispatcherSocket();
    char buf[DISPATCHER_BUF_SIZE];
    struct sockaddr_in addr;
    socklen_t addrLen = sizeof(addr);
    ss->waitForRegistration();
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    while (ss->isRunning()) {
        int len = recvfrom(sock, buf, sizeof(buf), 0,
                            (struct sockaddr *)&addr, &addrLen);
        if (len > 0) {
            DEBUG("received %d bytes from dispatcher\n", len);
            if (!ss->bypassDispatcher())
                addr = *(struct sockaddr_in *)(buf + len - sizeof(addr));
            ss->handlePacket((uint8_t *)buf, len - sizeof(addr), &addr);
        }
    }
    return NULL;
}

SCIONSocket::SCIONSocket(int protocol, SCIONAddr *dstAddrs, int numAddrs,
                         short srcPort, short dstPort)
    : mSrcPort(srcPort),
    mDstPort(dstPort),
    mProtocolID(protocol),
    mRegistered(false),
    mState(SCION_RUNNING),
    mLastAccept(-1),
    mParent(NULL),
    mDataProfile(SCION_PROFILE_DEFAULT)
{
    signal(SIGINT, signalHandler);

    pthread_mutex_init(&mAcceptMutex, NULL);
    pthread_cond_init(&mAcceptCond, NULL);
    pthread_mutex_init(&mRegisterMutex, NULL);
    pthread_cond_init(&mRegisterCond, NULL);
    pthread_mutex_init(&mSelectMutex, NULL);

    if (dstAddrs)
        for (int i = 0; i < numAddrs; i++)
            mDstAddrs.push_back(dstAddrs[i]);

    mDispatcherSocket = socket(AF_INET, SOCK_DGRAM, 0);

    switch (protocol) {
        case SCION_PROTO_SSP: {
            if (!mDstAddrs.empty()) {
                mProtocol = new SSPProtocol(mDstAddrs, mSrcPort, mDstPort);
                if (srcPort != -1) {
                    mProtocol->createManager(mDstAddrs);
                    mProtocol->start(NULL, NULL, mDispatcherSocket);
                    mRegistered = true;
                }
            } else {
                mProtocol = NULL;
                SSPEntry se;
                se.flowID = 0;
                se.port = mSrcPort;
                registerFlow(SCION_PROTO_SSP, &se, mDispatcherSocket, 1);
                mRegistered = true;
            }
            break;
        }
        case SCION_PROTO_UDP: {
            struct sockaddr_in addr;
            socklen_t addrLen = sizeof(addr);
            memset(&addr, 0, addrLen);
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = INADDR_ANY;
            addr.sin_port = htons(mSrcPort);
            bind(mDispatcherSocket, (struct sockaddr *)&addr, addrLen);
            if (!mSrcPort) {
                getsockname(mDispatcherSocket, (struct sockaddr *)&addr, &addrLen);
                mSrcPort = ntohs(addr.sin_port);
            }
            SUDPEntry se;
            se.port = mSrcPort;
            registerFlow(SCION_PROTO_UDP, &se, mDispatcherSocket, 1);
            mRegistered = true;
            DEBUG("Registered to receive SUDP packets on port %d\n", mSrcPort);
            mProtocol = new SUDPProtocol(mDstAddrs, mSrcPort, mDstPort);
            mProtocol->createManager(mDstAddrs);
            break;
        }
        default:
            break;
    }

    pthread_create(&mReceiverThread, NULL, dispatcherThread, this);
}

SCIONSocket::~SCIONSocket()
{
    mState = SCION_CLOSED;
    pthread_cancel(mReceiverThread);
    pthread_join(mReceiverThread, NULL);
    if (mProtocol) {
        mProtocol->removeDispatcher(mDispatcherSocket);
        delete mProtocol;
        mProtocol = NULL;
    } else if (mProtocolID == SCION_PROTO_SSP) {
        SSPEntry se;
        se.flowID = 0;
        se.port = mSrcPort;
        registerFlow(SCION_PROTO_SSP, &se, mDispatcherSocket, 0);
    }
    if (mProtocolID == SCION_PROTO_UDP) {
        SUDPEntry se;
        se.port = mSrcPort;
        registerFlow(SCION_PROTO_UDP, &se, mDispatcherSocket, 0);
    }
    close(mDispatcherSocket);
    pthread_mutex_destroy(&mAcceptMutex);
    pthread_cond_destroy(&mAcceptCond);
    pthread_mutex_destroy(&mRegisterMutex);
    pthread_cond_destroy(&mRegisterCond);
    if (mParent)
        mParent->removeChild(this);
}

SCIONSocket * SCIONSocket::accept()
{
    SCIONSocket *s;
    pthread_mutex_lock(&mAcceptMutex);
    while (mLastAccept >= (int)mAcceptedSockets.size() - 1)
        pthread_cond_wait(&mAcceptCond, &mAcceptMutex);
    s = mAcceptedSockets[++mLastAccept];
    pthread_mutex_unlock(&mAcceptMutex);
    return s;
}

int SCIONSocket::send(uint8_t *buf, size_t len)
{
    return send(buf, len, mDataProfile);
}

int SCIONSocket::send(uint8_t *buf, size_t len, DataProfile profile)
{
    return mProtocol->send(buf, len, profile);
}

int SCIONSocket::recv(uint8_t *buf, size_t len, SCIONAddr *srcAddr)
{
    return mProtocol->recv(buf, len, srcAddr);
}

int SCIONSocket::setSocketOption(SCIONOption *option)
{
    if (!option)
        return -EINVAL;

    switch (option->type) {
    case SCION_OPTION_BLOCKING:
        if (!mProtocol)
            return -EPERM;
        mProtocol->setBlocking(option->val);
        return 0;
    case SCION_OPTION_STAY_ISD:
        if (!mProtocol)
            return -EPERM;
        return mProtocol->setStayISD(option->val);
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
        if (!mProtocol)
            return -1;
        option->val = mProtocol->isBlocking();
        return 0;
    default:
        break;
    }
    return 0;
}

bool SCIONSocket::checkChildren(SCIONPacket *packet, uint8_t *ptr)
{
    bool claimed = false;
    pthread_mutex_lock(&mAcceptMutex);
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
    pthread_mutex_unlock(&mAcceptMutex);
    return claimed;
}

void SCIONSocket::signalSelect()
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

void SCIONSocket::handlePacket(uint8_t *buf, size_t len, struct sockaddr_in *addr)
{
    DEBUG("received SCION packet: %lu bytes\n", len);
    DEBUG("sent from %s:%d\n", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
    // SCION header
    SCIONPacket *packet = (SCIONPacket *)malloc(sizeof(SCIONPacket));
    memset(packet, 0, sizeof(SCIONPacket));
    gettimeofday(&(packet->arrivalTime), NULL);
    SCIONHeader &sh = packet->header;
    SCIONCommonHeader &sch = sh.commonHeader;
    memcpy(&sh, buf, sizeof(SCIONCommonHeader) + 2 * SCION_ADDR_LEN);
    sch.totalLen = ntohs(sch.totalLen);
    DEBUG("SCION header len = %d bytes\n", sch.headerLen);
    DEBUG("total packet len = %d bytes\n", sch.totalLen);

    // address
    SCIONAddr srcAddr;
    memset(&srcAddr, 0, sizeof(srcAddr));
    srcAddr.isd_ad = ntohl(*(uint32_t *)(sh.srcAddr));
    srcAddr.host.addrLen = SCION_HOST_ADDR_LEN;
    memcpy(srcAddr.host.addr, sh.srcAddr + SCION_HOST_OFFSET, SCION_HOST_ADDR_LEN);

    // path
    sh.pathLen = sch.headerLen - sizeof(sch) - 2 * SCION_ADDR_LEN;
    sh.path = (uint8_t *)malloc(sh.pathLen);
#ifdef SIMULATOR
    memcpy(sh.path, buf + sch.headerLen - sh.pathLen, sh.pathLen);
#else
    int res = reversePath(buf + sch.headerLen - sh.pathLen, sh.path, sh.pathLen);
    if (res < 0) {
        DEBUG("reversePath failed\n");
        free(packet);
        return;
    }
#endif
    packet->firstHop = (uint32_t)(addr->sin_addr.s_addr);

    uint8_t *ptr = parseExtensions(&packet->header, buf + sch.headerLen);

    if (!mProtocol) {
        bool claimed = checkChildren(packet, ptr);
        if (!claimed) {
            // accept: create new socket to handle connection
            SCIONAddr addrs[1];
            addrs[0] = srcAddr;
            DEBUG("create new socket to handle incoming flow\n");
            SCIONSocket *s = new SCIONSocket(mProtocolID, (SCIONAddr *)addrs, 1, -1, mDstPort);
            s->mParent = this;
            s->mProtocol->setReceiver(true);
            s->mProtocol->createManager(s->mDstAddrs);
            s->mProtocol->start(packet, buf + sch.headerLen, s->mDispatcherSocket);
            s->mRegistered = true;
            pthread_cond_signal(&s->mRegisterCond);
            pthread_mutex_lock(&mAcceptMutex);
            mAcceptedSockets.push_back(s);
            pthread_mutex_unlock(&mAcceptMutex);
            pthread_cond_signal(&mAcceptCond);
        }
        return;
    }

    mProtocol->handlePacket(packet, ptr);
}

void SCIONSocket::setDataProfile(DataProfile profile)
{
    if (profile < SCION_PROFILE_DEFAULT || profile > SCION_PROFILE_MAX)
        return;
    mDataProfile = profile;
}

bool SCIONSocket::isListener()
{
    return mProtocol == NULL;
}

bool SCIONSocket::isRunning()
{
    return mState != SCION_CLOSED;
}

void SCIONSocket::waitForRegistration()
{
    DEBUG("wait for registration\n");
    pthread_mutex_lock(&mRegisterMutex);
    while (!mRegistered)
        pthread_cond_wait(&mRegisterCond, &mRegisterMutex);
    pthread_mutex_unlock(&mRegisterMutex);
    DEBUG("registered\n");
}

int SCIONSocket::getDispatcherSocket()
{
    return mDispatcherSocket;
}

bool SCIONSocket::bypassDispatcher()
{
    return mProtocolID == SCION_PROTO_UDP;
}

void * SCIONSocket::getStats(void *buf, int len)
{
    if (!mProtocol)
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
        pathLen +=  (SCION_ISD_AD_LEN + SCION_IFID_LEN) * stats->ifCounts[i];
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
            /* Python ISD_AD class expects network byte order */
            *(uint32_t *)ptr = htonl(ISD_AD(sif.isd, sif.ad));
            ptr += 4;
            *(uint16_t *)ptr = sif.interface;
            ptr += 2;
        }
    }
    free(stats);
    return (void *)(ptr - (uint8_t *)buf);
}

bool SCIONSocket::readyToRead()
{
    if (!mProtocol) {
        bool ready = false;
        pthread_mutex_lock(&mAcceptMutex);
        ready = mLastAccept < (int)mAcceptedSockets.size() - 1;
        pthread_mutex_unlock(&mAcceptMutex);
        DEBUG("accept socket: ready? %d\n", ready);
        return ready;
    }
    return mProtocol->readyToRead();
}

bool SCIONSocket::readyToWrite()
{
    if (!mProtocol)
        return false;
    return mProtocol->readyToWrite();
}

int SCIONSocket::registerSelect(Notification *n, int mode)
{
    if (!mProtocol && mode == SCION_SELECT_WRITE)
        return -1;
    if (!mProtocol && mode == SCION_SELECT_READ) {
        pthread_mutex_lock(&mSelectMutex);
        mSelectRead[++mSelectCount] = *n;
        pthread_mutex_unlock(&mSelectMutex);
        return mSelectCount;
    }
    return mProtocol->registerSelect(n, mode);
}

void SCIONSocket::deregisterSelect(int index)
{
    if (index == 0)
        return;
    pthread_mutex_lock(&mSelectMutex);
    if (!mProtocol) {
        if (mSelectRead.find(index) != mSelectRead.end())
            mSelectRead.erase(index);
    } else {
        mProtocol->deregisterSelect(index);
    }
    pthread_mutex_unlock(&mSelectMutex);
}

int SCIONSocket::shutdown()
{
    int ret = 0;
    if (!mProtocol) {
        mState = SCION_CLOSED;
    } else {
        mState = SCION_SHUTDOWN;
        ret = mProtocol->shutdown();
    }
    return ret;
}

void SCIONSocket::removeChild(SCIONSocket *child)
{
    pthread_mutex_lock(&mAcceptMutex);
    for (size_t i = 0; i < mAcceptedSockets.size(); i++) {
        if (mAcceptedSockets[i] == child) {
            mAcceptedSockets[i] = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&mAcceptMutex);
}
