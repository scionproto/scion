#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/un.h>

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
    uint8_t buf[DISPATCHER_BUF_SIZE];
    struct sockaddr_in addr;
    ss->waitForRegistration();
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    while (ss->isRunning()) {
        int len = recv_all(sock, buf, DP_HEADER_LEN);
        if (len < 0) {
            fprintf(stderr, "error on recv from dispatcher: %s\n", strerror(errno));
            exit(1);
        }
        int addr_len = 0;
        int packet_len = 0;
        parse_dp_header(buf, &addr_len, &packet_len);
        if (packet_len == 0) {
            fprintf(stderr, "invalid dispatcher header\n");
            exit(1);
        }
        len = recv_all(sock, buf, addr_len + 2 + packet_len);
        if (len > 0) {
            DEBUG("received %d bytes from dispatcher, addr_len = %d\n", len, addr_len);
            memcpy(&addr.sin_addr, buf, addr_len);
            addr.sin_port = *(uint16_t *)(buf + addr_len);
            ss->handlePacket(buf + addr_len + 2, packet_len, &addr);
        }
    }
    return NULL;
}

int setupSocket()
{
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    return sock;
}

SCIONSocket::SCIONSocket(int protocol)
    : mProtocolID(protocol),
    mRegistered(false),
    mState(SCION_RUNNING),
    mLastAccept(-1),
    mIsListener(false),
    mParent(NULL),
    mDataProfile(SCION_PROFILE_DEFAULT)
{
    signal(SIGINT, signalHandler);

    // init pthread variables
    pthread_mutex_init(&mAcceptMutex, NULL);
    pthread_cond_init(&mAcceptCond, NULL);
    pthread_mutex_init(&mRegisterMutex, NULL);
    pthread_cond_init(&mRegisterCond, NULL);
    pthread_mutex_init(&mSelectMutex, NULL);

    // open dispatcher socket
    mDispatcherSocket = setupSocket();

    switch (protocol) {
        case L4_SSP: {
            mProtocol = new SSPProtocol(mDispatcherSocket);
            break;
        }
        case L4_UDP: {
            mProtocol = new SUDPProtocol(mDispatcherSocket);
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
    delete mProtocol;
    mProtocol = NULL;
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

/*
 * Used to send/receive on subset of host's SCION addresses
 * Since we don't support multiple addresses yet, does pretty much nothing ATM
 * Still needs to be called before listen() and accept()
 */
int SCIONSocket::bind(SCIONAddr addr)
{
    if (addr.isd_as == 0 && addr.host.port == 0) {
        struct sockaddr_in sa;
        socklen_t len = sizeof(sa);
        getsockname(mDispatcherSocket, (struct sockaddr *)&sa, &len);
        addr.host.port = ntohs(sa.sin_port);
    }
    int ret = mProtocol->bind(addr, mDispatcherSocket);
    if (mProtocolID == L4_UDP) {
        pthread_mutex_lock(&mRegisterMutex);
        mRegistered = true;
        pthread_cond_signal(&mRegisterCond);
        pthread_mutex_unlock(&mRegisterMutex);
    }
    return ret;
}

int SCIONSocket::connect(SCIONAddr addr)
{
    mProtocol->start(NULL, NULL, mDispatcherSocket);
    pthread_mutex_lock(&mRegisterMutex);
    mRegistered = true;
    pthread_cond_signal(&mRegisterCond);
    pthread_mutex_unlock(&mRegisterMutex);
    return mProtocol->connect(addr);
}

int SCIONSocket::listen()
{
    int ret = mProtocol->listen(mDispatcherSocket);
    if (ret < 0)
        return ret;
    mIsListener = true;
    pthread_mutex_lock(&mRegisterMutex);
    mRegistered = true;
    pthread_cond_signal(&mRegisterCond);
    pthread_mutex_unlock(&mRegisterMutex);
    return 0;
}

int SCIONSocket::recv(uint8_t *buf, size_t len, SCIONAddr *srcAddr)
{
    return mProtocol->recv(buf, len, srcAddr);
}

int SCIONSocket::send(uint8_t *buf, size_t len)
{
    return send(buf, len, NULL);
}

int SCIONSocket::send(uint8_t *buf, size_t len, SCIONAddr *dstAddr)
{
    return mProtocol->send(buf, len, dstAddr);
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
    DEBUG("sent from %s:%d\n", inet_ntoa(addr->sin_addr), addr->sin_port);
    // SCION header
    SCIONPacket *packet = (SCIONPacket *)malloc(sizeof(SCIONPacket));
    memset(packet, 0, sizeof(SCIONPacket));
    gettimeofday(&(packet->arrivalTime), NULL);
    SCIONHeader &sh = packet->header;
    SCIONCommonHeader &sch = sh.commonHeader;
    memcpy(&sh, buf, sizeof(SCIONCommonHeader));
    sch.total_len = ntohs(sch.total_len);

    int src_len = get_src_len(buf);
    int dst_len = get_dst_len(buf);
    memcpy(sh.srcAddr, buf + sizeof(SCIONCommonHeader), ISD_AS_LEN);
    memcpy(sh.srcAddr + ISD_AS_LEN, get_src_addr(buf), get_src_len(buf));
    memcpy(sh.dstAddr, get_dst_addr(buf) - ISD_AS_LEN, ISD_AS_LEN);
    memcpy(sh.dstAddr + ISD_AS_LEN, get_dst_addr(buf), get_dst_len(buf));
    DEBUG("SCION header len = %d bytes\n", sch.header_len);
    DEBUG("total packet len = %d bytes\n", sch.total_len);

    // address
    SCIONAddr srcAddr;
    memset(&srcAddr, 0, sizeof(srcAddr));
    srcAddr.isd_as = ntohl(*(uint32_t *)(sh.srcAddr));
    // TODO: IPv6?
    srcAddr.host.addr_len = ADDR_IPV4_LEN;
    memcpy(srcAddr.host.addr, sh.srcAddr + ISD_AS_LEN, ADDR_IPV4_LEN);

    // path
    sh.pathLen = sch.header_len - sizeof(sch) - 2 * ISD_AS_LEN - src_len - dst_len;
    sh.path = (uint8_t *)malloc(sh.pathLen);
#ifdef SIMULATOR
    memcpy(sh.path, buf + sch.header_len - sh.pathLen, sh.pathLen);
#else
    int res = reverse_path(buf, sh.path);
    if (res < 0) {
        DEBUG("reverse_path failed\n");
        free(packet);
        return;
    }
#endif
    packet->firstHop = (uint32_t)(addr->sin_addr.s_addr);

    uint8_t *ptr = parseExtensions(&packet->header, buf + sch.header_len);

    if (mIsListener) {
        bool claimed = checkChildren(packet, ptr);
        if (!claimed) {
            // accept: create new socket to handle connection
            DEBUG("create new socket to handle incoming flow\n");
            SCIONSocket *s = new SCIONSocket(mProtocolID);
            s->mParent = this;
            s->mProtocol->start(packet, buf + sch.header_len, s->mDispatcherSocket);
            s->mRegistered = true;
            pthread_cond_signal(&s->mRegisterCond);
            pthread_mutex_lock(&mAcceptMutex);
            mAcceptedSockets.push_back(s);
            pthread_mutex_unlock(&mAcceptMutex);
            pthread_cond_signal(&mAcceptCond);
            signalSelect();
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
    return mIsListener;
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

bool SCIONSocket::readyToRead()
{
    if (mIsListener) {
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
    if (mIsListener)
        return false;
    return mProtocol->readyToWrite();
}

int SCIONSocket::registerSelect(Notification *n, int mode)
{
    if (mIsListener && mode == SCION_SELECT_WRITE)
        return -1;
    if (mIsListener && mode == SCION_SELECT_READ) {
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
    if (mIsListener) {
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
    if (mIsListener) {
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
