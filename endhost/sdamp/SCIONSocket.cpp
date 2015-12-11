#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <semaphore.h>
#include <sys/mman.h>

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
    while (ss->isRunning()) {
        int len = recvfrom(sock, buf, sizeof(buf), 0,
                            (struct sockaddr *)&addr, &addrLen);
        if (len > 0) {
            DEBUG("received %d bytes from dispatcher\n", len);
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
    mRunning(true),
    mDataProfile(SCION_PROFILE_DEFAULT)
{
    signal(SIGINT, signalHandler);

    pthread_mutex_init(&mAcceptMutex, NULL);
    pthread_cond_init(&mAcceptCond, NULL);
    pthread_mutex_init(&mRegisterMutex, NULL);
    pthread_cond_init(&mRegisterCond, NULL);

    if (dstAddrs)
        for (int i = 0; i < numAddrs; i++)
            mDstAddrs.push_back(dstAddrs[i]);

    mDispatcherSocket = socket(AF_INET, SOCK_DGRAM, 0);

    switch (protocol) {
        case SCION_PROTO_SDAMP: {
            if (!mDstAddrs.empty()) {
                mProtocol = new SDAMPProtocol(mDstAddrs, mSrcPort, mDstPort);
                if (srcPort != -1) {
                    mProtocol->createManager(mDstAddrs);
                    mProtocol->start(NULL, NULL, mDispatcherSocket);
                    mRegistered = true;
                }
            } else {
                mProtocol = NULL;
                SDAMPEntry se;
                se.flowID = 0;
                se.port = mSrcPort;
                registerFlow(SCION_PROTO_SDAMP, &se, mDispatcherSocket);
                mRegistered = true;
            }
            break;
        }
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
                SDAMPEntry se;
                se.flowID = 0;
                se.port = mSrcPort;
                registerFlow(SCION_PROTO_SDAMP, &se, mDispatcherSocket);
                mRegistered = true;
            }
            break;
        }
        case SCION_PROTO_SUDP: {
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
            registerFlow(SCION_PROTO_SUDP, &se, mDispatcherSocket);
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

SCIONSocket::SCIONSocket(const SCIONSocket &s)
    : mSrcPort(s.mSrcPort),
    mDstPort(s.mDstPort),
    mProtocolID(s.mProtocolID),
    mDispatcherSocket(s.mDispatcherSocket),
    mRegistered(s.mRegistered),
    mRunning(s.mRunning),
    mProtocol(s.mProtocol),
    mDstAddrs(s.mDstAddrs),
    mAcceptedSockets(s.mAcceptedSockets),
    mDataProfile(s.mDataProfile)
{
    pthread_mutex_init(&mAcceptMutex, NULL);
    pthread_cond_init(&mAcceptCond, NULL);
    pthread_mutex_init(&mRegisterMutex, NULL);
    pthread_cond_init(&mRegisterCond, NULL);
    pthread_create(&mReceiverThread, NULL, dispatcherThread, this);
}

SCIONSocket::~SCIONSocket()
{
    if (mProtocol) {
        delete mProtocol;
        mProtocol = NULL;
    }
    pthread_mutex_destroy(&mAcceptMutex);
    pthread_cond_destroy(&mAcceptCond);
    pthread_mutex_destroy(&mRegisterMutex);
    pthread_cond_destroy(&mRegisterCond);
    mRunning = false;
    close(mDispatcherSocket);
    pthread_kill(mReceiverThread, SIGTERM);
}

SCIONSocket & SCIONSocket::operator=(const SCIONSocket &s)
{
    mSrcPort = s.mSrcPort;
    mDstPort = s.mDstPort;
    mProtocolID = s.mProtocolID;
    mDispatcherSocket = s.mDispatcherSocket;
    mRegistered = s.mRegistered;
    mRunning = s.mRunning;
    mProtocol = s.mProtocol;
    mDstAddrs = s.mDstAddrs;
    mAcceptedSockets = s.mAcceptedSockets;
    mDataProfile = s.mDataProfile;
    pthread_mutex_init(&mAcceptMutex, NULL);
    pthread_cond_init(&mAcceptCond, NULL);
    pthread_mutex_init(&mRegisterMutex, NULL);
    pthread_cond_init(&mRegisterCond, NULL);
    pthread_create(&mReceiverThread, NULL, dispatcherThread, this);
    return *this;
}

SCIONSocket & SCIONSocket::accept()
{
    pthread_mutex_lock(&mAcceptMutex);
    pthread_cond_wait(&mAcceptCond, &mAcceptMutex);
    return *(mAcceptedSockets.back());
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

    if (!mProtocol) {
        std::vector<SCIONSocket *>::iterator it = mAcceptedSockets.begin();
        for (; it != mAcceptedSockets.end(); it++) {
            SCIONProtocol *proto = (*it)->mProtocol;
            if (proto->claimPacket(packet, buf + sch.headerLen)) {
                DEBUG("socket %p claims packet\n", (*it));
                proto->handlePacket(packet, buf + sch.headerLen);
                return;
            }
        }
        // accept: create new socket to handle connection
        SCIONAddr addrs[1];
        addrs[0] = srcAddr;
        DEBUG("create new socket to handle incoming flow\n");
        SCIONSocket *s = new SCIONSocket(mProtocolID, (SCIONAddr *)addrs, 1, -1, mDstPort);
        s->mProtocol->createManager(s->mDstAddrs);
        s->mProtocol->start(packet, buf + sch.headerLen, s->mDispatcherSocket);
        s->mRegistered = true;
        pthread_cond_signal(&s->mRegisterCond);
        mAcceptedSockets.push_back(s);
        pthread_cond_signal(&mAcceptCond);
        return;
    }

    mProtocol->handlePacket(packet, buf + sch.headerLen);
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
    return mRunning;
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

SCIONStats * SCIONSocket::getStats()
{
    if (mProtocol) {
        SCIONStats *stats = (SCIONStats *)malloc(sizeof(SCIONStats));
        memset(stats, 0, sizeof(SCIONStats));
        if (!stats)
            return NULL;
        mProtocol->getStats(stats);
        return stats;
    }
    return NULL;
}
