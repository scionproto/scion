#ifndef PATH_MANAGER_H
#define PATH_MANAGER_H

#include <vector>

#include "DataStructures.h"
#include "OrderedList.h"
#include "PathPolicy.h"
#include "SCIONDefines.h"

class SSPProtocol;
class Path;
class PathState;

class PathManager {
public:
    PathManager(int sock, const char *sciond);
    virtual ~PathManager();

    int getSocket();
    int getPathCount();
    int maxPayloadSize();
    SCIONAddr * localAddress();

    void queryLocalAddress();
    int setLocalAddress(SCIONAddr addr);
    virtual void setRemoteAddress(SCIONAddr addr);
    void getPaths();

    virtual Path * createPath(SCIONAddr &dstAddr, uint8_t *rawPath, int pathLen);
    virtual void handleTimeout();
    virtual void getStats(SCIONStats *stats);

    int setISDWhitelist(void *data, size_t len);

    virtual void threadCleanup();
    virtual void didSend(SCIONPacket *packet);
    int sendRawPacket(uint8_t *buf, int len, HostAddr *firstHop);

protected:
    int checkPath(uint8_t *ptr, int len, std::vector<Path *> &candidates);
    void prunePaths();
    void insertPaths(std::vector<Path *> &candidates);
    int insertOnePath(Path *p);

    int                          mDaemonSocket;
    int                          mSendSocket;
    SCIONAddr                    mLocalAddr;
    SCIONAddr                    mDstAddr;

    std::vector<Path *>          mPaths;
    pthread_mutex_t              mPathMutex;
    pthread_mutex_t              mDispatcherMutex;
    int                          mInvalid;
    PathPolicy                   mPolicy;
};

// SSP

class SSPConnectionManager : public PathManager {
public:
    SSPConnectionManager(int sock, const char *sciond);
    SSPConnectionManager(int sock, const char *sciond, SSPProtocol *protocol);
    virtual ~SSPConnectionManager();

    void setRemoteWindow(uint32_t window);
    bool bufferFull(int window);
    int totalQueuedSize();
    void waitForSendBuffer(int len, int windowSize);

    void queuePacket(SCIONPacket *packet);
    int sendAllPaths(SCIONPacket *packet);

    void startScheduler();
    static void * workerHelper(void *arg);
    bool readyToSend();
    void schedule();
    SCIONPacket * nextPacket();
    Path * pathToSend(bool *dup);
    void didSend(SCIONPacket *packet);

    void sendAck(SCIONPacket *packet);
    void sendProbes(uint32_t probeNum, uint64_t flowID);

    int handlePacket(SCIONPacket *packet, bool receiver);
    void handleAck(SCIONPacket *packet, size_t initCount, bool receiver);
    void handleProbeAck(SCIONPacket *packet);
    void handleTimeout();

    void getStats(SCIONStats *stats);

    Path * createPath(SCIONAddr &dstAddr, uint8_t *rawPath, int pathLen);

    void threadCleanup();

    PathState *mState;

protected:
    int sendAlternatePath(SCIONPacket *packet, size_t exclude);
    void handlePacketAcked(bool found, SCIONPacket *ack, SCIONPacket *sent);
    bool handleDupAck(SCIONPacket *packet);
    void addRetries(std::vector<SCIONPacket *> &retries);
    int handleAckOnPath(SCIONPacket *packet, bool rttSample, int pathIndex);

    int                          mReceiveWindow;
    int                          mInitSends;

    bool                         mRunning;
    bool                         mFinAcked;
    int                          mFinAttempts;
    struct timeval               mFinSentTime;
    bool                         mInitAcked;
    bool                         mResendInit;

    size_t                       mTotalSize;
    PacketList                   mSentPackets;
    OrderedList<SCIONPacket *>   *mRetryPackets;
    OrderedList<SCIONPacket *>   *mFreshPackets;

    pthread_mutex_t              mMutex;
    pthread_cond_t               mCond;

    pthread_mutex_t              mSentMutex;
    pthread_cond_t               mSentCond;
    pthread_mutex_t              mFreshMutex;
    pthread_mutex_t              mRetryMutex;
    pthread_mutex_t              mPacketMutex;
    pthread_cond_t               mPacketCond;
    pthread_cond_t               mPathCond;

    pthread_t                    mWorker;

    SSPProtocol               *mProtocol;
};

// SUDP

class SUDPConnectionManager : public PathManager {
public:
    SUDPConnectionManager(int sock, const char *sciond);
    ~SUDPConnectionManager();

    int sendPacket(SCIONPacket *packet);

    void sendProbes(uint32_t probeNum, uint16_t srcPort, uint16_t dstPort);
    void handlePacket(SCIONPacket *packet);

    void setRemoteAddress(SCIONAddr addr);

    Path * createPath(SCIONAddr &dstAddr, uint8_t *rawPath, int pathLen);
protected:
    void handleProbe(SUDPPacket *sp, SCIONExtension *ext, int index);

    struct timeval mLastProbeTime;
    std::vector<uint32_t> mLastProbeAcked;
};

#endif // PATH_MANAGER_H
