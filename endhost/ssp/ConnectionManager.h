#ifndef PATH_MANAGER_H
#define PATH_MANAGER_H

#include "DataStructures.h"
#include "SCIONDefines.h"
#include "OrderedList.h"

class SSPProtocol;
class Path;
class PathState;

class PathManager {
public:
    PathManager(std::vector<SCIONAddr> &addrs, int sock);
    virtual ~PathManager();

    int getSocket();
    int getPathCount();
    int maxPayloadSize();

    void getPaths();
    void prunePaths();
    void insertPaths(std::vector<Path *> &candidates);
    int insertOnePath(Path *p);

    virtual Path * createPath(SCIONAddr &dstAddr, uint8_t *rawPath, int pathLen);
    virtual void handleTimeout();
    virtual void getStats(SCIONStats *stats);

protected:

    int                          mDaemonSocket;
    int                          mSendSocket;
    SCIONAddr                    mLocalAddr;
    std::vector<SCIONAddr>      &mDstAddrs;

    std::vector<Path *>          mPaths;
    int                          mInvalid;
};

// SUDP

class SUDPConnectionManager : public PathManager {
public:
    SUDPConnectionManager(std::vector<SCIONAddr> &addrs, int sock);
    ~SUDPConnectionManager();

    int send(SCIONPacket *packet);

    void sendProbes(uint32_t probeNum, uint16_t srcPort, uint16_t dstPort);
    void handlePacket(SCIONPacket *packet);

    Path * createPath(SCIONAddr &dstAddr, uint8_t *rawPath, int pathLen);
protected:
    struct timeval mLastProbeTime;
    std::vector<uint32_t> mLastProbeAcked;
};

// SSP

class SSPConnectionManager : public PathManager {
public:
    SSPConnectionManager(std::vector<SCIONAddr> &addrs, int sock);
    SSPConnectionManager(std::vector<SCIONAddr> &addrs, int sock, SSPProtocol *protocol);
    virtual ~SSPConnectionManager();

    void setRemoteWindow(uint32_t window);
    void waitForSendBuffer(int len, int windowSize);

    void queuePacket(SCIONPacket *packet);
    int sendAllPaths(SCIONPacket *packet);

    void startScheduler();
    static void * workerHelper(void *arg);
    bool readyToSend();
    void schedule();
    SCIONPacket * nextPacket();
    Path * pathToSend();
    void didSend(SCIONPacket *packet);

    void sendAck(SCIONPacket *packet);
    void sendProbes(uint32_t probeNum, uint64_t flowID);

    int handlePacket(SCIONPacket *packet);
    void handleAck(SCIONPacket *packet, size_t initCount, bool receiver);
    void handleDupAck(int index);
    void handleProbeAck(SCIONPacket *packet);
    void handleTimeout();

    void getStats(SCIONStats *stats);

    Path * createPath(SCIONAddr &dstAddr, uint8_t *rawPath, int pathLen);

    PathState *mState;

protected:
    int handleAckOnPath(SCIONPacket *packet, bool rttSample);
    int totalQueuedSize();

    int                          mReceiveWindow;

    bool                         mInitPacketQueued;
    bool                         mRunning;

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

#endif // PATH_MANAGER_H
