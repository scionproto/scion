#ifndef PATH_MANAGER_H
#define PATH_MANAGER_H

#include "DataStructures.h"
#include "SCIONDefines.h"
#include "OrderedList.h"
#include "RingBuffer.h"

class SDAMPProtocol;
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

    virtual Path * createPath(SCIONAddr &dstAddr, uint8_t *rawPath, int pathLen);
    virtual void handleTimeout();
    virtual void getStats(SCIONStats *stats);

protected:

    int                          mDaemonSocket;
    int                          mSendSocket;
    SCIONAddr                    mLocalAddr;
    std::vector<SCIONAddr>      &mDstAddrs;

    std::vector<Path *>          mPaths;
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

// SDAMP

class SDAMPConnectionManager : public PathManager {
public:
    SDAMPConnectionManager(std::vector<SCIONAddr> &addrs, int sock);
    SDAMPConnectionManager(std::vector<SCIONAddr> &addrs, int sock, SDAMPProtocol *protocol);
    virtual ~SDAMPConnectionManager();

    void setRemoteWindow(uint32_t window);
    virtual void waitForSendBuffer(int len, int windowSize);

    void queuePacket(SCIONPacket *packet);
    int sendAllPaths(SCIONPacket *packet);
    virtual void didSend(SCIONPacket *packet);
    virtual void abortSend(SCIONPacket *packet);

    void startScheduler();
    static void * workerHelper(void *arg);
    bool readyToSend();
    void schedule();
    virtual SCIONPacket * nextPacket();
    virtual Path * pathToSend();
    virtual SCIONPacket * maximizeBandwidth(int index, int bps, int rtt, double loss);
    virtual SCIONPacket * requestPacket(int index, int bps, int rtt, double loss);

    void sendAck(SCIONPacket *packet);
    virtual void sendProbes(uint32_t probeNum, uint64_t flowID);

    virtual int handlePacket(SCIONPacket *packet);
    virtual void handleAck(SCIONPacket *packet, size_t initCount, bool receiver);
    void handleDupAck(int index);
    void handleProbeAck(SCIONPacket *packet);
    virtual void handleTimeout();

    void getStats(SCIONStats *stats);

    Path * createPath(SCIONAddr &dstAddr, uint8_t *rawPath, int pathLen);

    PathState *mState;

protected:
    virtual bool sleepIfUnused(int index);
    virtual int handleAckOnPath(SCIONPacket *packet, bool rttSample);
    virtual int totalQueuedSize();

    int                          mReceiveWindow;

    bool                         mInitPacketQueued;
    bool                         mRunning;
    SDAMPMetric                  mMetric;

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

    SDAMPProtocol               *mProtocol;
};

class SSPConnectionManager : public SDAMPConnectionManager {
public:
    SSPConnectionManager(std::vector<SCIONAddr> &addrs, int sock);
    SSPConnectionManager(std::vector<SCIONAddr> &addrs, int sock, SSPProtocol *protocol);
    ~SSPConnectionManager();

    Path * createPath(SCIONAddr &dstAddr, uint8_t *rawPath, int pathLen);
    void waitForSendBuffer(int len, int windowSize);
    void sendProbes(uint32_t probeNum, uint64_t flowID);

    int handlePacket(SCIONPacket *packet);
    void handleAck(SCIONPacket *packet, size_t initCount, bool receiver);
    void handleTimeout();

    void didSend(SCIONPacket *packet);
    void abortSend(SCIONPacket *packet);

protected:
    virtual int totalQueuedSize();
    int handleAckOnPath(SCIONPacket *packet, bool rttSample);
};

#endif // PATH_MANAGER_H
