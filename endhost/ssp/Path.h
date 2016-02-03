#ifndef PATH_H
#define PATH_H

#include <pthread.h>

#include <vector>

#include "ConnectionManager.h"
#include "PathState.h"
#include "SCIONDefines.h"

class Path {
public:
    Path(PathManager *manager, SCIONAddr &localAddr, SCIONAddr &dstAddr, uint8_t *rawPath, size_t pathLen);
    virtual ~Path();

    virtual int send(SCIONPacket *packet, int sock);

    virtual void handleTimeout(struct timeval *current);

    virtual int timeUntilReady();
    virtual int getPayloadLen(bool ack);
    int getETA(SCIONPacket *packet);
    int getRTT();
    int getRTO();
    int getMTU();
    double getLossRate();
    long getIdleTime(struct timeval *current);
    int getIndex();
    virtual void setIndex(int index);
    void setRawPath(uint8_t *path, int len);
    void setInterfaces(uint8_t *interfaces, size_t count);
    bool isUp();
    void setUp();
    bool isUsed();
    void setUsed(bool used);
    bool isValid();
    void setFirstHop(int len, uint8_t *addr);

    virtual bool didTimeout(struct timeval *current);

    bool usesSameInterfaces(uint8_t *interfaces, size_t count);
    bool isSamePath(uint8_t *path, size_t len);

    void copySCIONHeader(uint8_t *bufptr, SCIONHeader *sh);

    virtual void getStats(SCIONStats *stats);

protected:
    int             mIndex;
    int             mSocket;

    PathState       *mState;
    size_t          mPathLen;
    uint8_t         *mPath;

    SCIONAddr       mLocalAddr;
    SCIONAddr       mDstAddr;
    HostAddr        mFirstHop;
    std::vector<SCIONInterface> mInterfaces;

    uint16_t        mMTU;
    bool            mUp;

    bool            mUsed;
    bool            mValid;
    int             mProbeAttempts;
    struct timeval  mLastSendTime;

    pthread_mutex_t mMutex;
};

class SSPPath : public Path {
public:
    SSPPath(SSPConnectionManager *manager, SCIONAddr &localAddr, SCIONAddr &dstAddr, uint8_t *rawPath, size_t pathLen);
    ~SSPPath();

    virtual int send(SCIONPacket *packet, int sock);

    int handleData(SCIONPacket *packet);
    virtual int handleAck(SCIONPacket *packet, bool rttSample);
    void handleDupAck();
    void handleTimeout(struct timeval *current);

    void addLoss(uint64_t packetNum);
    void addRetransmit();

    bool didTimeout(struct timeval *current);
    
    virtual int timeUntilReady();
    virtual int getPayloadLen(bool ack);
    void setIndex(int index);
    void setRemoteWindow(uint32_t window);

    void getStats(SCIONStats *stats);
protected:
    uint8_t *copySSPPacket(SSPPacket *sp, uint8_t *bufptr, bool probe);
    void postProcessing(SCIONPacket *packet, bool probe);

    SSPConnectionManager *mManager;

    int             mTotalReceived;
    int             mTotalSent;
    int             mTotalAcked;
    int             mTimeoutCount;
    struct timeval  mLastLossTime;

    pthread_mutex_t mTimeMutex;
    pthread_mutex_t mWindowMutex;
    pthread_cond_t  mWindowCond;

    pthread_t       mThread;
};

class SUDPPath : public Path {
public:
    SUDPPath(SUDPConnectionManager *manager, SCIONAddr &localAddr, SCIONAddr &dstAddr, uint8_t *rawPath, size_t pathLen);
    ~SUDPPath();

    int send(SCIONPacket *packet, int sock);

    int getPayloadLen(bool ack);
    void handleTimeout(struct timeval *current);
};

#endif // PATH_H
