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

#ifndef PATH_H
#define PATH_H

#include <pthread.h>

#include <vector>

#include "ConnectionManager.h"
#include "PathState.h"
#include "SCIONDefines.h"

enum CCType {
    CC_CBR,
    CC_PCC,
    CC_RENO,
    CC_CUBIC,
};

struct PathParams {
    SCIONAddr *localAddr;
    SCIONAddr *dstAddr;
    uint8_t *rawPath;
    size_t pathLen;
    CCType type;
};

class Path {
public:
    Path(PathManager *manager, PathParams *params);
    virtual ~Path();

    virtual int sendPacket(SCIONPacket *packet, int sock);

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
    std::vector<SCIONInterface> & getInterfaces();
    bool isUp();
    void setUp();
    bool isUsed();
    void setUsed(bool used);
    bool isValid();
    void setFirstHop(HostAddr *addr);

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

    Mutex           mMutex;

    PathManager *mManager;
};

class SSPPath : public Path {
public:
    SSPPath(SSPConnectionManager *manager, PathParams *params);
    ~SSPPath();

    virtual int sendPacket(SCIONPacket *packet, int sock);

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

    int             mTotalReceived;
    int             mTotalSent;
    int             mTotalAcked;
    int             mTimeoutCount;
    struct timeval  mLastLossTime;

    Mutex           mTimeMutex;
    Mutex           mWindowMutex;
    pthread_cond_t  mWindowCond;

    pthread_t       mThread;
};

class SUDPPath : public Path {
public:
    SUDPPath(SUDPConnectionManager *manager, PathParams *params);
    ~SUDPPath();

    int sendPacket(SCIONPacket *packet, int sock);

    int getPayloadLen(bool ack);
    void handleTimeout(struct timeval *current);
};

#endif // PATH_H
