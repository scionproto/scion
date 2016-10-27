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

#ifndef PATH_STATE_H
#define PATH_STATE_H

#include <pthread.h>
#include <set>
#include <list>

#include "SCIONDefines.h"
#include "Mutex.h"
#include "MutexScion.h"
#include "DataStructures.h"
#include "ProtocolConfigs.h"

#define MAX_LOSS_INTERVALS 8

#define VAR_SHIFT 2
#define ERR_SHIFT 3

using namespace std;

enum ALIType {
    ALI_FROM_INTERVAL_1,
    ALI_FROM_INTERVAL_0,
    ALI_HISTORY_DISCOUNTING
};

class PathState {
public:
    PathState(int rtt, int mtu);
    virtual ~PathState();

    virtual void setIndex(int index);
    virtual void setRemoteWindow(uint32_t sendWindow);

    virtual int timeUntilReady();
    virtual int bandwidth();
    virtual int estimatedRTT();
    virtual int getRTO();
    virtual int packetsInFlight();
    virtual double getLossRate();

    virtual void addLoss(uint64_t packetNum);
    virtual void addRTTSample(int rtt, uint64_t packetNum);
    virtual void addRetransmit();

    virtual void handleSend(uint64_t packetNum);
    virtual void handleTimeout();
    virtual void handleDupAck();

    virtual bool isWindowBased();
    virtual int window();

    int profileLoss();

protected:
    void calculateLoss(ALIType type);

    int             mPathIndex;
    int             mMTU;
    int             mRTO;
    int             mSRTT;
    int             mVAR;
    int             mLastRTT;
    int             mSendWindow;
    int             mCongestionWindow;
    int             mWindow;
    int             mInFlight;
    int             mLossBursts[SSP_MAX_LOSS_BURST];
    int             mCurrentBurst;
    bool            mInLoss;
    uint64_t        mTotalSent;
    uint64_t        mTotalAcked;
    uint64_t        mLastTotalAcked;
    uint64_t        mTotalLost;
    Mutex           mMutex;
    list<uint64_t>  mLossIntervals;
    uint64_t        mAverageLossInterval;
};

class CBRPathState: public PathState {
public:
    CBRPathState(int rtt, int mtu);

    int timeUntilReady();
    int bandwidth();

    virtual void handleSend(uint64_t packetNum);

protected:
    int             mSendInterval;
    struct timeval  mLastSendTime;
};

enum PCCState {
    PCC_START,
    PCC_DECISION,
    PCC_ADJUST
};

#define PCC_TRIALS 4
#define PCC_MIN_PACKETS 10
#define PCC_ADJUST_RATE 0.01
#define PCC_MAX_ADJUST_COUNT 5

class PCCPathState: public CBRPathState {
public:
    PCCPathState(int rtt, int mtu);

    int timeUntilReady();

    void handleSend(uint64_t packetNum);
    void addRTTSample(int rtt, uint64_t packetNum);
    void addLoss(uint64_t packetNum);

private:
    void handleMonitorEnd();
    void startDecision();
    double utility(int received, int lost, double time, double rtt);

    int             mLastSendInterval;

    set<uint64_t>   mMonitoredPackets;
    struct timeval  mMonitorStartTime;
    struct timeval  mMonitorEndTime;
    long            mMonitorDuration;
    double          mMonitorRTT;
    uint64_t        mMonitorReceived;
    uint64_t        mMonitorLost;
    bool            mMonitoring;
    Mutex           mMonitorMutex;

    double          mUtility;
    double          mTrialResults[PCC_TRIALS];
    int             mTrialIntervals[PCC_TRIALS];
    int             mCurrentTrial;
    int             mAdjustCount;
    int             mDirection;

    PCCState        mState;
};

enum TCPState {
    TCP_STATE_START,
    TCP_STATE_TIMEOUT,
    TCP_STATE_FAST_RETRANSMIT,
    TCP_STATE_NORMAL,
};

class RenoPathState: public PathState {
public:
    RenoPathState(int rtt, int mtu);

    int timeUntilReady();
    void handleTimeout();
    void handleDupAck();
    void addRTTSample(int rtt, uint64_t packetNum);
    void addRetransmit();
    bool isWindowBased();
    int window();

private:
    TCPState mState;
    int mThreshold;
    int mDupAckCount;
    int mAckCount;
};

#define BETA 0.2
#define C    0.4
#define CUBIC_SSTHRESH 100

class CUBICPathState: public PathState {
public:
    CUBICPathState(int rtt, int mtu);

    int timeUntilReady();

    void addRTTSample(int rtt, uint64_t packetNum);
    void addRetransmit();

    void handleSend(uint64_t packetNum);
    void handleTimeout();

    bool isWindowBased();
    int window();

private:
    void reset();
    void doTCPFriendly();
    void update();

    int             mThreshold;
    int             mWindowCount;
    int             mAckCount;
    int             mMinDelay;
    int             mMaxWindow;
    int             mTCPWindow;
    int             mOrigin;
    int             mCount;
    int             mK;
    bool            mTimeout;
    time_t          mEpochStart;
};

#endif // PATH_STATE_H
