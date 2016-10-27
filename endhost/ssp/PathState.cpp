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

#include <math.h>

#include "Mutex.h"
#include "PathState.h"
#include "Utils.h"

/* calculate the cubic root of x using a table lookup followed by one
 * Newton-Raphson iteration.
 * Avg err ~= 0.195%
 *
 * Taken (and slightly modified) from Linux TCP Cubic implementation
 */
static uint32_t cubeRoot(uint64_t a)
{
    uint32_t x, b, shift;
    uint64_t c;
    /*
     * cbrt(x) MSB values for x MSB values in [0..63].
     * Precomputed then refined by hand - Willy Tarreau
     *
     * For x in [0..63],
     *   v = cbrt(x << 18) - 1
     *   cbrt(x) = (v[x] + 10) >> 6
     */
    static const uint8_t v[] = {
        /* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
        /* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
        /* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
        /* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
        /* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
        /* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
        /* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
        /* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
    };

    /* Probably not the fastest way but works without using asm */
    b = 0;
    c = a;
    while (c >>= 1)
        b++;
    b++;

    if (b < 7) {
        /* a in [0..63] */
        return ((uint32_t)v[(uint32_t)a] + 35) >> 6;
    }

    b = ((b * 84) >> 8) - 1;
    shift = (a >> (b * 3));

    x = ((uint32_t)(((uint32_t)v[shift] + 10) << b)) >> 6;

    /*
     * Newton-Raphson iteration
     *                         2
     * x    = ( 2 * x  +  a / x  ) / 3
     *  k+1          k         k
     */
    x = 2 * x + (uint32_t)(a / ((uint64_t)x * (uint64_t)(x - 1)));
    x = ((x * 341) >> 10);
    return x;
}

PathState::PathState(int rtt, int mtu)
    : mPathIndex(-1),
    mMTU(mtu),
    mSRTT(rtt),
    mLastRTT(rtt),
    mSendWindow(2),
    mCongestionWindow(1),
    mWindow(1),
    mInFlight(0),
    mCurrentBurst(0),
    mInLoss(false),
    mTotalSent(0),
    mTotalAcked(0),
    mLastTotalAcked(0),
    mTotalLost(0),
    mAverageLossInterval(0)
{
    mVAR = rtt >> VAR_SHIFT;
    mRTO = mSRTT + (mVAR << 2);
    mSRTT = 0; // initial RTT estimate used for RTO only
    memset(mLossBursts, 0, sizeof(mLossBursts));
    Mutex mMutex;
}

PathState::~PathState()
{
}

void PathState::setIndex(int index)
{
    mPathIndex = index;
}

void PathState::setRemoteWindow(uint32_t sendWindow)
{
    mSendWindow = sendWindow;
    DEBUG("send window set to %d\n", mSendWindow);
}

int PathState::timeUntilReady()
{
    return 0;
}

int PathState::bandwidth()
{
    if (mSRTT == 0)
        return 0;
    return mWindow * mMTU / mSRTT * 1000000;
}

int PathState::estimatedRTT() EXCLUDES(mMutex)
{
    int ret;
    mMutex.Lock();
    ret = mSRTT;
    mMutex.Unlock();
    return ret;
}

int PathState::getRTO() EXCLUDES(mMutex)
{
    int ret;
    mMutex.Lock();
    ret = mRTO;
    mMutex.Unlock();
    return ret;
}

int PathState::packetsInFlight() EXCLUDES(mMutex)
{
    int ret;
    mMutex.Lock();
    ret = mInFlight;
    mMutex.Unlock();
    return ret;
}

double PathState::getLossRate() EXCLUDES(mMutex)
{
    mMutex.Lock();
    uint64_t currentInterval = mTotalAcked - mLastTotalAcked;
    if (currentInterval > mAverageLossInterval) {
        if (currentInterval > 2 * mAverageLossInterval)
            calculateLoss(ALI_HISTORY_DISCOUNTING);
        else
            calculateLoss(ALI_FROM_INTERVAL_0);
    }
    mMutex.Unlock();
    if (mAverageLossInterval == 0)
        return 0.0;
    return 1.0 / mAverageLossInterval;
}

void PathState::addLoss(uint64_t packetNum) EXCLUDES(mMutex)
{
    mTotalLost++;
    mMutex.Lock();
    mInFlight--;
    mMutex.Unlock();
    mCurrentBurst++;
    mInLoss = true;
    if (mCurrentBurst == SSP_MAX_LOSS_BURST) {
        mLossBursts[SSP_MAX_LOSS_BURST - 1]++;
        mCurrentBurst = 0;
        mInLoss = false;
    }
}

void PathState::addRTTSample(int rtt, uint64_t packetNum) EXCLUDES(mMutex)
{
    mTotalAcked++;
    mMutex.Lock();
    mInFlight--;
    DEBUG("path %d: receive ack: %d packets now in flight\n", mPathIndex, mInFlight);
    if (rtt > 0) {
        mLastRTT = rtt;
        if (mSRTT == 0) {
            mSRTT = rtt;
            mVAR = rtt >> 1;
        } else {
            int err = rtt - mSRTT;
            mSRTT += err >> ERR_SHIFT;
            err = err >= 0 ? err : -err;
            mVAR += (err - mVAR) >> VAR_SHIFT;
        }
        mRTO = mSRTT + (mVAR << 2);
        if (mRTO > SSP_MAX_RTO)
            mRTO = SSP_MAX_RTO;
        DEBUG("path %d: RTT sample %d us, sRTT = %d us, RTO = %d us\n", mPathIndex, rtt, mSRTT, mRTO);
    }
    if (mInLoss) {
        mLossBursts[mCurrentBurst]++;
        mCurrentBurst = 0;
        mInLoss = false;
    }
    mMutex.Unlock();
}

void PathState::addRetransmit() EXCLUDES(mMutex)
{
    mMutex.Lock();
    mLossIntervals.push_front(mTotalAcked - mLastTotalAcked);
    if (mLossIntervals.size() > MAX_LOSS_INTERVALS)
        mLossIntervals.pop_back();
    DEBUG("loss on path %d: new loss interval = %ld, %d/%d in flight\n",
            mPathIndex, mTotalAcked - mLastTotalAcked, mInFlight, mWindow);
    mLastTotalAcked = mTotalAcked;
    calculateLoss(ALI_FROM_INTERVAL_1);
    mMutex.Unlock();
}

void PathState::handleSend(uint64_t packetNum) EXCLUDES(mMutex)
{
    mMutex.Lock();
    mInFlight++;
    mTotalSent++;
    DEBUG("path %d: send: %d/%d packets now in flight\n", mPathIndex, mInFlight, mWindow);
    mMutex.Unlock();
}


void PathState::handleTimeout() EXCLUDES(mMutex)
{
    mMutex.Lock();
    mRTO = mRTO << 1;
    if (mRTO > SSP_MAX_RTO)
        mRTO = SSP_MAX_RTO;
    DEBUG("timeout: new rto = %d\n", mRTO);
    mMutex.Unlock();
}

void PathState::handleDupAck()
{
}

void PathState::calculateLoss(ALIType type)
{
    if (mLossIntervals.empty())
        return;

    uint64_t currentInterval = mTotalAcked - mLastTotalAcked;
    size_t i;
    list<uint64_t>::iterator it;
    size_t n = mLossIntervals.size();
    double ws = 0.0;
    double w = 0.0;
    double d[MAX_LOSS_INTERVALS + 1];
    double di = 2.0 * mAverageLossInterval / currentInterval;
    double wi;
    DEBUG("calculate average loss interval (%d), currentInterval = %ld\n", type, currentInterval);
    if (di < 0.5)
        di = 0.5;
    for (i = 0; i <= MAX_LOSS_INTERVALS; i++)
        d[i] = 1.0;
    switch (type) {
        case ALI_HISTORY_DISCOUNTING:
            for (i = 1; i < MAX_LOSS_INTERVALS; i++)
                d[i] = di;
        case ALI_FROM_INTERVAL_0:
            mLossIntervals.push_front(currentInterval);
        case ALI_FROM_INTERVAL_1:
            for (it = mLossIntervals.begin(), i = 1; it != mLossIntervals.end() && i < MAX_LOSS_INTERVALS; it++, i++) {
                if (i <= n / 2) {
                    ws += d[i - 1] * (*it);
                    w += d[i - 1];
                } else {
                    wi = 1 - (i - n / 2.0) / (n / 2.0 + 1);
                    ws += d[i - 1] * wi * (*it);
                    w += d[i - 1] * wi;
                }
            }
            break;
        default:
            break;
    }
    if (type != ALI_FROM_INTERVAL_1)
        mLossIntervals.pop_front();
    mAverageLossInterval = ws / w;
    DEBUG("average loss interval = %ld\n", mAverageLossInterval);
}

bool PathState::isWindowBased()
{
    return false;
}

int PathState::window()
{
    return 0;
}

int PathState::profileLoss()
{
    double p, q;

    int m = 0;
    for (int i = 1; i < SSP_MAX_LOSS_BURST; i++)
        m += mLossBursts[i];
    p = (double)m / mTotalAcked;

    int mi1 = 0, mi2 = 0;
    for (int i = 2; i < SSP_MAX_LOSS_BURST; i++)
        mi2 += mLossBursts[i] * (i - 1);
    for (int i = 1; i < SSP_MAX_LOSS_BURST; i++)
        mi1 += mLossBursts[i] * i;
    q = 1 - (double)mi2 / mi1;

    printf("p = %f, q = %f\n", p, q);
    return 0;
}

// CBR

CBRPathState::CBRPathState(int rtt, int mtu)
    : PathState(rtt, mtu),
    mSendInterval(SSP_SEND_INTERVAL)
{
    memset(&mLastSendTime, 0, sizeof(mLastSendTime));
}

int CBRPathState::timeUntilReady()
{
    if (mLastSendTime.tv_sec == 0)
        return 0;

    struct timeval current;
    gettimeofday(&current, NULL);
    DEBUG("%ld us since last send\n", elapsedTime(&mLastSendTime, &current));
    int time = mSendInterval - elapsedTime(&mLastSendTime, &current);
    if (time < 0)
        time = 0;
    return time;
}

int CBRPathState::bandwidth()
{
    return mMTU / mSendInterval * 1000000;
}

void CBRPathState::handleSend(uint64_t packetNum)
{
    PathState::handleSend(packetNum);
    gettimeofday(&mLastSendTime, NULL);
}

// PCC

PCCPathState::PCCPathState(int rtt, int mtu)
    : CBRPathState(rtt, mtu),
    mLastSendInterval(SSP_SEND_INTERVAL),
    mMonitorRTT(0.0),
    mMonitorReceived(0),
    mMonitorLost(0),
    mMonitoring(false),
    mUtility(0.0),
    mCurrentTrial(0),
    mAdjustCount(0),
    mDirection(0),
    mState(PCC_START)
{
    memset(&mMonitorStartTime, 0, sizeof(mMonitorStartTime));
    memset(&mMonitorEndTime, 0, sizeof(mMonitorEndTime));
    memset(mTrialResults, 0, sizeof(mTrialResults));
    memset(mTrialIntervals, 0, sizeof(mTrialIntervals));
    Mutex mMonitorMutex;
}

int PCCPathState::timeUntilReady()
{
    int currentInterval = mSendInterval;
    if (mState == PCC_DECISION)
        mSendInterval = mTrialIntervals[mCurrentTrial];
    int res = CBRPathState::timeUntilReady();
    mSendInterval = currentInterval;
    return res;
}

void PCCPathState::handleSend(uint64_t packetNum) EXCLUDES(mMonitorMutex)
{
    struct timeval t;
    gettimeofday(&t, NULL);
    CBRPathState::handleSend(packetNum);
    if (!mMonitoring) {
        DEBUG("%ld.%06ld: current state = %d, begin monitoring\n", t.tv_sec, t.tv_usec, mState);
        mMonitorStartTime = t;
        srand(t.tv_usec);
        double x = (double)rand() / RAND_MAX; // 0 ~ 1.0
        x /= 2.0; // 0 ~ 0.5
        x += 1.7; // 1.7 ~ 2.2
        mMonitorDuration = x * mSRTT;
        if (mMonitorDuration < PCC_MIN_PACKETS * mSendInterval)
            mMonitorDuration = PCC_MIN_PACKETS * mSendInterval;
        mMonitorRTT = 0;
        mMonitorReceived = 0;
        mMonitorLost = 0;
        mMonitoring = true;
    }
    if (mMonitoring) {
        if (elapsedTime(&mMonitorStartTime, &t) < mMonitorDuration ) {
            mMonitorMutex.Lock();
            mMonitoredPackets.insert(packetNum);
            mMonitorMutex.Unlock();
        }
    }
}

void PCCPathState::addRTTSample(int rtt, uint64_t packetNum) EXCLUDES(mMonitorMutex)
{
    PathState::addRTTSample(rtt, packetNum);

    if (mMonitoring) {
        bool found = false;
        mMonitorMutex.Lock();
        found = mMonitoredPackets.find(packetNum) != mMonitoredPackets.end();
        mMonitorMutex.Unlock();
        if (found) {
            mMonitorReceived++;
            mMonitorRTT += rtt;
            DEBUG("current state = %d: got ack %ld\n", mState, packetNum);
        }
    }
    struct timeval t;
    gettimeofday(&t, NULL);
    if (elapsedTime(&mMonitorStartTime, &t) >= mMonitorDuration + mSRTT)
        handleMonitorEnd();
}

void PCCPathState::addLoss(uint64_t packetNum)
{
    PathState::addLoss(packetNum);
    struct timeval t;
    gettimeofday(&t, NULL);
    if (elapsedTime(&mMonitorStartTime, &t) >= mMonitorDuration + mSRTT)
        handleMonitorEnd();
}

void PCCPathState::handleMonitorEnd() EXCLUDES(mMonitorMutex)
{
    if (!mMonitoring)
        return;

    mMonitorMutex.Lock();
    gettimeofday(&mMonitorEndTime, NULL);
    DEBUG("%ld.%06ld: monitor end\n", mMonitorEndTime.tv_sec, mMonitorEndTime.tv_usec);
    long monitorTime = elapsedTime(&mMonitorStartTime, &mMonitorEndTime);
    if (mMonitorReceived == 0) {
        mMonitorRTT = SSP_MAX_RTO;
    } else {
        mMonitorRTT /= mMonitorReceived;
    }
    DEBUG("%lu packets sent during this interval, %lu received\n", mMonitoredPackets.size(), mMonitorReceived);
    mMonitorLost = mMonitoredPackets.size() - mMonitorReceived;
    double u = utility(mMonitorReceived, mMonitorLost, monitorTime / 1000000.0, mMonitorRTT);
    DEBUG("utility %f\n", u);
    if (mState == PCC_DECISION) {
        DEBUG("decision phase, trial %d\n", mCurrentTrial);
        mTrialResults[mCurrentTrial++] = u;
        if (mCurrentTrial == PCC_TRIALS) {
            int direction = 0;
            for (int i = 0; i < PCC_TRIALS - 1; i += 2) {
                if (mTrialIntervals[i] < mSendInterval) {
                    // i: shorter period, i + 1: longer period
                    if (mTrialResults[i] > mTrialResults[i + 1])
                        direction--;
                    else if (mTrialResults[i] < mTrialResults[i + 1])
                        direction++;
                } else {
                    // i: longer period, i + 1: shorter period
                    if (mTrialResults[i] > mTrialResults[i + 1])
                        direction++;
                    else if (mTrialResults[i] < mTrialResults[i + 1])
                        direction--;
                }
            }
            if (direction == 0) {
                DEBUG("inconclusive, do over with larger deltas\n");
                mAdjustCount++;
                if (mAdjustCount > PCC_MAX_ADJUST_COUNT)
                    mAdjustCount = PCC_MAX_ADJUST_COUNT;
                startDecision();
            } else {
                mDirection = direction / 2; // direction = +-2, mDirection = +-1
                mState = PCC_ADJUST;
                mLastSendInterval = mSendInterval;
                mSendInterval += mSendInterval * mDirection * mAdjustCount * PCC_ADJUST_RATE;
                DEBUG("switched to adjust phase, direction = %d with %d us period\n", mDirection, mSendInterval);
            }
        }
    } else if (mState == PCC_ADJUST) {
        if (u >= mUtility) {
            mAdjustCount++;
            if (mAdjustCount > PCC_MAX_ADJUST_COUNT)
                mAdjustCount = PCC_MAX_ADJUST_COUNT;
            mLastSendInterval = mSendInterval;
            mSendInterval += mSendInterval * mDirection * mAdjustCount * PCC_ADJUST_RATE;
            DEBUG("utility increased, keep going in direction %d with %d us period\n", mDirection, mSendInterval);
        } else {
            mSendInterval = mLastSendInterval;
            mAdjustCount = 1;
            DEBUG("utility decreased, drop back to decision phase with %d us period\n", mSendInterval);
            startDecision();
        }
        mUtility = u;
    } else if (mState == PCC_START) {
        if (u >= mUtility) {
            mLastSendInterval = mSendInterval;
            mSendInterval /= 2;
            DEBUG("utility increased, double speed: %d us period\n", mSendInterval);
        } else {
            mSendInterval = mLastSendInterval;
            mAdjustCount = 1;
            DEBUG("utility decreased, drop down to decision phase with %d us period\n", mSendInterval);
            startDecision();
        }
        mUtility = u;
    }
    if (mSendInterval > SSP_MAX_SEND_INTERVAL)
        mSendInterval = SSP_MAX_SEND_INTERVAL;
    mMonitoredPackets.clear();
    mMonitoring = false;
    if (mMonitorReceived == 0)
        mSendInterval *= 2;
    mMonitorMutex.Unlock();
}

void PCCPathState::startDecision()
{
    srand(time(NULL));
    for (int i = 0; i < PCC_TRIALS - 1; i += 2) {
        int delta = (rand() % 2) * 2 - 1;
        delta *= mAdjustCount * PCC_ADJUST_RATE * mSendInterval;
        mTrialIntervals[i] = mSendInterval + delta;
        mTrialIntervals[i + 1] = mSendInterval - delta;
    }
    mCurrentTrial = 0;
    mState = PCC_DECISION;
}

double PCCPathState::utility(int received, int lost, double time, double rtt)
{
    DEBUG("%d %d %f %f\n", received, lost, time, rtt);
        //utility = ((t-l)/time*(1-1/(1+exp(-100*(l/t-0.05))))-1*l/time);
        //utility = ((t-l)/time*(1-1/(1+exp(-100*(l/t-0.05))))* (1-1/(1+exp(-10*(1-previous_rtt/rtt)))) -1*l/time)/rtt*1000;
    return received / time * (1 - 1 / (1 + exp(-100 * (lost / (received + lost) - 0.05)))) - lost / time;
}

// TCP Reno

RenoPathState::RenoPathState(int rtt, int mtu)
    : PathState(rtt, mtu),
    mState(TCP_STATE_START),
    mThreshold(-1),
    mDupAckCount(0),
    mAckCount(0)
{
}

int RenoPathState::timeUntilReady()
{
    if (mInFlight < mWindow) {
        DEBUG("path %d: room in window (%d/%d), send right away\n", mPathIndex, mInFlight, mWindow);
        return 0;
    } else {
        DEBUG("path %d: window full, wait about 1 RTT (%d us)\n", mPathIndex, mSRTT);
        return mSRTT ? mSRTT : mRTO;
    }
}

void RenoPathState::handleTimeout()
{
    PathState::handleTimeout();
    mState = TCP_STATE_TIMEOUT;
    mCongestionWindow = 1;
    DEBUG("path %d: timeout: congestion window set to 1\n", mPathIndex);
}

void RenoPathState::handleDupAck()
{
    mDupAckCount++;
    if (mState > SSP_FR_THRESHOLD && mState == TCP_STATE_FAST_RETRANSMIT) {
        mCongestionWindow++;
        mWindow = mCongestionWindow > mSendWindow ? mSendWindow : mCongestionWindow;
        DEBUG("path %d: duplicate ack received: window set to %d (%d/%d)\n", mPathIndex, mWindow, mCongestionWindow, mSendWindow);
    }
}

void RenoPathState::addRTTSample(int rtt, uint64_t packetNum)
{
    PathState::addRTTSample(rtt, packetNum);

    mDupAckCount = 0;
    mAckCount++;
    switch (mState) {
        case TCP_STATE_START:
        case TCP_STATE_TIMEOUT:
            DEBUG("path %d: slow start: %d -> %d\n", mPathIndex, mCongestionWindow, mCongestionWindow + 1);
            mCongestionWindow++;
            if (mCongestionWindow == mThreshold) {
                DEBUG("path %d: reached threshold: %d\n", mPathIndex,  mThreshold);
                mState = TCP_STATE_NORMAL;
            }
            break;
        case TCP_STATE_FAST_RETRANSMIT:
            mState = TCP_STATE_NORMAL;
            mCongestionWindow = mThreshold;
            break;
        case TCP_STATE_NORMAL:
            if (mAckCount == mCongestionWindow) {
                DEBUG("path %d: congestion avoidance: %d -> %d\n", mPathIndex, mCongestionWindow, mCongestionWindow + 1);
                mAckCount = 0;
                mCongestionWindow++;
            }
            break;
        default:
            break;
    }
    mWindow = mCongestionWindow > mSendWindow ? mSendWindow : mCongestionWindow;
    DEBUG("path %d: ack received: window set to %d (%d/%d)\n", mPathIndex, mWindow, mCongestionWindow, mSendWindow);
}

void RenoPathState::addRetransmit()
{
    PathState::addRetransmit();

    mThreshold = mWindow >> 1;
    if (mThreshold < 2)
        mThreshold = 2;
    mAckCount = 0;
    if (mState != TCP_STATE_TIMEOUT && mState != TCP_STATE_FAST_RETRANSMIT) {
        mState = TCP_STATE_FAST_RETRANSMIT;
        mCongestionWindow = mThreshold + 3;
    }
    mWindow = mCongestionWindow > mSendWindow ? mSendWindow : mCongestionWindow;
    DEBUG("path %d: packet loss: window set to %d (%d/%d)\n", mPathIndex, mWindow, mCongestionWindow, mSendWindow);
}

bool RenoPathState::isWindowBased()
{
    return true;
}

int RenoPathState::window()
{
    return mWindow;
}

// TCP CUBIC

CUBICPathState::CUBICPathState(int rtt, int mtu)
    : PathState(rtt, mtu),
    mThreshold(-1),
    mTimeout(false)
{
    reset();
}

int CUBICPathState::timeUntilReady() EXCLUDES(mMutex)
{
    mMutex.Lock();
    if (mInFlight < mWindow) {
        DEBUG("path %d: room in window (%d/%d), send right away\n", mPathIndex, mInFlight, mWindow);
        mMutex.Unlock();
        return 0;
    } else {
        DEBUG("path %d: window full (%d/%d), wait about 1 RTT (%d us)\n", mPathIndex, mInFlight, mWindow, mSRTT);
        mMutex.Unlock();
        return mSRTT ? mSRTT : mRTO;
    }
}

void CUBICPathState::addRTTSample(int rtt, uint64_t packetNum)
{
    PathState::addRTTSample(rtt, packetNum);
    if (rtt == 0)
        return;

    mTimeout = false;
    if (mMinDelay == 0 || mMinDelay > rtt)
        mMinDelay = rtt;
    mAckCount++;

    int thresh = mThreshold > 0 ? mThreshold : CUBIC_SSTHRESH;
    if (mCongestionWindow < thresh) {
        mCongestionWindow++;
        DEBUG("path %d: slow start, increase to %d\n", mPathIndex, mCongestionWindow);
    } else {
        update();
        DEBUG("path %d: congestion avoidance (%d/%d)\n", mPathIndex, mWindowCount, mCount);
        if (mWindowCount > mCount) {
            mCongestionWindow++;
            DEBUG("path %d: increase window to %d\n", mPathIndex, mCongestionWindow);
            mWindowCount = 0;
        } else {
            mWindowCount++;
        }
    }

    mWindow = mCongestionWindow < mSendWindow ? mCongestionWindow : mSendWindow;
    DEBUG("path %d: ack received: window set to %d (%d|%d)\n", mPathIndex, mWindow, mCongestionWindow, mSendWindow);
}

void CUBICPathState::addRetransmit() EXCLUDES(mMutex)
{
    PathState::addRetransmit();

    mEpochStart = 0;
    if (mCongestionWindow < mMaxWindow)
        mMaxWindow = mCongestionWindow * (2 - BETA) / 2;
    else
        mMaxWindow = mCongestionWindow;
    mCongestionWindow *= (1 - BETA);
    if (mCongestionWindow < 1)
        mCongestionWindow = 1;
    mThreshold = mCongestionWindow;
    if (mTimeout)
        mCongestionWindow = 1;

    mMutex.Lock();
    mWindow = mCongestionWindow < mSendWindow ? mCongestionWindow : mSendWindow;
    mMutex.Unlock();
    DEBUG("path %d: packet loss: window set to %d (last max window %d)\n", mPathIndex, mWindow, mMaxWindow);
}

void CUBICPathState::handleSend(uint64_t packetNum)
{
    PathState::handleSend(packetNum);
}

void CUBICPathState::handleTimeout()
{
    PathState::handleTimeout();
    mTimeout = true;
    mThreshold = (1 - BETA) * mCongestionWindow;
    reset();
    DEBUG("path %d: timeout: congestion window dropped to 1\n", mPathIndex);
}

void CUBICPathState::reset()
{
    mWindowCount = 0;
    mAckCount = 0;
    mMinDelay = 0;
    mMaxWindow = 0;
    mTCPWindow = 0;
    mOrigin = 0;
    mCount = 0;
    mK = 0;
    mEpochStart = 0;
}

void CUBICPathState::doTCPFriendly()
{
    mTCPWindow += 3 * BETA / (2 - BETA) * mAckCount / mCongestionWindow;
    mAckCount = 0;
    if (mTCPWindow > mCongestionWindow) {
        if (mCount > mCongestionWindow / (mTCPWindow - mCongestionWindow))
            mCount = mCongestionWindow / (mTCPWindow - mCongestionWindow);
    }
}

void CUBICPathState::update()
{
    time_t timestamp = time(NULL);
    if (mEpochStart == 0) {
        mEpochStart = timestamp;
        if (mCongestionWindow < mMaxWindow) {
            mK = cubeRoot((mMaxWindow - mCongestionWindow) / C);
            mOrigin = mMaxWindow;
        } else {
            mK = 0;
            mOrigin = mCongestionWindow;
        }
        mAckCount = 1;
        mTCPWindow = mCongestionWindow;
    }
    int t = timestamp + mMinDelay / 1000000 - mEpochStart;
    int x = t - mK;
    int target = mOrigin + C * x * x * x;
    if (target > mCongestionWindow)
        mCount = mCongestionWindow / (target - mCongestionWindow);
    else
        mCount = 100 * mCongestionWindow;
    doTCPFriendly();
}

bool CUBICPathState::isWindowBased()
{
    return true;
}

int CUBICPathState::window()
{
    return mWindow;
}
