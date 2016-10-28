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

#ifndef PATH_MANAGER_H
#define PATH_MANAGER_H

#include <vector>

#include "DataStructures.h"
#include "OrderedList.h"
#include "PathPolicy.h"
#include "SCIONDefines.h"
#include "Mutex.h"
#include "MutexScion.h"

class SSPProtocol;
class Path;
class PathState;

class PathManager {
public:
    PathManager(int sock, const char *sciond);
    virtual ~PathManager();

    void getDefaultIP();
    int getSocket();
    int getPathCount();
    int maxPayloadSize(double timeout=0.0);
    SCIONAddr * localAddress();

    void queryLocalAddress();
    int setLocalAddress(SCIONAddr addr);
    virtual int setRemoteAddress(SCIONAddr addr, double timeout=0.0);
    void getPaths(double timeout=0.0);

    virtual Path * createPath(SCIONAddr &dstAddr, uint8_t *rawPath, int pathLen);
    virtual void handleTimeout();
    virtual void handlePathError(SCIONPacket *packet);
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
    Mutex                        mPathMutex;
    Mutex                        mDispatcherMutex;
    pthread_cond_t               mPathCond;
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
    int waitForSendBuffer(int len, int windowSize, double timeout=0.0);

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

    bool                         mRunning;
    bool                         mFinAcked;
    int                          mFinAttempts;
    struct timeval               mFinSentTime;
    bool                         mInitAcked;
    bool                         mResendInit;
    uint64_t                     mHighestAcked;

    size_t                       mTotalSize;
    PacketList                   mSentPackets;
    OrderedList<SCIONPacket *>   *mRetryPackets;
    OrderedList<SCIONPacket *>   *mFreshPackets;

    pthread_cond_t               mCond;

    Mutex                        mSentMutex;
    pthread_cond_t               mSentCond;
    Mutex                        mFreshMutex;
    Mutex                        mRetryMutex;
    Mutex                        mPacketMutex;
    pthread_cond_t               mPacketCond;

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

    int setRemoteAddress(SCIONAddr addr, double timeout=0.0);

    Path * createPath(SCIONAddr &dstAddr, uint8_t *rawPath, int pathLen);
protected:
    void handleProbe(SUDPPacket *sp, SCIONExtension *ext, int index);

    struct timeval mLastProbeTime;
    std::vector<uint32_t> mLastProbeAcked;
};

#endif // PATH_MANAGER_H
