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

#ifndef SCION_PROTOCOL_H
#define SCION_PROTOCOL_H

#include <map>
#include <pthread.h>

#include "ConnectionManager.h"
#include "DataStructures.h"
#include "Mutex.h"
#include "OrderedList.h"
#include "ProtocolConfigs.h"
#include "SCIONDefines.h"

class SCIONProtocol {
public:
    SCIONProtocol(int sock, const char *sciond);
    virtual ~SCIONProtocol();

    virtual int bind(SCIONAddr addr, int sock);
    virtual int connect(SCIONAddr addr, double timeout=0.0);
    virtual int listen(int sock);
    virtual int send(uint8_t *buf, size_t len, SCIONAddr *dstAddr=NULL, double timeout=0.0);
    virtual int recv(uint8_t *buf, size_t len, SCIONAddr *srcAddr, double timeout=0.0);

    virtual int handlePacket(SCIONPacket *packet, uint8_t *buf);
    virtual void handleTimerEvent();
    virtual void handlePathError(SCIONPacket *packet);

    bool isReceiver();
    void setReceiver(bool receiver);
    void setBlocking(bool blocking);
    bool isBlocking();

    virtual bool claimPacket(SCIONPacket *packet, uint8_t *buf);
    virtual void start(SCIONPacket *packet, uint8_t *buf, int sock);

    bool isRunning();

    virtual void getStats(SCIONStats *stats);

    virtual bool readyToRead();
    virtual bool readyToWrite();
    virtual int registerSelect(Notification *n, int mode);
    virtual void deregisterSelect(int index);
    virtual int registerDispatcher(uint64_t flowID, uint16_t port, int sock);

    int setISDWhitelist(void *data, size_t len);

    virtual int shutdown(bool force=false);

    uint32_t getLocalIA();

    virtual void threadCleanup();

    int getPort();
    int maxPayloadSize(double timeout=0.0);

protected:
    PathManager            *mPathManager;

    int                    mSocket;
    uint16_t               mSrcPort;
    SCIONAddr              mDstAddr;
    uint16_t               mDstPort;
    int                    mProtocolID;
    bool                   mIsReceiver;
    bool                   mReadyToRead;
    bool                   mBlocking;
    Mutex                  mReadMutex;
    Mutex                  mStateMutex;
    pthread_cond_t         mReadCond;
    SCIONState             mState;
    uint64_t               mNextSendByte;

    // dead path probing
    uint32_t               mProbeInterval;
    uint32_t               mProbeNum;
    struct timeval         mLastProbeTime;

    pthread_t              mTimerThread;
};

class SSPProtocol: public SCIONProtocol {
public:
    SSPProtocol(int sock, const char *sciond);
    ~SSPProtocol();

    int connect(SCIONAddr addr, double timeout=0.0);
    int listen(int sock);
    int send(uint8_t *buf, size_t len, SCIONAddr *dstAddr=NULL, double timeout=0.0);
    int recv(uint8_t *buf, size_t len, SCIONAddr *srcAddr, double timeout=0.0);

    bool claimPacket(SCIONPacket *packet, uint8_t *buf);
    void start(SCIONPacket *packet, uint8_t *buf, int sock);
    int handlePacket(SCIONPacket *packet, uint8_t *buf);

    SCIONPacket * createPacket(uint8_t *buf, size_t len);

    void handleTimerEvent();

    void getStats(SCIONStats *stats);

    bool readyToRead();
    bool readyToWrite();
    int registerSelect(Notification *n, int mode);
    void deregisterSelect(int index);
    void signalSelect();

    void notifySender();

    int shutdown(bool force=false);
    void notifyFinAck();
    int registerDispatcher(uint64_t flowID, uint16_t port, int sock);

    void threadCleanup();

protected:
    void getWindowSize();
    int getDeadlineFromProfile(DataProfile profile);

    void handleProbe(SCIONPacket *packet);
    SSPPacket * checkOutOfOrderQueue(SSPPacket *sp);
    void handleInOrder(SSPPacket *sp, int pathIndex);
    void handleOutOfOrder(SSPPacket *sp, int pathIndex);
    void handleData(SSPPacket *packet, int pathIndex);
    void sendAck(SSPPacket *sip, int pathIndex);

    // path manager
    SSPConnectionManager *mConnectionManager;

    // initialization, connection establishment
    bool                   mInitialized;
    uint32_t               mLocalReceiveWindow;
    uint32_t               mLocalSendWindow;
    uint32_t               mRemoteWindow;
    int                    mInitAckCount;
    uint64_t               mFlowID;

    // ack bookkeeping
    uint64_t               mLowestPending;
    uint64_t               mHighestReceived;
    int                    mAckVectorOffset;

    // sending packets
    PacketList             mSentPackets;

    // recv'ing packets
    uint32_t                mTotalReceived;
    uint64_t                mNextPacket;
    OrderedList<SSPPacket *> *mReadyPackets;
    OrderedList<SSPPacket *> *mOOPackets;

    // select
    Mutex                   mSelectMutex;
    std::map<int, Notification> mSelectRead;
    std::map<int, Notification> mSelectWrite;
    int mSelectCount;
};

class SUDPProtocol : public SCIONProtocol {
public:
    SUDPProtocol(int sock, const char *sciond);
    ~SUDPProtocol();

    int bind(SCIONAddr addr, int sock);
    int send(uint8_t *buf, size_t len, SCIONAddr *dstAddr=NULL, double timeout=0.0);
    int recv(uint8_t *buf, size_t len, SCIONAddr *srcAddr, double timeout=0.0);

    int handlePacket(SCIONPacket *packet, uint8_t *buf);
    void handleTimerEvent();

    bool claimPacket(SCIONPacket *packet, uint8_t *buf);
    void start(SCIONPacket *packet, uint8_t *buf, int sock);
    int registerDispatcher(uint64_t flowID, uint16_t port, int sock);

    void getStats(SCIONStats *stats);

protected:
    SUDPConnectionManager *mConnectionManager;
    std::list<SCIONPacket *> mReceivedPackets;
    size_t mTotalReceived;
};

#endif //SCION_PROTOCOL_H
