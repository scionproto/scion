#ifndef SCION_PROTOCOL_H
#define SCION_PROTOCOL_H

#include <pthread.h>

#include "SCIONDefines.h"
#include "DataStructures.h"
#include "ConnectionManager.h"
#include "RingBuffer.h"

class SCIONProtocol {
public:
    SCIONProtocol(std::vector<SCIONAddr> &dstAddrs, short srcPort, short dstPort);
    SCIONProtocol(const SCIONProtocol &p);
    virtual ~SCIONProtocol();

    SCIONProtocol & operator=(const SCIONProtocol &p);

    virtual int send(uint8_t *buf, size_t len, DataProfile profile);
    virtual int recv(uint8_t *buf, size_t len, SCIONAddr *srcAddr);

    virtual int handlePacket(SCIONPacket *packet, uint8_t *buf);
    virtual void handleTimerEvent();

    bool isReceiver();
    void setReceiver(bool receiver);

    virtual bool claimPacket(SCIONPacket *packet, uint8_t *buf);
    virtual void createManager(std::vector<SCIONAddr> &dstAddrs);
    virtual void start(SCIONPacket *packet, uint8_t *buf, int sock);

    bool isRunning();

    virtual void getStats(SCIONStats *stats);

protected:
    int                    mSocket;
    uint16_t               mSrcPort;
    uint16_t               mDstPort;
    int                    mProtocolID;
    bool                   mIsReceiver;
    bool                   mReadyToRead;
    pthread_mutex_t        mReadMutex;
    pthread_cond_t         mReadCond;
    bool                   mRunning;
    std::vector<SCIONAddr> &mDstAddrs;

    // dead path probing
    uint32_t               mProbeInterval;
    uint64_t               mProbeNum;
    struct timeval         mLastProbeTime;

    pthread_t              mTimerThread;
};

class SDAMPProtocol: public SCIONProtocol {
public:
    SDAMPProtocol(std::vector<SCIONAddr> &dstAddrs, short srcPort, short dstPort);
    ~SDAMPProtocol();

    virtual int send(uint8_t *buf, size_t len, DataProfile profile);
    virtual int recv(uint8_t *buf, size_t len, SCIONAddr *srcAddr);

    bool claimPacket(SCIONPacket *packet, uint8_t *buf);
    virtual void createManager(std::vector<SCIONAddr> &dstAddrs);
    void start(SCIONPacket *packet, uint8_t *buf, int sock);
    virtual int handlePacket(SCIONPacket *packet, uint8_t *buf);

    virtual SCIONPacket * createPacket(uint8_t *buf, size_t len);

    virtual void handleTimerEvent();

    virtual void getStats(SCIONStats *stats);

protected:
    void getWindowSize();
    int getDeadlineFromProfile(DataProfile profile);

    void handleProbe(SCIONPacket *packet);
    void handleProbeAck(SCIONPacket *packet);
    void handleAck(SCIONPacket *packet);
    void handleData(SCIONPacket *packet);
    void sendAck(SCIONPacket *packet);

    // path manager
    SDAMPConnectionManager *mConnectionManager;

    // initialization, connection establishment
    bool                   mInitialized;
    uint64_t               mFlowID;
    uint32_t               mLocalReceiveWindow;
    uint32_t               mLocalSendWindow;
    uint32_t               mRemoteWindow;
    int                    mInitAckCount;

    // ack bookkeeping
    uint64_t               mLowestPending;
    uint64_t               mHighestReceived;
    int                    mAckVectorOffset;

    // sending packets
    uint64_t               mNextSendByte;
    uint64_t               mLastPacketNum;
    PacketList             mSentPackets;
    pthread_mutex_t        mPacketMutex;

    // recv'ing packets
    uint32_t               mTotalReceived;
    uint64_t                mNextPacket;
private:
    std::list<SDAMPPacket *> mReadyPackets;
    std::list<SDAMPPacket *> mOOPackets;
};

class SSPProtocol : public SDAMPProtocol {
public:
    SSPProtocol(std::vector<SCIONAddr> &dstAddrs, short srcPort, short dstPort);
    ~SSPProtocol();

    void createManager(std::vector<SCIONAddr> &dstAddrs);

    int send(uint8_t *buf, size_t len, DataProfile profile);
    int recv(uint8_t *buf, size_t len, SCIONAddr *srcAddr);

    int handlePacket(SCIONPacket *packet, uint8_t *buf);
    void handleTimerEvent();

    SCIONPacket * createPacket(uint8_t *buf, size_t len);

    void getStats(SCIONStats *stats);

protected:
    void handleProbe(SSPInPacket *packet, int pathIndex);
    void handleData(SSPInPacket *packet, int pathIndex);
    void sendAck(SSPInPacket *sip, int pathIndex);

    uint64_t mNextOffset;
    RingBuffer *mReceiveBuffer;
    std::list<SSPInPacket *> mOOPackets;
};

class SUDPProtocol : public SCIONProtocol {
public:
    SUDPProtocol(std::vector<SCIONAddr> &dstAddrs, short srcPort, short dstPort);
    ~SUDPProtocol();

    void createManager(std::vector<SCIONAddr> &dstAddrs);

    int send(uint8_t *buf, size_t len, DataProfile profile);
    int recv(uint8_t *buf, size_t len, SCIONAddr *srcAddr);

    int handlePacket(SCIONPacket *packet, uint8_t *buf);
    void handleTimerEvent();

    bool claimPacket(SCIONPacket *packet, uint8_t *buf);
    void start(SCIONPacket *packet, uint8_t *buf, int sock);

    void getStats(SCIONStats *stats);

protected:
    SUDPConnectionManager *mConnectionManager;
    std::list<SUDPPacket *> mReceivedPackets;
    size_t mTotalReceived;
};

#endif //SCION_PROTOCOL_H
