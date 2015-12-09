#ifndef SCION_PROTOCOL_H
#define SCION_PROTOCOL_H

#include <pthread.h>

#include "SCIONDefines.h"
#include "DataStructures.h"
#include "ConnectionManager.h"
#include "OrderedList.h"

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

class SSPProtocol: public SCIONProtocol {
public:
    SSPProtocol(std::vector<SCIONAddr> &dstAddrs, short srcPort, short dstPort);
    ~SSPProtocol();

    int send(uint8_t *buf, size_t len, DataProfile profile);
    int recv(uint8_t *buf, size_t len, SCIONAddr *srcAddr);

    bool claimPacket(SCIONPacket *packet, uint8_t *buf);
    void createManager(std::vector<SCIONAddr> &dstAddrs);
    void start(SCIONPacket *packet, uint8_t *buf, int sock);
    int handlePacket(SCIONPacket *packet, uint8_t *buf);

    SCIONPacket * createPacket(uint8_t *buf, size_t len);

    void handleTimerEvent();

    void getStats(SCIONStats *stats);

protected:
    void getWindowSize();
    int getDeadlineFromProfile(DataProfile profile);

    void handleProbe(SSPPacket *packet, int pathIndex);
    void handleData(SSPPacket *packet, int pathIndex);
    void sendAck(SSPPacket *sip, int pathIndex, bool full=false);

    bool isFirstPacket();
    void didRead(L4Packet *packet);

    // path manager
    SSPConnectionManager *mConnectionManager;

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
    PacketList             mSentPackets;
    pthread_mutex_t        mPacketMutex;

    // recv'ing packets
    uint32_t                mTotalReceived;
    uint64_t                mNextPacket;
    OrderedList<L4Packet *> *mReadyPackets;
    OrderedList<L4Packet *> *mOOPackets;
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
