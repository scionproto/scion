#ifndef SCION_PROTOCOL_H
#define SCION_PROTOCOL_H

#include <map>
#include <pthread.h>

#include "ConnectionManager.h"
#include "DataStructures.h"
#include "OrderedList.h"
#include "ProtocolConfigs.h"
#include "SCIONDefines.h"

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
    void setBlocking(bool blocking);
    bool isBlocking();

    virtual bool claimPacket(SCIONPacket *packet, uint8_t *buf);
    virtual void createManager(std::vector<SCIONAddr> &dstAddrs, bool paths);
    virtual void start(SCIONPacket *packet, uint8_t *buf, int sock);

    bool isRunning();

    virtual void getStats(SCIONStats *stats);

    virtual bool readyToRead();
    virtual bool readyToWrite();
    virtual int registerSelect(Notification *n, int mode);
    virtual void deregisterSelect(int index);

    int setStayISD(uint16_t isd);

    virtual int shutdown();
    virtual void removeDispatcher(int sock);

protected:
    PathManager            *mPathManager;

    int                    mSocket;
    uint16_t               mSrcPort;
    uint16_t               mDstPort;
    int                    mProtocolID;
    bool                   mIsReceiver;
    bool                   mReadyToRead;
    bool                   mBlocking;
    pthread_mutex_t        mReadMutex;
    pthread_cond_t         mReadCond;
    SCIONState             mState;
    std::vector<SCIONAddr> &mDstAddrs;

    // dead path probing
    uint32_t               mProbeInterval;
    uint32_t               mProbeNum;
    struct timeval         mLastProbeTime;

    pthread_t              mTimerThread;
    pthread_mutex_t        mStateMutex;
};

class SSPProtocol: public SCIONProtocol {
public:
    SSPProtocol(std::vector<SCIONAddr> &dstAddrs, short srcPort, short dstPort);
    ~SSPProtocol();

    int send(uint8_t *buf, size_t len, DataProfile profile);
    int recv(uint8_t *buf, size_t len, SCIONAddr *srcAddr);

    bool claimPacket(SCIONPacket *packet, uint8_t *buf);
    void createManager(std::vector<SCIONAddr> &dstAddrs, bool paths);
    void start(SCIONPacket *packet, uint8_t *buf, int sock);
    int handlePacket(SCIONPacket *packet, uint8_t *buf);

    SCIONPacket * createPacket(uint8_t *buf, size_t len);

    void handleTimerEvent();

    void getStats(SCIONStats *stats);

    bool readyToRead();
    bool readyToWrite();
    int registerSelect(Notification *n, int mode);
    void deregisterSelect(int index);

    void notifySender();

    int shutdown();
    void notifyFinAck();
    void removeDispatcher(int sock);

    uint64_t               mFlowID;
protected:
    void getWindowSize();
    int getDeadlineFromProfile(DataProfile profile);

    void handleProbe(SCIONPacket *packet);
    SSPPacket * checkOutOfOrderQueue(SSPPacket *sp);
    void signalSelect();
    void handleInOrder(SSPPacket *sp, int pathIndex);
    void handleOutOfOrder(SSPPacket *sp, int pathIndex);
    void handleData(SSPPacket *packet, int pathIndex);
    void sendAck(SSPPacket *sip, int pathIndex, bool full=false);

    bool isFirstPacket();
    void didRead(L4Packet *packet);

    // path manager
    SSPConnectionManager *mConnectionManager;

    // initialization, connection establishment
    bool                   mInitialized;
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

    // recv'ing packets
    uint32_t                mTotalReceived;
    uint64_t                mNextPacket;
    OrderedList<SSPPacket *> *mReadyPackets;
    OrderedList<SSPPacket *> *mOOPackets;

    pthread_mutex_t        mSelectMutex;
    std::map<int, Notification> mSelectRead;
    std::map<int, Notification> mSelectWrite;
    int mSelectCount;
};

class SUDPProtocol : public SCIONProtocol {
public:
    SUDPProtocol(std::vector<SCIONAddr> &dstAddrs, short srcPort, short dstPort);
    ~SUDPProtocol();

    void createManager(std::vector<SCIONAddr> &dstAddrs, bool paths);

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
