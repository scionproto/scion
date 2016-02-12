#ifndef SCION_SOCKET_H
#define SCION_SOCKET_H

#include <pthread.h>
#include <sys/types.h>

#include <vector>

#include "SCIONDefines.h"
#include "DataStructures.h"
#include "SCIONProtocol.h"
#include "Utils.h"

class SCIONSocket {
public:
    SCIONSocket(int protocol, SCIONAddr *dstAddrs, int numAddrs, short srcPort, short dstPort);
    ~SCIONSocket();

    // traditional socket functionality
    SCIONSocket * accept();
    int send(uint8_t *buf, size_t len);
    int send(uint8_t *buf, size_t len, DataProfile profile);
    int recv(uint8_t *buf, size_t len, SCIONAddr *srcAddr);
    int setSocketOption(SCIONOption *option);
    int getSocketOption(SCIONOption *option);

    // construct SCION packet from incoming data
    void handlePacket(uint8_t *buf, size_t len, struct sockaddr_in *addr);

    // data profile: VoIP, streaming video, etc
    void setDataProfile(DataProfile profile);

    // getters
    bool isListener();
    bool isRunning();
    int getDispatcherSocket();
    bool bypassDispatcher();

    // wait for dispatcher registration
    void waitForRegistration();

    // select
    bool readyToRead();
    bool readyToWrite();
    int registerSelect(Notification *n, int mode);
    void deregisterSelect(int index);

    void * getStats(void *buf, int len);

    int shutdown();
    void removeChild(SCIONSocket *child);

private:
    bool checkChildren(SCIONPacket *packet, uint8_t *ptr);
    void signalSelect();

    uint16_t                   mSrcPort;
    uint16_t                   mDstPort;
    int                        mProtocolID;
    int                        mDispatcherSocket;
    bool                       mRegistered;
    SCIONState                 mState;
    int                        mLastAccept;

    SCIONSocket               *mParent;
    SCIONProtocol             *mProtocol;
    std::vector<SCIONAddr>     mDstAddrs;
    std::vector<SCIONSocket *> mAcceptedSockets;
    DataProfile                mDataProfile;
    pthread_mutex_t            mAcceptMutex;
    pthread_cond_t             mAcceptCond;
    pthread_mutex_t            mRegisterMutex;
    pthread_cond_t             mRegisterCond;
    pthread_t                  mReceiverThread;

    int                         mSelectCount;
    pthread_mutex_t             mSelectMutex;
    std::map<int, Notification> mSelectRead;
};

#endif // SCION_SOCKET_H
