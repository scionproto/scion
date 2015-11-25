#ifndef SCION_SOCKET_H
#define SCION_SOCKET_H

#include <pthread.h>
#include <sys/types.h>

#include "SCIONDefines.h"
#include "DataStructures.h"
#include "SCIONProtocol.h"
#include "Utils.h"

class SCIONSocket {
public:
    SCIONSocket(int protocol, SCIONAddr *dstAddrs, int numAddrs, short srcPort, short dstPort);
    SCIONSocket(const SCIONSocket &s);
    ~SCIONSocket();

    SCIONSocket & operator=(const SCIONSocket &s);

    // traditional socket functionality
    SCIONSocket & accept();
    int send(uint8_t *buf, size_t len);
    int send(uint8_t *buf, size_t len, DataProfile profile);
    int recv(uint8_t *buf, size_t len, SCIONAddr *srcAddr);

    // construct SCION packet from incoming data
    void handlePacket(uint8_t *buf, size_t len, struct sockaddr_in *addr);

    // data profile: VoIP, streaming video, etc
    void setDataProfile(DataProfile profile);

    // getters
    bool isListener();
    bool isRunning();
    void waitForRegistration();
    int getDispatcherSocket();

    SCIONStats * getStats();

private:

    uint16_t                   mSrcPort;
    uint16_t                   mDstPort;
    int                        mProtocolID;
    int                        mDispatcherSocket;
    bool                       mRegistered;
    bool                       mRunning;

    SCIONProtocol             *mProtocol;
    std::vector<SCIONAddr>     mDstAddrs;
    std::vector<SCIONSocket *> mAcceptedSockets;
    DataProfile                mDataProfile;
    pthread_mutex_t            mAcceptMutex;
    pthread_cond_t             mAcceptCond;
    pthread_mutex_t            mRegisterMutex;
    pthread_cond_t             mRegisterCond;
    pthread_t                  mReceiverThread;
};

#endif // SCION_SOCKET_H
