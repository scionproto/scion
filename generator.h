#include <stdint.h>
#include <cstring>
#include <string>
#include <arpa/inet.h>
using namespace std;

enum AddrType {IPV4=0, IPV6, NS3};
enum NbrType {PARENT=0, PEER, CHILD, ROUTING};

char* increment_address(const char* address_string);

struct Router {
  Router (int paddrType1, int pifid, int pnbrTdAid, int pnbrAdAid, int pnbrType,
          int paddrType2, const char *pextAddr, const char *pextToAddr,
          int pextUdpPort, int pextToUdpPort)
    : ifid (pifid),
      nbrTdAid (pnbrTdAid),
      nbrAdAid (pnbrAdAid),
      extUdpPort (pextUdpPort),
      extToUdpPort (pextToUdpPort) {
    switch (paddrType1) {
      case IPV4:
        strcpy(type, "IPv4");
        break;
      case IPV6:
        strcpy(type, "IPv6");
        break;
      case NS3:
        strcpy(type, "Direct");
        break;
      default:
        break;
    }
    switch(paddrType2) {
      case IPV4:
        strcpy(extAddrType, "IPv4");
        break;
      case IPV6:
        strcpy(extAddrType, "IPv6");
        break;
      case NS3:
        strcpy(extAddrType, "Direct");
        break;
      default:
        break;
    }
    switch(pnbrType) {
      case PARENT:
        strcpy(nbrType, "PARENT");
        break;
      case PEER:
        strcpy(nbrType, "PEER");
        break;
      case CHILD:
        strcpy(nbrType, "CHILD");
        break;
      case ROUTING:
        strcpy(nbrType, "ROUTING");
        break;
      default:
        break;
    }
    strcpy(extAddr, pextAddr);
    strcpy(extToAddr, pextToAddr);
  }

  char type[10], nbrType[10], extAddrType[10], extAddr[INET_ADDRSTRLEN],
       extToAddr[INET_ADDRSTRLEN];
  int ifid, extUdpPort, extToUdpPort, nbrTdAid, nbrAdAid;
};

class SCIONScriptGen {

    public:
        SCIONScriptGen (int ad_id, int core, int isd_id, int masterOFGKey,
                        int masterADKey, string &ip_address, int registerPath=0,
                        int pcbQueuSize=10, int psQueueSize=10,
                        int numRegisterPaths=10, int numShortestUPs=3,
                        double registerTime=5, double propagateTime=5,
                        double resetTime=600);
        ~SCIONScriptGen();
        void GenerateAllConf (string &ip_address);
        void AddRouter (const Router *rtr, string &ip_address);
        int GetISDId () const;
        string GetIpAddress () const;

    private:
        void GenerateADConf (const char *fileName) const;
        void GenerateTopologyXml (string &ip_address);

        int m_isd_id, m_registerPath, m_ifId, m_core, m_pcbQueueSize,
            m_psQueueSize, m_numRegisteredPaths, m_numShortestUPs, m_ad_id,
            m_aid, m_beaconServerAid, m_masterOFGKey, m_masterADKey;
        double m_registerTime, m_propagateTime, m_resetTime;
        char m_topoXmlName[100];
        string m_privKeyFile, m_certFile, m_topoFile, m_confFile, m_dirPrefix,
               m_ip_address;
};
