#include "generator.h"
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <cstring>
#include <fstream>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

using namespace std;


// NOTE: only works for IPv4.  Check out inet_pton/inet_ntop for IPv6 support.
char* increment_address(const char* address_string) {
    // convert the input IP address to an integer
    in_addr_t address = inet_addr(address_string);

    // add one to the value (making sure to get the correct byte orders)
    address = ntohl(address);
    address += 1;
    address = htonl(address);

    // pack the address into the struct inet_ntoa expects
    struct in_addr address_struct;
    address_struct.s_addr = address;

    // convert back to a string
    return inet_ntoa(address_struct);
}


SCIONScriptGen::SCIONScriptGen (int adAid, int core, int tdId,
              int masterOFGKey, int masterADKey, string &ip_address, int registerPath,
              int pcbQueueSize, int psQueueSize, int numRegisterPaths,
              int numShortestUPs, double registerTime, double propagateTime,
              double resetTime)
  : m_adAid (adAid),
    m_core (core),
    m_tdId (tdId),
    m_masterOFGKey (masterOFGKey),
    m_masterADKey (masterADKey),
    m_pcbQueueSize  (pcbQueueSize),
    m_psQueueSize  (psQueueSize),
    m_numRegisteredPaths (numRegisterPaths),
    m_numShortestUPs (numShortestUPs),
    m_registerTime (registerTime),
    m_propagateTime  (propagateTime), 
    m_resetTime (resetTime), 
    m_registerPath (registerPath),
    m_ifId (0) {

    m_ip_address = ip_address;
    ip_address = increment_address((const char*)ip_address.c_str());

    string temp="/td";

    char tempBuf[100];
    m_dirPrefix="TD";
    sprintf(tempBuf, "%d", m_tdId);
    m_dirPrefix.append(tempBuf);

    temp.append(tempBuf);
    temp.append("-ad");

    mkdir(m_dirPrefix.c_str(), S_IRWXU|S_IRGRP|S_IXGRP);

    temp.append(tempBuf);
    temp.append("-0.");

    m_topoFile = m_dirPrefix;
    m_topoFile.append("/topologies");

    m_confFile = m_dirPrefix;
    m_confFile.append("/configurations");
}


void SCIONScriptGen::GenerateAllConf (string &ip_address) {
    char temp[100];
    int prefixLen = m_dirPrefix.length();
    memcpy (temp, m_dirPrefix.c_str(), prefixLen);

    sprintf(temp+prefixLen, "/topologies/topology%i.xml", m_adAid);
    strcpy (m_topoXmlName, temp);
    GenerateTopologyXml(ip_address);

    sprintf(temp+prefixLen, "/configurations/AD%i.conf", m_adAid);
    GenerateADConf(temp);    
}

void SCIONScriptGen::GenerateADConf (const char *fileName) const {
    ofstream myfile;
    myfile.open(fileName);
    myfile << "MasterOFGKey " << m_masterOFGKey << "\n";
    myfile << "MasterADKey " << m_masterADKey << "\n";
    myfile << "PCBQueueSize " << m_pcbQueueSize << "\n";
    myfile << "PSQueueSize " << m_psQueueSize << "\n";
    myfile << "NumRegisteredPaths " << m_numRegisteredPaths << "\n";
    myfile << "NumShortestUPs " << m_numShortestUPs << "\n";
    myfile << "RegisterTime " << m_registerTime << "\n";
    myfile << "PropagateTime " << m_propagateTime << "\n";
    myfile << "ResetTime " << m_resetTime << "\n";
    myfile << "RegisterPath " << m_registerPath << "\n";
    myfile.close();
}

SCIONScriptGen::~SCIONScriptGen () {
    ofstream myfile;
    myfile.open(m_topoXmlName, std::ofstream::out | std::ofstream::app);
    myfile << "\t</BorderRouters>\n";
    myfile << "</Topology>\n";
    myfile.close();
}

void SCIONScriptGen::AddRouter (const Router *rtr, string &ip_address) {

    ofstream myfile;
    myfile.open (m_topoXmlName, std::ofstream::out | std::ofstream::app);
    myfile << "\t\t<Router>\n";
    myfile << "\t\t\t<AddrType>" << rtr->type << "</AddrType>\n";
    myfile << "\t\t\t<Addr>" << ip_address << "</Addr>\n";
    myfile << "\t\t\t<Interface>\n";
    myfile << "\t\t\t\t<IFID>" << ++m_ifId << "</IFID>\n";
    if (rtr->nbrTdAid) {
        myfile << "\t\t\t\t<NeighborTD>" << rtr->nbrTdAid << "</NeighborTD>\n";
    }
    myfile << "\t\t\t\t<NeighborAD>" << rtr->nbrAdAid<< "</NeighborAD>\n";
    myfile << "\t\t\t\t<NeighborType>" << rtr->nbrType<< "</NeighborType>\n";
    myfile << "\t\t\t\t<AddrType>" << rtr->extAddrType << "</AddrType>\n";
    myfile << "\t\t\t\t<Addr>" << rtr->extAddr << "</Addr>\n";
    myfile << "\t\t\t\t<ToAddr>" << rtr->extToAddr << "</ToAddr>\n";
    myfile << "\t\t\t\t<UdpPort>" << rtr->extUdpPort << "</UdpPort>\n";
    myfile << "\t\t\t\t<ToUdpPort>" << rtr->extToUdpPort << "</ToUdpPort>\n";
    myfile << "\t\t\t</Interface>\n";
    myfile << "\t\t</Router>\n";
    myfile.close();

    myfile.open ("run.sh", std::ofstream::out | std::ofstream::app);
    myfile << "screen -d -m -S r" << m_adAid << "r" << rtr->nbrAdAid << " sh -c \""
           << "PYTHONPATH=../ python3 router.py " << ip_address << " "
           << "../TD" << m_tdId << "/topologies/topology" << m_adAid << ".xml "
           << "../TD" << m_tdId << "/configurations/AD" << m_adAid << ".conf\"\n";
    myfile.close();

  ip_address = increment_address((const char*)ip_address.c_str());
}


void SCIONScriptGen::GenerateTopologyXml (string &ip_address) {

    ofstream myfile, netRun;
    myfile.open(m_topoXmlName, std::ofstream::out | std::ofstream::app);
    myfile << "<?xml version=\"1.0\" ?>\n";
    myfile << "<Topology>\n";
    myfile << "\t<Core>" << m_core << "</Core>\n";
    myfile << "\t<TDID>" << m_tdId << "</TDID>\n";
    myfile << "\t<ADAID>" << m_adAid << "</ADAID>\n";
    myfile << "\t<Servers>\n";
    myfile << "\t\t<BeaconServer>\n";
    myfile << "\t\t\t<AddrType>IPv4</AddrType>\n";
    myfile << "\t\t\t<Addr>" << ip_address << "</Addr>\n"; 
    myfile << "\t\t</BeaconServer>\n";

    netRun.open ("run.sh", std::ofstream::out | std::ofstream::app);
    netRun << "screen -d -m -S bs" << m_adAid << " sh -c \""
           << "PYTHONPATH=../ python3 beacon_server.py " << ip_address << " "
           << "../TD" << m_tdId << "/topologies/topology" << m_adAid << ".xml "
           << "../TD" << m_tdId << "/configurations/AD" << m_adAid << ".conf\"\n";

    ip_address = increment_address((const char*)ip_address.c_str());

    if (m_registerPath) {
        myfile << "\t\t<PathServer>\n";
        myfile << "\t\t\t<AddrType>IPv4</AddrType>\n";
        myfile << "\t\t\t<Addr>" << ip_address << "</Addr>\n";
        myfile << "\t\t</PathServer>\n";

        netRun << "screen -d -m -S ps" << m_adAid << " sh -c \""
               << "PYTHONPATH=../ python3 path_server.py " << ip_address << " "
               << "../TD" << m_tdId << "/topologies/topology" << m_adAid << ".xml "
               << "../TD" << m_tdId << "/configurations/AD" << m_adAid << ".conf\"\n";

        ip_address = increment_address((const char*)ip_address.c_str());    
    }

    myfile << "\t\t<CertificateServer>\n";
    myfile << "\t\t\t<AddrType>IPv4</AddrType>\n";
    myfile << "\t\t\t<Addr>"<< ip_address << "</Addr>\n";
    myfile << "\t\t</CertificateServer>\n";
    
    netRun << "screen -d -m -S cs" << m_adAid << " sh -c \""
           << "PYTHONPATH=../ python3 cert_server.py " << ip_address << " "
           << "../TD" << m_tdId << "/topologies/topology" << m_adAid << ".xml "
           << "../TD" << m_tdId << "/configurations/AD" << m_adAid << ".conf\"\n";
    
    ip_address = increment_address((const char*)ip_address.c_str());

    myfile << "\t</Servers>\n";
    myfile << "\t<BorderRouters>\n";
    myfile.close();
    netRun.close();
}


int SCIONScriptGen::GetTdId () const {
    return m_tdId;
}


string SCIONScriptGen::GetIpAddress () const {
    return m_ip_address;
}