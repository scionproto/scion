#include "generator.h"
#include <fstream>
#include <sstream>
#include <string>
#include <assert.h>
#include <arpa/inet.h>
#include <string>
#include <map>

using namespace std;


int main (void) {
    int ad_id, isd_id, isCore, registerPath, as1, as2, rel, nbrType1, port = 33000,
        nbrType2, ifId1, ifId2, nbrTd1, nbrTd2, nbrAd1, nbrAd2, numTDs;
    string line, ip_address = "127.0.0.1", tmp_ip_address = "127.0.0.1";
    ifstream asRel, asInfo;
    ofstream runNet, netIPs;
    map<int, SCIONScriptGen*> asList;

    //Write the SCION run script
    runNet.open("run.sh");
    runNet << "#!/bin/bash\n\n"
           << "cd ./infrastructure/\n";
    runNet.close();

    asInfo.open("ADToISD");
    while (getline(asInfo, line)) {
        istringstream iss(line);
        iss >> ad_id >> isd_id >> isCore;
        registerPath = (isCore==2 || isCore==0) ? 1 : 0;
        isCore = (isCore==0) ? 1 : 0;
        asList[ad_id-1] = new SCIONScriptGen(ad_id, isCore, isd_id, 1234567890, 1919191919, ip_address, registerPath);
        asList[ad_id-1]->GenerateAllConf (ip_address);
    }
    asInfo.close();

    asRel.open("ADRelationships");
    while (getline(asRel, line)) {
        istringstream iss(line);
        iss >> as1 >> as2 >> rel;
        ifId1 = 1;
        ifId2 = 1;
        nbrTd1 = 0;
        nbrTd2 = 0;
        nbrAd1 = as2;
        nbrAd2 = as1;

        if (rel == 0) {
            nbrType1 = PEER;
            nbrType2 = PEER;
        } else if (rel == -1) {
            nbrType1 = CHILD;
            nbrType2 = PARENT;
        } else if (rel == 1) {
            nbrType1 = ROUTING;
            nbrType2 = ROUTING;
            nbrTd1 = asList[as2-1]->GetISDId ();
            nbrTd2 = asList[as1-1]->GetISDId ();
        }

        Router rtr1(IPV4, ifId1, nbrTd1, nbrAd1, nbrType1, IPV4,
                    (const char*)(asList[as1-1]->GetIpAddress()).c_str(),
                    (const char*)(asList[as2-1]->GetIpAddress()).c_str(), port, port);
        asList[as1-1]->AddRouter(&rtr1, ip_address);
        Router rtr2(IPV4, ifId2, nbrTd2, nbrAd2, nbrType2, IPV4,
                    (const char*)(asList[as2-1]->GetIpAddress()).c_str(),
                    (const char*)(asList[as1-1]->GetIpAddress()).c_str(), port, port);
        asList[as2-1]->AddRouter(&rtr2, ip_address);
        port++;
    }
    asRel.close();

    for(map<int, SCIONScriptGen*>::iterator it = asList.begin(); it != asList.end(); it++) {
        delete it->second;
    }

    //Write the SCION setup script
    netIPs.open("setup.sh");
    netIPs << "#!/bin/bash\n\n";
    while (tmp_ip_address != ip_address) {
        netIPs << "ip addr add " << tmp_ip_address << "/8 " << "dev lo\n";
        tmp_ip_address = increment_address((const char*)tmp_ip_address.c_str());
    }
    netIPs.close();

    return 0;
}
