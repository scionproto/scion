#include <arpa/inet.h>
#include <unistd.h>

#include "SCIONSocket.h"

#define BUFSIZE 102400

int main(int argc, char **argv)
{
    SCIONAddr addrs[1];
    SCIONAddr saddr;
    uint16_t isd;
    uint32_t ad;
    char str[20];
    if (argc == 3) {
        isd = atoi(argv[1]);
        ad = atoi(argv[2]);
    } else {
        isd = 2;
        ad = 26;
    }
    saddr.isd_ad = ISD_AD(isd, ad);
    saddr.host.addrLen = 4;
    sprintf(str, "127.%d.%d.254", isd, ad);
    printf("connect to (%d, %d):%s\n", isd, ad, str);
    in_addr_t in = inet_addr(str);
    memcpy(saddr.host.addr, &in, 4);
    addrs[0] = saddr;
    SCIONSocket s(SCION_PROTO_SSP, addrs, 1, 0, 8080);
    /*
    SCIONOption option;
    memset(&option, 0, sizeof(option));
    option.type = SCION_OPTION_STAY_ISD;
    option.val = 1;
    s.setSocketOption(&option);
    */
    int count = 0;
    char buf[BUFSIZE];
    memset(buf, 0, BUFSIZE);
    while (1) {
        count++;
        sprintf(buf, "This is message %d\n", count);
        s.send((uint8_t *)buf, BUFSIZE);
        //usleep(500000);
    }
    exit(0);
}
