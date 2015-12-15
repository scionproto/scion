#include <pthread.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include "SCIONSocket.h"
#include <unistd.h>

#define BUFSIZE 10240

void *sender(void *arg)
{
    printf("start sender thread\n");
    uint8_t buf[BUFSIZE];
    memset(buf, 0, BUFSIZE);
    SCIONSocket *sock = (SCIONSocket *)arg;
    int count = 0;
    while (1) {
        count++;
        sprintf((char *)buf, "This is message %d\n", count);
        sock->send(buf, BUFSIZE);
        printf("client sent message on sock %p\n", sock);
        usleep(50000);
    }
    return NULL;
}

void *receiver(void *arg)
{
    printf("start receiver thread\n");
    uint8_t buf[BUFSIZE];
    SCIONSocket *sock = (SCIONSocket *)arg;
    while (1) {
        sock->recv(buf, BUFSIZE, NULL);
        printf("client received message on sock %p\n", sock);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    SCIONAddr addrs[1];
    SCIONAddr saddr;
    int isd, ad;
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
    pthread_t sendthread;
    pthread_t recvthread;
    SCIONSocket *s;
    for (int i = 0; i < 10; i++) {
        printf("client will create new socket\n");
        s = new SCIONSocket(SCION_PROTO_SSP, addrs, 1, 0, 8080);

        pthread_create(&sendthread, NULL, sender, s);
        pthread_create(&recvthread, NULL, receiver, s);
    }
    pthread_join(sendthread, NULL);
    pthread_join(recvthread, NULL);
    exit(0);
}
