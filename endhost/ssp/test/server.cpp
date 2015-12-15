#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "SCIONSocket.h"

#define BUFSIZE 10240

void *sender(void *arg)
{
    printf("started sender thread\n");
    uint8_t buf[BUFSIZE];
    memset(buf, 0, BUFSIZE);
    SCIONSocket *sock = (SCIONSocket *)arg;
    int count = 0;
    while (1) {
        count++;
        sprintf((char *)buf, "This is message %d\n", count);
        sock->send(buf, BUFSIZE);
        printf("server sent message on sock %p\n", sock);
        usleep(50000);
    }
    return NULL;
}

void *receiver(void *arg)
{
    printf("started receiver thread\n");
    uint8_t buf[BUFSIZE];
    SCIONSocket *sock = (SCIONSocket *)arg;
    while (1) {
        sock->recv(buf, BUFSIZE, NULL);
        printf("server received message on sock %p\n", sock);
    }
    return NULL;
}

int main()
{
    SCIONSocket s(SCION_PROTO_SSP, NULL, 0, 8080, 0);
    while (1) {
        SCIONSocket *newSocket = s.accept();
        printf("accepted socket\n");

        pthread_t sendthread;
        pthread_t recvthread;
        pthread_create(&sendthread, NULL, sender, newSocket);
        pthread_create(&recvthread, NULL, receiver, newSocket);
    }

    exit(0);
}
