#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>

#include "SCIONDefines.h"
#include "uthash.h"

#define APP_BUFSIZE 16
#define DATA_BUFSIZE 2048
#define NAME_MAX 32

uint8_t L4PROTOCOLS[] = {1, 6, SCION_PROTO_UDP, SCION_PROTO_SSP};

typedef struct Entry {
    struct sockaddr_in addr;
    uint64_t flowID;
    uint16_t port;
    UT_hash_handle hh;
} Entry;

Entry *SSPFlows = NULL;
Entry *SSPWildcards = NULL;
Entry *UDPPorts = NULL;

int dataSocket, appSocket;

void reply(char code, struct sockaddr_in *addr)
{
    sendto(appSocket, &code, 1, 0, (struct sockaddr *)addr, sizeof(*addr));
}

void registerSSP(char *buf, int len, struct sockaddr_in *addr)
{
    if (len != 12) {
        fprintf(stderr, "invalid SSP registration\n");
        reply(0, addr);
        return;
    }
    printf("SSP registration request\n");
    uint8_t reg = *buf;
    uint64_t flowID = *(uint64_t *)(buf + 2);
    uint16_t port = *(uint16_t *)(buf + 10);
    printf("flow = %lu, port = %d\n", flowID, port);
    Entry *e, *old;
    e = (Entry *)malloc(sizeof(Entry));
    e->addr = *addr;
    e->flowID = flowID;
    e->port = port;
    if (flowID != 0) {
        HASH_FIND(hh, SSPFlows, &flowID, 8, old);
        if (old) {
            HASH_DELETE(hh, SSPFlows, old);
            printf("entry for flow %lu deleted\n", flowID);
        }
        if (reg)
            HASH_ADD(hh, SSPFlows, flowID, 8, e);
    } else {
        HASH_FIND(hh, SSPWildcards, &flowID, 8, old);
        if (old) {
            HASH_DELETE(hh, SSPWildcards, old);
            printf("wildcard entry for port %d deleted\n", port);
        }
        if (reg)
            HASH_ADD(hh, SSPWildcards, port, 2, e);
    }
    printf("registration success\n");
    reply(1, addr);
}

void registerUDP(char *buf, int len, struct sockaddr_in *addr)
{
    if (len != 4) {
        fprintf(stderr, "invalid UDP registration\n");
        reply(0, addr);
        return;
    }
    printf("UDP registration request\n");
    uint16_t port = *(uint16_t *)(buf + 1);
    Entry *e, *old;
    e = (Entry *)malloc(sizeof(Entry));
    e->addr = *addr;
    e->port = port;
    HASH_REPLACE(hh, UDPPorts, port, 2, e, old);
    printf("registration success\n");
    reply(1, addr);
}

void * appHandler(void *arg)
{
    while (1) {
        struct sockaddr_in addr;
        socklen_t addrLen = sizeof(addr);
        char buf[APP_BUFSIZE];
        int len = recvfrom(appSocket, buf, APP_BUFSIZE, 0,
                (struct sockaddr *)&addr, &addrLen);
        if (len > 2) { /* command (1B) | proto (1B) | id */
            unsigned char protocol = buf[1];
            printf("received registration for proto: %d\n", protocol);
            switch (protocol) {
                case SCION_PROTO_SSP:
                    registerSSP(buf, len, &addr);
                    break;
                case SCION_PROTO_UDP:
                    registerUDP(buf, len, &addr);
                    break;
            }
        }
    }
    return NULL;
}

int isKnownProtocol(uint8_t type)
{
    size_t i;
    for (i = 0; i < sizeof(L4PROTOCOLS); i++) {
        if (L4PROTOCOLS[i] == type)
            return 1;
    }
    return 0;
}

uint8_t getL4Protocol(uint8_t **l4ptr)
{
    uint8_t *ptr = *l4ptr;
    SCIONCommonHeader *sch = (SCIONCommonHeader *)ptr;
    uint8_t currentHeader = sch->nextHeader;
    ptr += sch->headerLen;
    while (!isKnownProtocol(currentHeader)) {
        currentHeader = *ptr;
        uint8_t nextLen = *(ptr + 1);
        nextLen = (nextLen + 1) * 8;
        ptr += nextLen;
    }
    *l4ptr = ptr;
    return currentHeader;
}

void deliverSSP(char *buf, uint8_t *l4ptr, int len, struct sockaddr_in *addr)
{
    Entry *e;
    uint64_t flowID = be64toh(*(uint64_t *)l4ptr);
    uint16_t port = ntohs(*(uint16_t *)(l4ptr + 8));
    HASH_FIND(hh, SSPFlows, &flowID, 8, e);
    if (!e) {
        HASH_FIND(hh, SSPWildcards, &port, 2, e);
        if (!e)
            return;
    }
    socklen_t addrLen = sizeof(struct sockaddr_in);
    memcpy(buf + len, addr, addrLen);
    sendto(appSocket, buf, len + addrLen, 0,
            (struct sockaddr *)&e->addr, addrLen);
}

void deliverUDP(char *buf, uint8_t *l4ptr, int len, struct sockaddr_in *addr)
{
    Entry *e;
    uint16_t port = ntohs(*(uint16_t *)(l4ptr + 2));
    HASH_FIND(hh, UDPPorts, &port, 2, e);
    if (!e)
        return;
    socklen_t addrLen = sizeof(struct sockaddr_in);
    memcpy(buf + len, addr, addrLen);
    sendto(appSocket, buf, len + addrLen, 0,
            (struct sockaddr *)&e->addr, addrLen);;
}

void * dataHandler(void *arg)
{
    while (1) {
        struct sockaddr_in addr;
        socklen_t addrLen = sizeof(addr);
        char buf[DATA_BUFSIZE];
        int len = recvfrom(dataSocket, buf, DATA_BUFSIZE, 0,
                (struct sockaddr *)&addr, &addrLen);
        if (len > 0) {
            SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
            if (sch->headerLen > DATA_BUFSIZE ||
                    ntohs(sch->totalLen) > DATA_BUFSIZE) {
                fprintf(stderr, "invalid SCION packet\n");
                continue;
            }
            uint8_t *l4ptr = (uint8_t *)buf;
            uint8_t l4 = getL4Protocol(&l4ptr);
            switch (l4) {
                case SCION_PROTO_SSP:
                    deliverSSP(buf, l4ptr, len, &addr);
                    break;
                case SCION_PROTO_UDP:
                    deliverUDP(buf, l4ptr, len, &addr);
                    break;
            }
        }
    }

    return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s host_addresss\n", argv[0]);
        return 1;
    }

    int res;
    int optval = 1;

    dataSocket = socket(PF_INET, SOCK_DGRAM, 0);
    if (dataSocket < 0) {
        fprintf(stderr, "failed to open data socket\n");
        return 1;
    }
	res = setsockopt(dataSocket, SOL_SOCKET, SO_REUSEADDR,
					 &optval, sizeof(optval));
    if (res < 0) {
        fprintf(stderr, "failed to set reuse option\n");
        return 1;
    }
    struct sockaddr_in dataAddr;
    memset(&dataAddr, 0, sizeof(dataAddr));
    dataAddr.sin_addr.s_addr = inet_addr(argv[1]);
    dataAddr.sin_port = htons(SCION_UDP_EH_DATA_PORT);
    dataAddr.sin_family = AF_INET;
    res = bind(dataSocket, (struct sockaddr *)&dataAddr, sizeof(dataAddr));
    if (res < 0) {
        fprintf(stderr, "failed to bind data socket: %s\n", strerror(errno));
        return 1;
    }
    printf("data socket bound to %s:%d\n", argv[1], SCION_UDP_EH_DATA_PORT);

    appSocket = socket(PF_INET, SOCK_DGRAM, 0);
    if (appSocket < 0) {
        fprintf(stderr,
                "failed to open application socket: %s\n", strerror(errno));
        return 1;
    }
	res = setsockopt(appSocket, SOL_SOCKET, SO_REUSEADDR,
					 &optval, sizeof(optval));
    if (res < 0) {
        fprintf(stderr, "failed to set reuse option\n");
        return 1;
    }
    struct sockaddr_in appAddr;
    memset(&appAddr, 0, sizeof(appAddr));
    appAddr.sin_family = AF_INET;
    appAddr.sin_port = htons(SCIOND_DISPATCHER_PORT);
    appAddr.sin_addr.s_addr = inet_addr(SCION_DISPATCHER_HOST);
    res = bind(appSocket, (struct sockaddr *)&appAddr, sizeof(appAddr));
    if (res < 0) {
        fprintf(stderr,
                "failed to bind application socket to %s:%d -  %s\n",
                SCION_DISPATCHER_HOST, SCIOND_DISPATCHER_PORT, strerror(errno));
        return 1;
    }
    printf("application socket bound to %s:%d\n",
            SCION_DISPATCHER_HOST, SCIOND_DISPATCHER_PORT);

    pthread_t appThread, dataThread;
    pthread_create(&appThread, NULL, appHandler, NULL);
    pthread_create(&dataThread, NULL, dataHandler, NULL);
    pthread_join(appThread, NULL);
    pthread_join(dataThread, NULL);
    return 0;
}
