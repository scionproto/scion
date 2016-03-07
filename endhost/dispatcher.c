#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/types.h>
#include <unistd.h>

#include "libscion_api.h"
#include "SCIONDefines.h"
#include "uthash.h"

#define APP_BUFSIZE 16
#define DATA_BUFSIZE 65535

typedef struct sockaddr_in sockaddr_in;

typedef struct {
    uint16_t port;
    uint32_t host;
    uint64_t flow_id;
} SSPKey;

typedef struct Entry {
    sockaddr_in addr;
    sockaddr_in udp_key;
    SSPKey ssp_key;
    UT_hash_handle hh;
} Entry;

Entry *SSPFlows = NULL;
Entry *SSPWildcards = NULL;
Entry *UDPPorts = NULL;

static int data_socket;
static int app_socket;

int create_sockets();

void handle_app();
void register_ssp(char *buf, int len, sockaddr_in *addr);
void register_udp(char *buf, int len, sockaddr_in *addr);
Entry * parse_request(char *buf, int proto, sockaddr_in *addr);
void reply(char code, sockaddr_in *addr);

void handle_data();
int is_known_proto(uint8_t type);
uint8_t get_l4_proto(uint8_t **l4ptr);
void deliver_ssp(uint8_t *buf, uint8_t *l4ptr, int len, sockaddr_in *addr);
void deliver_udp(uint8_t *buf, int len, sockaddr_in *from, sockaddr_in *key);

int main(int argc, char **argv)
{
    int res;

    if (create_sockets() < 0)
        return -1;

    fd_set fds;
    FD_ZERO(&fds);
    while (1) {
        int max = data_socket > app_socket ? data_socket : app_socket;
        FD_SET(data_socket, &fds);
        FD_SET(app_socket, &fds);
        res = select(max + 1, &fds, NULL, NULL, NULL);
        if (res < 0) {
            fprintf(stderr, "select error: %s\n", strerror(errno));
            break;
        }

        if (FD_ISSET(app_socket, &fds)) {
            FD_CLR(app_socket, &fds);
            handle_app();
        }
        if (FD_ISSET(data_socket, &fds)) {
            FD_CLR(data_socket, &fds);
            handle_data();
        }
    }

    close(data_socket);
    close(app_socket);
    return res;
}

int create_sockets()
{
    int res;
    data_socket = socket(PF_INET, SOCK_DGRAM, 0);
    app_socket = socket(PF_INET, SOCK_DGRAM, 0);
    if (data_socket < 0 || app_socket < 0) {
        fprintf(stderr, "failed to open sockets\n");
        return -1;
    }
    int optval = 1;
    res = setsockopt(data_socket, SOL_SOCKET, SO_REUSEADDR,
            &optval, sizeof(optval));
    res |= setsockopt(app_socket, SOL_SOCKET, SO_REUSEADDR,
            &optval, sizeof(optval));
    if (res < 0) {
        fprintf(stderr, "failed to set addr resuse option\n");
        return -1;
    }
    /* Bind data socket to SCION_UDP_EH_DATA_PORT */
    sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(SCION_UDP_EH_DATA_PORT);
    res = bind(data_socket, (struct sockaddr *)&sa, sizeof(sa));
    if (res < 0) {
        fprintf(stderr, "failed to bind data socket to %s:%d\n",
                inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
        return -1;
    }
    optval = 1 << 20;
    setsockopt(data_socket, SOL_SOCKET, SO_RCVBUF, &optval, sizeof(optval));
    fprintf(stderr, "data socket bound to %s:%d\n", inet_ntoa(sa.sin_addr), SCION_UDP_EH_DATA_PORT);

    /* Bind app socket to SCION_DISPATCHER_PORT */
    sa.sin_port = htons(SCION_DISPATCHER_PORT);
    sa.sin_addr.s_addr = inet_addr(SCION_DISPATCHER_HOST);
    res = bind(app_socket, (struct sockaddr *)&sa, sizeof(sa));
    if (res < 0) {
        fprintf(stderr, "failed to bind app socket to %s:%d\n",
                inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
        return -1;
    }
    fprintf(stderr, "app socket bound to %s:%d\n", inet_ntoa(sa.sin_addr), SCION_DISPATCHER_PORT);
    return 0;
}

void handle_app()
{
    sockaddr_in addr;
    socklen_t addrLen = sizeof(addr);
    char buf[APP_BUFSIZE];
    int len = recvfrom(app_socket, buf, APP_BUFSIZE, 0,
            (struct sockaddr *)&addr, &addrLen);
    if (len > 2) { /* command (1B) | proto (1B) | id */
        unsigned char protocol = buf[1];
        fprintf(stderr, "received registration for proto: %d\n", protocol);
        switch (protocol) {
            case SCION_PROTO_SSP:
                register_ssp(buf, len, &addr);
                break;
            case SCION_PROTO_UDP:
                register_udp(buf, len, &addr);
                break;
        }
    }
}

void register_ssp(char *buf, int len, sockaddr_in *addr)
{
    if (len != 16) {
        fprintf(stderr, "invalid SSP registration\n");
        reply(0, addr);
        return;
    }
    fprintf(stderr, "SSP registration request\n");
    /* command (1B) | proto (1B) | flow_ID (8B) | port (2B) | addr (4B) */
    uint8_t reg = *buf; /* 0 = unregister, 1 = register */
    Entry *e = parse_request(buf, SCION_PROTO_SSP, addr);
    if (!e)
        return;
    Entry *old = NULL;
    if (e->ssp_key.flow_id != 0) {
        /* Find registered flow ID */
        HASH_FIND(hh, SSPFlows, &e->ssp_key, sizeof(SSPKey), old);
        if (old) {
            /* Delete obsolete entry - this also serves as unregister */
            HASH_DELETE(hh, SSPFlows, old);
            free(old);
            fprintf(stderr, "entry for flow %lu deleted\n", e->ssp_key.flow_id);
        }
        /* If command is "register", add new entry */
        if (reg) {
            HASH_ADD(hh, SSPFlows, ssp_key, sizeof(SSPKey), e);
            fprintf(stderr, "flow registration success: %p\n", SSPFlows);
        }
    } else {
        /* Find registered wildcard port */
        HASH_FIND(hh, SSPWildcards, &e->ssp_key, sizeof(SSPKey), old);
        if (old) {
            /* Delete obsolete entry - this also serves as unregister */
            HASH_DELETE(hh, SSPWildcards, old);
            free(old);
            fprintf(stderr, "entry for port %d deleted\n", e->ssp_key.port);
        }
        /* If command is "register", add new entry */
        if (reg) {
            HASH_ADD(hh, SSPWildcards, ssp_key, sizeof(SSPKey), e);
            fprintf(stderr, "wildcard registration success: %p\n", SSPWildcards);
        }
    }
    reply(1, addr);
}

void register_udp(char *buf, int len, sockaddr_in *addr)
{
    if (len != 8) {
        fprintf(stderr, "invalid UDP registration\n");
        reply(0, addr);
        return;
    }
    fprintf(stderr, "UDP registration request\n");

    /* command (1B) | proto (1B) | port (2B) | addr (4B) */
    uint8_t reg = *buf; /* 0 = unregister, 1 = register */
    Entry *e = parse_request(buf, SCION_PROTO_UDP, addr);
    if (!e)
        return;
    Entry *old = NULL;
    HASH_FIND(hh, UDPPorts, &e->udp_key, sizeof(sockaddr_in), old);
    if (old) {
        /* Delete obsolete entry - this also serves as unregister */
        HASH_DELETE(hh, UDPPorts, old);
        free(old);
    }
    /* If command is "register", add new entry */
    if (reg)
        HASH_ADD(hh, UDPPorts, udp_key, sizeof(sockaddr_in), e);
    fprintf(stderr, "registered for (%s:%d)\n",
            inet_ntoa(e->udp_key.sin_addr), e->udp_key.sin_port);
    reply(1, addr);
}

Entry * parse_request(char *buf, int proto, sockaddr_in *addr)
{
    uint16_t port = *(uint16_t *)(buf + 2);
    uint64_t flow_id;
    uint32_t host;
    if (proto == SCION_PROTO_SSP) {
        flow_id = *(uint64_t *)(buf + 4);
        host = *(uint32_t *)(buf + 12);
    } else if (proto == SCION_PROTO_UDP) {
        host = *(uint32_t *)(buf + 4);
    }

    Entry *e = (Entry *)malloc(sizeof(Entry));
    if (!e)
        return NULL;
    memset(e, 0, sizeof(Entry));
    e->addr = *addr;
    if (proto == SCION_PROTO_SSP) {
        e->ssp_key.flow_id = flow_id;
        e->ssp_key.port = port;
        e->ssp_key.host = host;
    } else if (proto == SCION_PROTO_UDP) {
        e->udp_key.sin_family = AF_INET;
        e->udp_key.sin_addr.s_addr = host;
        e->udp_key.sin_port = port;
    }
    return e;
}

void reply(char code, sockaddr_in *addr)
{
    sendto(app_socket, &code, 1, 0, (struct sockaddr *)addr, sizeof(*addr));
}

void handle_data()
{
    sockaddr_in from;
    socklen_t addrLen = sizeof(from);
    uint8_t buf[DATA_BUFSIZE];
    int len = recvfrom(data_socket, buf, DATA_BUFSIZE, 0,
            (struct sockaddr *)&from, &addrLen);
    if (len < 0) {
        fprintf(stderr, "error on recvfrom: %s\n", strerror(errno));
        return;
    }
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    if (sch->headerLen > DATA_BUFSIZE ||
            ntohs(sch->totalLen) > DATA_BUFSIZE) {
        fprintf(stderr, "invalid SCION packet\n");
        return;
    }
    uint8_t *l4ptr = (uint8_t *)buf;
    uint8_t l4 = get_l4_proto(&l4ptr);
    sockaddr_in key;
    switch (l4) {
        case SCION_PROTO_SSP:
            deliver_ssp(buf, l4ptr, len, &from);
            break;
        case SCION_PROTO_UDP:
            memset(&key, 0, sizeof(key));
            key.sin_family = AF_INET;
            /* Find dst info in packet */
            key.sin_port = htons(*(uint16_t *)(l4ptr + 2));
            key.sin_addr.s_addr = *(uint32_t *)(get_dst_addr(buf));
            deliver_udp(buf, len, &from, &key);
            break;
    }
}

void deliver_ssp(uint8_t *buf, uint8_t *l4ptr, int len, sockaddr_in *addr)
{
    Entry *e;
    SSPKey key;
    memset(&key, 0, sizeof(key));
    key.flow_id = be64toh(*(uint64_t *)l4ptr);
    key.port = 0;
    key.host = *(uint32_t *)get_dst_addr(buf);
    HASH_FIND(hh, SSPFlows, &key, sizeof(key), e);
    if (!e) {
        key.flow_id = 0;
        key.port = ntohs(*(uint16_t *)(l4ptr + 8));
        HASH_FIND(hh, SSPWildcards, &key, sizeof(key), e);
        if (!e) {
            fprintf(stderr, "no entry found\n");
            return;
        }
    }
    socklen_t addrLen = sizeof(sockaddr_in);
    /* Append real first hop sender addr to end of message (needed by socket) */
    memcpy(buf + len, addr, addrLen);
    sendto(app_socket, buf, len + addrLen, 0,
            (struct sockaddr *)&e->addr, addrLen);
}

void deliver_udp(uint8_t *buf, int len, sockaddr_in *from, sockaddr_in *key)
{
    Entry *e;
    HASH_FIND(hh, UDPPorts, key, sizeof(*key), e);
    if (!e)
        return;
    socklen_t addrLen = sizeof(sockaddr_in);
    /* Append real first hop sender addr to end of message (needed by socket) */
    memcpy(buf + len, from, addrLen);
    sendto(app_socket, buf, len + addrLen, 0,
            (struct sockaddr *)&e->addr, addrLen);
}
