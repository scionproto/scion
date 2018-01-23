#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "scion.h"

static const uint8_t cookie[] = { 0xde, 0x00, 0xad, 0x01, 0xbe, 0x02, 0xef, 0x03 };

char addr_buf[MAX_HOST_ADDR_STR];

int validate_cookie(uint8_t *buf)
{
    return !memcmp(buf, cookie, DP_COOKIE_LEN);
}

void parse_dp_header(uint8_t *buf, uint8_t *addr_type, int *packet_len)
{
    if (!validate_cookie(buf)) {
        *packet_len = -1;
        return;
    }
    if (addr_type)
        *addr_type = buf[DP_COOKIE_LEN];
    *packet_len = ntohl(*(uint32_t *)(buf + DP_COOKIE_LEN + 1));
}

void write_dp_header(uint8_t *buf, HostAddr *host, int packet_len)
{
    int addr_len = ADDR_NONE_LEN;
    uint8_t addr_type = ADDR_NONE_TYPE;
    if (host) {
        addr_len = get_addr_len(host->addr_type);
        addr_type = host->addr_type;
    }
    memcpy(buf, cookie, DP_COOKIE_LEN);
    buf += DP_COOKIE_LEN;
    *buf++ = addr_type;
    *(uint32_t *)buf = htonl(packet_len);
    buf += 4;
    if (addr_len > 0) {
        memcpy(buf, host->addr, addr_len);
        buf += addr_len;
        *(uint16_t *)buf = htons(host->port);
    }
}

int send_dp_header(int sock, HostAddr *host, int packet_len)
{
    int addr_port_len = 0;
    if (host && host->addr_type != ADDR_NONE_TYPE)
        addr_port_len = get_addr_len(host->addr_type) + 2;
    uint8_t buf[DP_HEADER_LEN + addr_port_len];
    write_dp_header(buf, host, packet_len);
    int hdr_len = DP_HEADER_LEN + addr_port_len;
    int sent = send_all(sock, buf, hdr_len);
    if (hdr_len != sent)  {
        return -1;
    }
    return 0;
}

int recv_all(int sock, uint8_t *buf, int len)
{
    int recvd = 0;
    while (recvd < len) {
        errno = 0;
        int ret = recv(sock, buf + recvd, len - recvd, 0);
        if (ret < 0)
            return ret;
        if (ret == 0)
            return -1;
        recvd += ret;
    }
    return recvd;
}

int send_all(int sock, uint8_t *buf, int len)
{
    errno = 0;
    int sent = 0;
    while (sent < len) {
        errno = 0;
        int ret = send(sock, buf + sent, len - sent, 0);
        if (ret < 0)
            return ret;
        if (ret == 0)
            return -1;
        sent += ret;
    }
    return sent;
}

const char * addr_to_str(uint8_t *addr, uint8_t type, char *buf)
{
    char *str;
    if (buf)
        str = buf;
    else
        str = addr_buf;
    switch (type) {
        case ADDR_IPV4_TYPE:
            return inet_ntop(AF_INET, addr, str, MAX_HOST_ADDR_STR);
        case ADDR_IPV6_TYPE:
            return inet_ntop(AF_INET6, addr, str, MAX_HOST_ADDR_STR);
        case ADDR_SVC_TYPE:
            return svc_to_str(ntohs(*(uint16_t *)addr), str);
        default:
            snprintf(str, MAX_HOST_ADDR_STR, "Unknown type %d", type);
            return str;
    }
}

const char * svc_to_str(uint16_t svc, char *buf) {
    char *service;
    switch (svc & ~SVC_MULTICAST) {
        case SVC_BEACON:
            service = "BS";
            break;
        case SVC_PATH_MGMT:
            service = "PS";
            break;
        case SVC_CERT_MGMT:
            service = "CS";
            break;
        case SVC_SIBRA:
            service = "SB";
            break;
        default:
            snprintf(buf, MAX_HOST_ADDR_STR, "Unknown svc %d", svc);
            return buf;
    }
    snprintf(buf, MAX_HOST_ADDR_STR, "%s %c", service,
            svc & SVC_MULTICAST ? 'M' : 'A');
    return buf;
}

int family_to_type(int family)
{
    switch (family) {
        case AF_INET:
            return ADDR_IPV4_TYPE;
        case AF_INET6:
            return ADDR_IPV6_TYPE;
        default:
            return 0;
    }
}

int type_to_family(int type)
{
    switch (type) {
        case ADDR_IPV4_TYPE:
            return AF_INET;
        case ADDR_IPV6_TYPE:
            return AF_INET6;
        default:
            return 0;
    }
}

uint8_t * get_ss_addr(struct sockaddr_storage *ss)
{
    if (ss->ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)ss;
        return (uint8_t *)&sin->sin_addr;
    } else if (ss->ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
        return (uint8_t *)&sin6->sin6_addr;
    }
    return NULL;
}
