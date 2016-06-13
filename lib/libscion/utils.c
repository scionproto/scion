#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "scion.h"

static const uint8_t cookie[] = { 0xde, 0x00, 0xad, 0x01, 0xbe, 0x02, 0xef, 0x03 };

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
    *packet_len = *(uint32_t *)(buf + DP_COOKIE_LEN + 1);
}

void write_dp_header(uint8_t *buf, HostAddr *host, int packet_len)
{
    int addr_len = 0;
    uint8_t addr_type = 0;
    if (host) {
        addr_len = get_addr_len(host->addr_type);
        addr_type = host->addr_type;
    }
    memcpy(buf, cookie, DP_COOKIE_LEN);
    buf += DP_COOKIE_LEN;
    *buf++ = addr_type;
    *(uint32_t *)buf = packet_len;
    buf += 4;
    if (addr_len > 0) {
        memcpy(buf, host->addr, addr_len);
        buf += addr_len;
        *(uint16_t *)buf = host->port;
    }
}

int send_dp_header(int sock, HostAddr *host, int packet_len)
{
    int addr_port_len = 0;
    if (host && host->addr_type != 0)
        addr_port_len = get_addr_len(host->addr_type) + 2;
    uint8_t buf[DP_HEADER_LEN + addr_port_len];
    write_dp_header(buf, host, packet_len);
    return send_all(sock, buf, DP_HEADER_LEN + addr_port_len);
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
