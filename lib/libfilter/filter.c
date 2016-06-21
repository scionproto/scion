#define _GNU_SOURCE // required to get struct in6_pktinfo definition
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>

#include <zlog.h>

#include "filter.h"

#define DSTADDR(x) (((struct in_pktinfo *)CMSG_DATA(x))->ipi_addr)
#define DSTV6ADDR(x) (((struct in6_pktinfo *)CMSG_DATA(x))->ipi6_addr)

uint8_t zerobuf[MAX_HOST_ADDR_LEN] = { 0 };

int bind_filter_socket(FilterSocket *filter_socket);
void handle_filter(FilterSocket *filter_socket);
void set_filter(uint8_t *buf, FilterSocket *filter_socket);
uint8_t * set_scionaddr(SCIONAddr *addr, uint8_t *ptr, uint8_t *filter_level);
void print_filter_key(FilterKey *f, zlog_category_t *zc, const char *prefix);
void print_scionaddr(SCIONAddr *addr, zlog_category_t *zc, const char *prefix);
int blocked_at_send(FilterSocket *filter_socket, const SCIONAddr *src, const SCIONAddr *dst,
    const SCIONAddr *hop, uint8_t l4);
int l4_index(uint8_t l4);
void mask_scionaddr_at_level(SCIONAddr *src_m, const SCIONAddr *src, int level);
void construct_filter_key(FilterKey *f, const SCIONAddr *src, const SCIONAddr *dst,
    const SCIONAddr *hop, uint8_t on_egress, uint8_t is_end2end, uint8_t l4);
int blocked_at_deliver(FilterSocket *filter_socket, const SCIONAddr *src, const SCIONAddr *dst,
    const SCIONAddr *hop, uint8_t l4);

FilterSocket * init_filter_socket(zlog_category_t *zc)
{
    FilterSocket *filter_socket = (FilterSocket *)malloc(sizeof(FilterSocket));
    filter_socket->zc = zc;
    int i, j, k, l;
    for (i = 0; i < FILTER_LEVELS; i++) {
        for (j = 0; j < FILTER_LEVELS; j++) {
            for (k = 0; k < FILTER_LEVELS; k++) {
                for (l = 0; l < L4_PROTOCOL_COUNT; l++)
                filter_socket->filter_list[i][j][k][l] = NULL;
            }
        }
    }
    /* Create the filter socket */
    filter_socket->sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (filter_socket->sock < 0) {
        zlog_fatal(zc, "failed to open filter socket");
        return NULL;
    }
    /* Bind filter socket to SCION_FILTER_CMD_PORT */
    if (bind_filter_socket(filter_socket) < 0) {
        zlog_fatal(zc, "failed to bind filter socket");
        return NULL;
    }
    /* Set socket options */
    int optval = 1, res = 0;
    res |= setsockopt(filter_socket->sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    optval = 1 << 10;
    res |= setsockopt(filter_socket->sock, SOL_SOCKET, SO_RCVBUF, &optval, sizeof(optval));
    if (res < 0) {
        zlog_fatal(zc, "failed to set filter socket options");
        return NULL;
    }
    filter_socket->pollfd.fd = filter_socket->sock;
    filter_socket->pollfd.events = POLLIN;
    return filter_socket;
}

int bind_filter_socket(FilterSocket *filter_socket)
{
    struct sockaddr_in6 sin6;
    memset(&sin6, 0, sizeof(struct sockaddr_in6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_addr = in6addr_any;
    sin6.sin6_port = htons(SCION_FILTER_CMD_PORT);
    char str[MAX_HOST_ADDR_STR];
    inet_ntop(AF_INET6, &sin6.sin6_addr, str, 50);
    if (bind(filter_socket->sock, (struct sockaddr *)&sin6, sizeof(struct sockaddr_in6)) < 0) {
        zlog_fatal(filter_socket->zc, "failed to bind filter socket to %s : %d, %s",
                str, ntohs(sin6.sin6_port), strerror(errno));
        return -1;
    }
    zlog_info(filter_socket->zc, "filter socket bound to %s:%d", str, ntohs(sin6.sin6_port));
    return 0;
}

void close_filter_socket(FilterSocket *filter_socket)
{
    close(filter_socket->sock);
    close(filter_socket->pollfd.fd);
}

void poll_filter(FilterSocket *filter_socket)
{
    int count = poll(&filter_socket->pollfd, 1, 0);
    if (count < 0)
        zlog_fatal(filter_socket->zc, "poll error: %s", strerror(errno));
    if (count > 0)
        handle_filter(filter_socket);
}

void handle_filter(FilterSocket *filter_socket)
{
    uint8_t buf[FILTER_BUFSIZE];
    int sock = accept(filter_socket->sock, NULL, NULL);
    if (sock < 0) {
        zlog_error(filter_socket->zc, "error in accept: %s", strerror(errno));
        return;
    }
    zlog_info(filter_socket->zc, "new socket created: %d", sock);
    /*
     * Filter command header format:
     * length of the filter command packet (1B)
     */
    int len = recv_all(sock, buf, 1);
    if (len < 0) {
        zlog_error(filter_socket->zc, "error receiving filter command header");
        close(sock);
        return;
    }
    int packet_len = buf[0];
    if (packet_len < 0 || packet_len > FILTER_BUFSIZE) {
        zlog_error(filter_socket->zc, "invalid filter command header");
        close(sock);
        return;
    }
    /*
     * Filter command packet format:
     * isd_as (4B) | addr_type (1B) | addr (?B) | port (2B) (for src)
     * isd_as (4B) | addr_type (1B) | addr (?B) | port (2B) (for dst)
     * isd_as (4B) | addr_type (1B) | addr (?B) | port (2B) (for hop)
     * on_egress (1B) | is_end2end (1B) | l4_proto (1B)
     */
    len = recv_all(sock, buf, packet_len);
    if (len < packet_len) {
        zlog_error(filter_socket->zc, "invalid filter command packet size");
        close(sock);
    }
    set_filter(buf, filter_socket);
}

void set_filter(uint8_t *buf, FilterSocket *filter_socket)
{
    FilterKey f;
    memset(&f, 0, sizeof(f));

    /* Obtain the fields of the filter from the buffer */
    uint8_t *ptr = buf;
    uint8_t src_l, dst_l, hop_l;  // The filtering level of the addresses.
    ptr = set_scionaddr(&f.src, ptr, &src_l);
    ptr = set_scionaddr(&f.dst, ptr, &dst_l);
    ptr = set_scionaddr(&f.hop, ptr, &hop_l);
    f.on_egress = *ptr;
    f.is_end2end = *(ptr + 1);
    f.l4_proto = *(ptr + 2);

    /* Check if the filter already exists and add it, if it doesn't */
    Filter *e;
    HASH_FIND(hh, filter_socket->filter_list[src_l][dst_l][hop_l][f.l4_proto], &f, sizeof(FilterKey), e);
    if (e) {
        zlog_debug(filter_socket->zc, "entry present in the filter list already");
        return;
    }
    e = (Filter *)malloc(sizeof(Filter));
    memset(e, 0, sizeof(Filter));
    e->fkey = f;
    HASH_ADD(hh, filter_socket->filter_list[src_l][dst_l][hop_l][f.l4_proto], fkey, sizeof(FilterKey), e);
    print_filter_key(&f, filter_socket->zc, "adding a new filter key:");
}

uint8_t * set_scionaddr(SCIONAddr *addr, uint8_t *ptr, uint8_t *filter_level)
{
    /* Set the SCIONAddr fields */
    addr->isd_as = *(uint32_t *)ptr;
    addr->host.addr_type = *(uint8_t *)(ptr + 4);
    int addr_len = get_addr_len(addr->host.addr_type);
    memcpy(addr->host.addr, (uint8_t *)(ptr + 5), addr_len);
    addr->host.port = *(uint16_t *)(ptr + 5 + addr_len);
    ptr = ptr + 7 + addr_len;
    /* Obtain the filtering level by looking at the zero-valued fields hierarchially */
    /* Assumes that if a higher level field is 0, then subsequent ones are also 0 */
    *filter_level = FILTER_LEVELS - 1;
    if (addr->host.port == 0)
        (*filter_level)--;
    if (memcmp(addr->host.addr, zerobuf, MAX_HOST_ADDR_LEN) == 0)
        (*filter_level)--;
    if (addr->isd_as == 0)
        (*filter_level)--;
    return ptr;
}

void print_filter_key(FilterKey *f, zlog_category_t *zc, const char *prefix)
{
    if (prefix)
        zlog_debug(zc, "%s", prefix);
    print_scionaddr(&f->src, zc, "src");
    print_scionaddr(&f->dst, zc, "dst");
    print_scionaddr(&f->hop, zc, "hop");
    zlog_debug(zc, "on_egress : %d, is_end2end : %d, L4 protocol : %d",
            f->on_egress, f->is_end2end, f->l4_proto);
}

void print_scionaddr(SCIONAddr *addr, zlog_category_t *zc, const char *prefix)
{
    char buf[MAX_HOST_ADDR_STR];
    format_host(addr->host.addr_type, addr->host.addr, buf, MAX_HOST_ADDR_STR);
    if (prefix)
        zlog_debug(zc, "%s: [ISD-AS : %d-%d, IP : %s, Port : %d]", prefix, ISD(addr->isd_as),
                AS(addr->isd_as), buf, addr->host.port);
    else
        zlog_debug(zc, "[ISD-AS : %d-%d, IP : %s, Port : %d]", ISD(addr->isd_as),
                AS(addr->isd_as), buf, addr->host.port);
}

int is_blocked_by_filter(FilterSocket *filter_socket, uint8_t *buf, HostAddr hop, uint8_t called_from_send, struct msghdr *msg)
{
    struct timeval t1, t2;  // For profiling
    gettimeofday(&t1, NULL);

    SCIONAddr src, dst, h;
    uint8_t *l4ptr = buf;
    uint8_t l4 = get_l4_proto(&l4ptr);
    SCIONUDPHeader *udp = (SCIONUDPHeader *)l4ptr;

    /* Get src address. */
    memset(&src, 0, sizeof(SCIONAddr));
    src.isd_as = get_src_isd_as(buf);
    src.host.addr_type = SRC_TYPE((SCIONCommonHeader *) buf);
    memcpy(src.host.addr, get_src_addr(buf), get_src_len(buf));
    src.host.port = ntohs(udp->src_port);

    /* Get dst address. */
    memset(&dst, 0, sizeof(SCIONAddr));
    dst.isd_as = get_dst_isd_as(buf);
    if (called_from_send) {
        dst.host.addr_type = DST_TYPE((SCIONCommonHeader *) buf);
        memcpy(dst.host.addr, get_dst_addr(buf), get_dst_len(buf));
    }
    else {
        // Obtain the destination address from the IP header, since it is not known within the 
        // SCIONCommonHeader because of dst being a service.
        struct cmsghdr *cmsgptr;
        for (cmsgptr = CMSG_FIRSTHDR(msg); cmsgptr != NULL; cmsgptr = CMSG_NXTHDR(msg, cmsgptr)) {
            if (cmsgptr->cmsg_level == IPPROTO_IP && cmsgptr->cmsg_type == IP_PKTINFO) {
                dst.host.addr_type = ADDR_IPV4_TYPE;
                memcpy(dst.host.addr, &(DSTADDR(cmsgptr)), ADDR_IPV4_LEN);
            }
            if (cmsgptr->cmsg_level == IPPROTO_IPV6 && cmsgptr->cmsg_type == IPV6_PKTINFO) {
                dst.host.addr_type = ADDR_IPV6_TYPE;
                memcpy(dst.host.addr, &(DSTV6ADDR(cmsgptr)), ADDR_IPV6_LEN);
            }
        }
    }
    dst.host.port = ntohs(udp->dst_port);

    /* Get hop address. */
    memset(&h, 0, sizeof(SCIONAddr));
    h.isd_as = called_from_send ? src.isd_as : dst.isd_as;  // Change this if ER moves to dispatcher.
    h.host.addr_type = hop.addr_type;
    memcpy(h.host.addr, hop.addr, get_addr_len(hop.addr_type));
    h.host.port = hop.port;

    if (called_from_send) {
        if (blocked_at_send(filter_socket, &src, &dst, &h, l4))
            return 1;
    }
    else {
        if (blocked_at_deliver(filter_socket, &src, &dst, &h, l4))
            return 1;   
    }

    gettimeofday(&t2, NULL);
    zlog_debug(filter_socket->zc, "time taken by is_blocked_by_filter(): %ld",
            (t2.tv_sec - t1.tv_sec) * 1000000L + t2.tv_usec - t1.tv_usec);
    return 0;
}

int blocked_at_send(FilterSocket *filter_socket, const SCIONAddr *src, const SCIONAddr *dst, const SCIONAddr *hop, uint8_t l4)
{
    Filter *e;
    FilterKey f;
    int l4_i = l4_index(l4);
    int i, j, k;

    for (i = 0; i < FILTER_LEVELS; i++) {
        for (j = 0; j < FILTER_LEVELS; j++) {
            for (k = 0; k < FILTER_LEVELS; k++) {
                if (filter_socket->filter_list[i][j][k][l4_i] == NULL)
                    continue;

                SCIONAddr src_m, dst_m, hop_m;
                mask_scionaddr_at_level(&src_m, src, i);
                mask_scionaddr_at_level(&dst_m, dst, j);
                mask_scionaddr_at_level(&hop_m, hop, k);

                construct_filter_key(&f, &src_m, &dst_m, &src_m, BLOCK_EGRESS, BLOCK_END2END, l4);
                HASH_FIND(hh, filter_socket->filter_list[i][j][k][l4_i], &f, sizeof(FilterKey), e);
                if (e) {
                    print_filter_key(&f, filter_socket->zc,
                            "handle_send() :: Filtering packet on the following fiter:");
                    return 1;
                }
                construct_filter_key(&f, &src_m, &dst_m, &hop_m, BLOCK_INGRESS, BLOCK_END2END, l4);
                HASH_FIND(hh, filter_socket->filter_list[i][j][k][l4_i], &f, sizeof(FilterKey), e);
                if (e) {
                    print_filter_key(&f, filter_socket->zc,
                            "handle_send() :: Filtering packet on the following fiter:");
                    return 1;
                }
                construct_filter_key(&f, &src_m, &hop_m, &src_m, BLOCK_EGRESS, BLOCK_HOP_BY_HOP, l4);
                HASH_FIND(hh, filter_socket->filter_list[i][j][k][l4_i], &f, sizeof(FilterKey), e);
                if (e) {
                    print_filter_key(&f, filter_socket->zc,
                            "handle_send() :: Filtering packet on the following fiter:");
                    return 1;
                }
                construct_filter_key(&f, &src_m, &hop_m, &hop_m, BLOCK_INGRESS, BLOCK_HOP_BY_HOP, l4);
                HASH_FIND(hh, filter_socket->filter_list[i][j][k][l4_i], &f, sizeof(FilterKey), e);
                if (e) {
                    print_filter_key(&f, filter_socket->zc,
                            "handle_send() :: Filtering packet on the following fiter:");
                    return 1;
                }
            }
        }
    }
    return 0;
}

int l4_index(uint8_t l4)
{
    switch(l4) {
        case L4_SCMP:
            return 0;
        case L4_TCP:
            return 1;
        case L4_UDP:
            return 2;
        case L4_SSP:
            return 3;
        default:
            return -1;
    }
}

void mask_scionaddr_at_level(SCIONAddr *src_m, const SCIONAddr *src, int level)
{
    memset(src_m, 0, sizeof(SCIONAddr));
    if (level >= 1)
        src_m->isd_as = src->isd_as;
    if (level >= 2) {
        src_m->host.addr_type = src->host.addr_type;
        memcpy(src_m->host.addr, src->host.addr, get_addr_len(src_m->host.addr_type));
    }
    if (level >= 3)
        src_m->host.port = src->host.port;
}

void construct_filter_key(
        FilterKey *f, const SCIONAddr *src, const SCIONAddr *dst, const SCIONAddr *hop,
        uint8_t on_egress, uint8_t is_end2end, uint8_t l4)
{
    memset(f, 0, sizeof(FilterKey));
    memcpy(&f->src, src, sizeof(SCIONAddr));
    memcpy(&f->dst, dst, sizeof(SCIONAddr));
    memcpy(&f->hop, hop, sizeof(SCIONAddr));
    f->on_egress = on_egress;
    f->is_end2end = is_end2end;
    f->l4_proto = l4;
}

int blocked_at_deliver(FilterSocket *filter_socket, const SCIONAddr *src, const SCIONAddr *dst, const SCIONAddr *hop, uint8_t l4)
{
    Filter *e;
    FilterKey f;
    int l4_i = l4_index(l4);
    int i, j, k;

    for (i = 0; i < FILTER_LEVELS; i++) {
        for (j = 0; j < FILTER_LEVELS; j++) {
            for (k = 0; k < FILTER_LEVELS; k++) {
                if (filter_socket->filter_list[i][j][k][l4_i] == NULL)
                    continue;

                SCIONAddr src_m, dst_m, hop_m;
                mask_scionaddr_at_level(&src_m, src, i);
                mask_scionaddr_at_level(&dst_m, dst, j);
                mask_scionaddr_at_level(&hop_m, hop, k);

                construct_filter_key(&f, &src_m, &dst_m, &hop_m, BLOCK_EGRESS, BLOCK_END2END, l4);
                HASH_FIND(hh, filter_socket->filter_list[i][j][k][l4_i], &f, sizeof(FilterKey), e);
                if (e) {
                    print_filter_key(&f, filter_socket->zc,
                            "handle_data() :: Filtering packet on the following fiter:");
                    return 1;
                }
                construct_filter_key(&f, &src_m, &dst_m, &dst_m, BLOCK_INGRESS, BLOCK_END2END, l4);
                HASH_FIND(hh, filter_socket->filter_list[i][j][k][l4_i], &f, sizeof(FilterKey), e);
                if (e) {
                    print_filter_key(&f, filter_socket->zc,
                            "handle_data() :: Filtering packet on the following fiter:");
                    return 1;
                }
                construct_filter_key(&f, &hop_m, &dst_m, &hop_m, BLOCK_EGRESS, BLOCK_HOP_BY_HOP, l4);
                HASH_FIND(hh, filter_socket->filter_list[i][j][k][l4_i], &f, sizeof(FilterKey), e);
                if (e) {
                    print_filter_key(&f, filter_socket->zc,
                            "handle_data() :: Filtering packet on the following fiter:");
                    return 1;
                }
                construct_filter_key(&f, &hop_m, &dst_m, &dst_m, BLOCK_INGRESS, BLOCK_HOP_BY_HOP, l4);
                HASH_FIND(hh, filter_socket->filter_list[i][j][k][l4_i], &f, sizeof(FilterKey), e);
                if (e) {
                    print_filter_key(&f, filter_socket->zc,
                            "handle_data() :: Filtering packet on the following fiter:");
                    return 1;
                }
            }
        }
    }   
    return 0;        
}

void populate_test_filter_hashmaps(FilterSocket *filter_socket)
{
    int i, j, k, l, t;
    Filter *e = NULL;
    FilterKey f;
    for (i = 0; i < FILTER_LEVELS; i++) {
        for (j = 0; j < FILTER_LEVELS; j++) {
            for (k = 0; k < FILTER_LEVELS; k++) {
                for (l = 0; l < L4_PROTOCOL_COUNT; l++) {
                    for (t = 0; t < 10000; t++) {
                        e = (Filter *)malloc(sizeof(Filter));
                        memset(e, 0, sizeof(Filter));
                        f.src.isd_as = t;
                        e->fkey = f;
                        HASH_ADD(hh, filter_socket->filter_list[i][j][k][l], fkey, sizeof(FilterKey), e);
                    }
                }
            }
        }
    }
}
