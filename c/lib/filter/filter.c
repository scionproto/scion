#define _GNU_SOURCE // required to get struct in6_pktinfo definition
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <zlog.h>

#include "filter.h"

static zlog_category_t *zc;
static uint8_t zerobuf[MAX_HOST_ADDR_LEN] = { 0 };

int bind_filter_socket(FilterSocket *fs);
void set_filters(uint8_t *buf, uint8_t *num_filters_for_l4, FilterSocket *fs);
int l4_index(uint8_t l4);
uint8_t * set_scionaddr(SCIONAddr *addr, uint8_t *ptr);
void format_filter(Filter *f, char **str);
void format_scionaddr(SCIONAddr *addr, char **str);
int scionaddrs_match(const SCIONAddr *a, const SCIONAddr *b);

FilterSocket * init_filter_socket(zlog_category_t *parent_zc)
{
    zc = parent_zc;
    FilterSocket *fs = (FilterSocket *)malloc(sizeof(FilterSocket));

    int i;
    for (i = 0; i < L4_PROTOCOL_COUNT; i++) {
        fs->filter_list[i] = NULL;
        fs->num_filters_for_l4[i] = 0;
    }
    /* Create the filter socket */
    fs->sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (fs->sock < 0) {
        zlog_fatal(zc, "failed to open filter socket");
        free(fs);
        return NULL;
    }
    /* Set socket options */
    int optval = 1, res = 0;
    res |= setsockopt(fs->sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    optval = 1 << 20;
    res |= setsockopt(fs->sock, SOL_SOCKET, SO_RCVBUF, &optval, sizeof(optval));
    if (res < 0) {
        zlog_fatal(zc, "failed to set filter socket options");
        free(fs);
        return NULL;
    }
    /* Bind filter socket to SCION_FILTER_CMD_PORT and listen for connections*/
    if (bind_filter_socket(fs) < 0) {
        zlog_fatal(zc, "failed to open filter socket to connections");
        free(fs);
        return NULL;
    }
    return fs;
}

int bind_filter_socket(FilterSocket *fs)
{
    struct sockaddr_in6 sin6;
    memset(&sin6, 0, sizeof(struct sockaddr_in6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_addr = in6addr_any;
    sin6.sin6_port = htons(SCION_FILTER_CMD_PORT);
    char str[MAX_HOST_ADDR_STR];
    inet_ntop(AF_INET6, &sin6.sin6_addr, str, MAX_HOST_ADDR_STR);
    if (bind(fs->sock, (struct sockaddr *)&sin6, sizeof(struct sockaddr_in6)) < 0) {
        zlog_fatal(zc, "failed to bind filter socket to %s : %d, %s",
                str, ntohs(sin6.sin6_port), strerror(errno));
        return -1;
    }
    if (listen(fs->sock, MAX_FILTER_BACKLOG) < 0) {
        zlog_fatal(zc, "failed to listen on filter socket");
        return -1;
    }
    zlog_info(zc, "filter socket bound to %s:%d", str, ntohs(sin6.sin6_port));
    return 0;
}

void handle_filter(FilterSocket *fs)
{
    /* Accept a new connection for receving the filter */
    int sock = accept(fs->sock, NULL, NULL);
    if (sock < 0) {
        zlog_error(zc, "error in filter socket accept: %s", strerror(errno));
        return;
    }
    zlog_info(zc, "new filter connection socket created: %d", sock);

    uint8_t buf[FILTER_BUFSIZE];
    /*
     * Filter header format:
     * No. of filter commands for SCMP (1B)
     * No. of filter commands for TCP  (1B)
     * No. of filter commands for UDP  (1B)
     */
    int len = recv_all(sock, buf, L4_PROTOCOL_COUNT);
    if (len < 0) {
        zlog_error(zc, "error receiving filter header (len = %d)", len);
        close(sock);
        return;
    }

    uint8_t num_filters_for_l4[L4_PROTOCOL_COUNT];
    int num_filters = 0;
    int i;
    for (i = 0; i < L4_PROTOCOL_COUNT; i++) {
        num_filters_for_l4[i] = buf[i];
        num_filters += num_filters_for_l4[i];
    }
    /*
     * Filter command format (follows network byte order):
     * [
     *  l4_protocol (1B) |
     *  src: isd_as (4B) | addr_type (1B) | addr (MAX_HOST_ADDR_LEN) | port (2B) |
     *  dst: isd_as (4B) | addr_type (1B) | addr (MAX_HOST_ADDR_LEN) | port (2B) |
     *  hop: isd_as (4B) | addr_type (1B) | addr (MAX_HOST_ADDR_LEN) | port (2B) |
     *  options (1B)
     * ]

     * Filter packet format:
     * <Filter command-1> <Filter command-2> ...... <Filter command-[num_filters]>
     */
    int packet_len = num_filters * FILTER_CMD_SIZE;
    if (packet_len > FILTER_BUFSIZE) {
        zlog_error(zc, "cannot read so many filter commands into the buffer");
        close(sock);
        return;
    }
    len = recv_all(sock, buf, packet_len);
    if (len != packet_len) {
        zlog_error(zc, "invalid filter packet size (len = %d)", len);
        close(sock);
        return;
    }
    close(sock);

    /* Clear existing filters and set the new batch of filters */
    for (i = 0; i < L4_PROTOCOL_COUNT; i++) {
        free(fs->filter_list[i]);
        fs->filter_list[i] = NULL;
        fs->num_filters_for_l4[i] = 0;
    }
    set_filters(buf, num_filters_for_l4, fs);
}

void set_filters(uint8_t *buf, uint8_t *num_filters_for_l4, FilterSocket *fs)
{
    /* Initialize the filter arrays for the L4 protocols */
    int num_filters = 0;
    int i;
    for (i = 0; i < L4_PROTOCOL_COUNT; i++) {
        fs->filter_list[i] = (Filter *)malloc(num_filters_for_l4[i] * sizeof(Filter));
        num_filters += num_filters_for_l4[i];
        fs->num_filters_for_l4[i] = 0;
    }

    /* Populate the arrays with the filter commands in the buffer */
    uint8_t *ptr = buf;
    for (i = 0; i < num_filters; i++) {
        uint8_t l4 = *ptr;
        int l4_idx = l4_index(l4);

        if (l4_idx < 0) {
            zlog_debug(zc, "filter neglected : unknown l4 protocol number '%d'", l4);
            ptr += FILTER_CMD_SIZE;
            continue;
        }

        if (fs->num_filters_for_l4[l4_idx] >= num_filters_for_l4[l4_idx]) {
            zlog_debug(zc, "filter neglected : array for l4 protocol number '%d' full", l4);
            ptr += FILTER_CMD_SIZE;
            continue;
        }

        ptr++;
        Filter *f = &fs->filter_list[l4_idx][fs->num_filters_for_l4[l4_idx]];
        memset(f, 0, sizeof(Filter));
        ptr = set_scionaddr(&f->src, ptr);
        ptr = set_scionaddr(&f->dst, ptr);
        ptr = set_scionaddr(&f->hop, ptr);
        f->options = *ptr++;
        fs->num_filters_for_l4[l4_idx]++;
        /* Log the newly added filter */
        char *filter_str = NULL;
        format_filter(f, &filter_str);
        zlog_debug(zc, "adding a new filter:\n%s", filter_str);
        free(filter_str);
    }
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
        default:
            return -1;
    }
}

uint8_t * set_scionaddr(SCIONAddr *addr, uint8_t *ptr)
{
    /* Set the SCIONAddr fields */
    addr->isd_as = be64toh(*(isdas_t *)ptr);
    addr->host.addr_type = *(ptr + 4);
    memcpy(addr->host.addr, ptr + 5, MAX_HOST_ADDR_LEN);
    addr->host.port = ntohs(*(uint16_t *)(ptr + 5 + MAX_HOST_ADDR_LEN));
    return (ptr + 7 + MAX_HOST_ADDR_LEN);
}

void format_filter(Filter *f, char **str)
{
    char *src = NULL, *dst = NULL, *hop = NULL;
    format_scionaddr(&f->src, &src);
    format_scionaddr(&f->dst, &dst);
    format_scionaddr(&f->hop, &hop);
    asprintf(str, "src = %s\ndst = %s\nhop = %s\noptions = %d", src, dst, hop, f->options);
    free(src);
    free(dst);
    free(hop);
}

void format_scionaddr(SCIONAddr *addr, char **str)
{
    char buf[MAX_HOST_ADDR_STR];
    char isd_as_str[MAX_ISD_AS_STR];

    format_host(addr->host.addr_type, addr->host.addr, buf, MAX_HOST_ADDR_STR);
    format_isd_as(isd_as_str, MAX_ISD_AS_STR, addr->isd_as);
    asprintf(str, "[ISD-AS : %s, IP : %s, Port : %d]", isd_as_str, buf, addr->host.port);
}

int is_blocked_by_filter(FilterSocket *fs, uint8_t *buf, SCIONAddr *hop, int on_egress)
{
    struct timeval t1, t2;  // For profiling
    gettimeofday(&t1, NULL);

    SCIONAddr src, dst;
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
    dst.host.addr_type = DST_TYPE((SCIONCommonHeader *) buf);
    memcpy(dst.host.addr, get_dst_addr(buf), get_dst_len(buf));
    dst.host.port = ntohs(udp->dst_port);

    /* Check if the packet is blocked by any filter for the L4 proto */
    Filter *f;
    int l4_idx = l4_index(l4);
    if (l4_idx < 0) {
        zlog_debug(zc, "filtering logic neglected : unknown l4 protocol number '%d'", l4);
        return 0;
    }

    int i;
    for (i = 0; i < fs->num_filters_for_l4[l4_idx]; i++) {
        f = &fs->filter_list[l4_idx][i];
        if (on_egress != ON_EGRESS(f->options))
            continue;
        int filter_addrs_match =
            (scionaddrs_match(&f->src, &src) != IS_SRC_NEGATED(f->options)) &&
            (scionaddrs_match(&f->dst, &dst) != IS_DST_NEGATED(f->options)) &&
            (scionaddrs_match(&f->hop,  hop) != IS_HOP_NEGATED(f->options));
        if (filter_addrs_match) {
            if (IS_FILTER_NEGATED(f->options))
                return 0;
            else
                return 1;
        }
    }

    gettimeofday(&t2, NULL);  // For profiling
    zlog_debug(zc, "time taken by is_blocked_by_filter() in microsecs: %ld",
            (t2.tv_sec - t1.tv_sec) * 1000000L + t2.tv_usec - t1.tv_usec);
    return 0;
}

int scionaddrs_match(const SCIONAddr *a, const SCIONAddr *b)
{
    if (ISD(a->isd_as) == 0)
        return 1;
    if (ISD(a->isd_as) != ISD(b->isd_as))
        return 0;
    if (AS(a->isd_as) == 0)
        return 1;
    if (AS(a->isd_as) != AS(b->isd_as))
        return 0;
    if (a->host.addr_type == 0)
        return 1;
    if (a->host.addr_type != b->host.addr_type)
        return 0;
    if (!memcmp(a->host.addr, zerobuf, get_addr_len(a->host.addr_type)))
        return 1;
    if (!memcmp(a->host.addr, b->host.addr, get_addr_len(a->host.addr_type)))
        return 0;
    if (a->host.port == 0)
        return 1;
    if (a->host.port != b->host.port)
        return 0;
    return 1;
}
