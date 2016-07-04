#define _GNU_SOURCE // required to get struct in6_pktinfo definition
#include <errno.h>
#include <fcntl.h>

#include <zlog.h>

#include "filter.h"

#define DSTADDR(x) (((struct in_pktinfo *)CMSG_DATA(x))->ipi_addr)
#define DSTV6ADDR(x) (((struct in6_pktinfo *)CMSG_DATA(x))->ipi6_addr)

int bind_filter_socket(FilterSocket *filter_socket);
void handle_filter(FilterSocket *filter_socket);
void set_filter(uint8_t *buf, FilterSocket *filter_socket);
uint8_t * set_scionaddr(SCIONAddr *addr, uint8_t *ptr);
void print_filter_key(FilterKey *f, zlog_category_t *zc);
void print_scionaddr(SCIONAddr *addr, char *str, zlog_category_t *zc);
void construct_filter_key(FilterKey *f, const SCIONAddr *src, const SCIONAddr *dst,
    const SCIONAddr *hop, uint8_t on_egress, uint8_t is_end2end, int l4);

FilterSocket * init_filter_socket(zlog_category_t *zc)
{
    FilterSocket *filter_socket = (FilterSocket *)malloc(sizeof(FilterSocket));
    filter_socket->zc = zc;
    filter_socket->filter_list = NULL;
    /* Create the filter socket */
    filter_socket->sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (filter_socket->sockfd < 0) {
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
    setsockopt(filter_socket->sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    res |= setsockopt(filter_socket->sockfd, IPPROTO_IP, IP_PKTINFO, &optval, sizeof(optval));
    optval = 1 << 10;
    res |= setsockopt(filter_socket->sockfd, SOL_SOCKET, SO_RCVBUF, &optval, sizeof(optval));
    res |= fcntl(filter_socket->sockfd, F_SETFL, O_NONBLOCK);
    if (res < 0) {
        zlog_fatal(zc, "failed to set filter socket options");
        return NULL;
    }
    filter_socket->socket.fd = filter_socket->sockfd;
    filter_socket->socket.events = POLLIN;
    return filter_socket;
}

int bind_filter_socket(FilterSocket *filter_socket)
{
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(SCION_FILTER_CMD_PORT);
    if (bind(filter_socket->sockfd, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) < 0) {
        zlog_fatal(filter_socket->zc, "failed to bind filter socket to %s:%d, %s",
                inet_ntoa(sin.sin_addr), ntohs(sin.sin_port), strerror(errno));
        return -1;
    }
    if (listen(filter_socket->sockfd, MAX_FILTER_BACKLOG) < 0) {
        zlog_fatal(filter_socket->zc, "failed to listen on filter socket");
        return -1;
    }
    zlog_info(filter_socket->zc, "filter socket bound to %s:%d",
            inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
    return 0;
}

void poll_filter(FilterSocket *filter_socket)
{
    int count = poll(&filter_socket->socket, 1, 0);
    if (count < 0)
        zlog_fatal(filter_socket->zc, "poll error: %s", strerror(errno));
    if (count > 0)
        handle_filter(filter_socket);
}

void handle_filter(FilterSocket *filter_socket)
{
    uint8_t buf[FILTER_BUFSIZE];
    int sock = accept(filter_socket->sockfd, NULL, NULL);
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
    /*
     * Filter command packet format:
     * isd_as (4B) | addr_type (1B) | addr (?B) | port (2B) (for src)
     * isd_as (4B) | addr_type (1B) | addr (?B) | port (2B) (for dst)
     * isd_as (4B) | addr_type (1B) | addr (?B) | port (2B) (for hop)
     * on_egress (1B) | is_end2end (1B) | l4 protocol (4B)
     */
    int packet_len = buf[0];
    if (packet_len < 0) {
        zlog_error(filter_socket->zc, "invalid filter command header");
        close(sock);
        return;
    }
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
    ptr = set_scionaddr(&f.src, ptr);
    ptr = set_scionaddr(&f.dst, ptr);
    ptr = set_scionaddr(&f.hop, ptr);
    f.on_egress = *((uint8_t *)ptr);
    ptr++;
    f.is_end2end = *((uint8_t *)ptr);
    ptr++;
    f.protocol = *((int *)ptr);

    /* Check if the filter already exists and add it, if it doesn't */
    Filter *e;
    HASH_FIND(hh, filter_socket->filter_list, &f, sizeof(FilterKey), e);
    if (e) {
        zlog_debug(filter_socket->zc, "entry present in the filter list already");
        return;
    }
    e = (Filter *)malloc(sizeof(Filter));
    memset(e, 0, sizeof(Filter));
    e->fkey = f;
    HASH_ADD(hh, filter_socket->filter_list, fkey, sizeof(FilterKey), e);
    zlog_debug(filter_socket->zc, "adding a new filter key:");
    print_filter_key(&f, filter_socket->zc);
}

uint8_t * set_scionaddr(SCIONAddr *addr, uint8_t *ptr)
{
    addr->isd_as = *(uint32_t *)ptr;
    addr->host.addr_type = *(uint8_t *)(ptr + 4);
    int addr_len = get_addr_len(addr->host.addr_type);
    memcpy(addr->host.addr, (uint8_t *)(ptr + 5), addr_len);
    addr->host.port = *(uint16_t *)(ptr + 5 + addr_len);
    return ptr + 7 + addr_len;
}

void print_filter_key(FilterKey *f, zlog_category_t *zc)
{
    print_scionaddr(&f->src, "src", zc);
    print_scionaddr(&f->dst, "dst", zc);
    print_scionaddr(&f->hop, "hop", zc);
    zlog_debug(zc, "on_egress : %d, is_end2end : %d, L4 protocol : %d", f->on_egress,
            f->is_end2end, f->protocol);
}

void print_scionaddr(SCIONAddr *addr, char *str, zlog_category_t *zc)
{
    char buf[MAX_HOST_ADDR_STR];
    format_host(addr->host.addr_type, addr->host.addr, buf, MAX_HOST_ADDR_STR);
    zlog_debug(zc, "%s: [ISD-AS : %d-%d, IP : %s, Port : %d]", str, ISD(addr->isd_as),
            AS(addr->isd_as), buf, addr->host.port);
}

int is_blocked_by_filter(FilterSocket *filter_socket, uint8_t *buf, HostAddr hop, uint8_t called_from_send, struct msghdr *msg)
{
    SCIONAddr src, dst, h;
    uint8_t *l4ptr = buf;
    int l4 = get_l4_proto(&l4ptr);
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

    /* Check if any combination of filter is satisfied by the packet. */
    Filter *e;
    FilterKey f;
    if (called_from_send) {  // Called from handle_send()
        zlog_debug(filter_socket->zc, "Inside handle_send() filter checking.");
        construct_filter_key(&f, &src, &dst, &src, BLOCK_EGRESS, BLOCK_END2END, l4);
        HASH_FIND(hh, filter_socket->filter_list, &f, sizeof(FilterKey), e);
        if (e) {
            print_filter_key(&f, filter_socket->zc);
            return 1;
        }
        construct_filter_key(&f, &src, &dst, &h, BLOCK_INGRESS, BLOCK_END2END, l4);
        print_filter_key(&f, filter_socket->zc);  // For debug (remove later).
        HASH_FIND(hh, filter_socket->filter_list, &f, sizeof(FilterKey), e);
        if (e) {
            print_filter_key(&f, filter_socket->zc);
            return 1;
        }
        construct_filter_key(&f, &src, &h, &src, BLOCK_EGRESS, BLOCK_HOP_BY_HOP, l4);
        HASH_FIND(hh, filter_socket->filter_list, &f, sizeof(FilterKey), e);
        if (e) {
            print_filter_key(&f, filter_socket->zc);
            return 1;
        }
        construct_filter_key(&f, &src, &h, &h, BLOCK_INGRESS, BLOCK_HOP_BY_HOP, l4);
        HASH_FIND(hh, filter_socket->filter_list, &f, sizeof(FilterKey), e);
        if (e) {
            print_filter_key(&f, filter_socket->zc);
            return 1;
        }
    }
    else {  // Called from handle_data()
        zlog_debug(filter_socket->zc, "Inside handle_data() filter checking.");
        construct_filter_key(&f, &src, &dst, &h, BLOCK_EGRESS, BLOCK_END2END, l4);
        print_filter_key(&f, filter_socket->zc);  // For debug (remove later).
        HASH_FIND(hh, filter_socket->filter_list, &f, sizeof(FilterKey), e);
        if (e) {
            print_filter_key(&f, filter_socket->zc);
            return 1;
        }
        construct_filter_key(&f, &src, &dst, &dst, BLOCK_INGRESS, BLOCK_END2END, l4);
        HASH_FIND(hh, filter_socket->filter_list, &f, sizeof(FilterKey), e);
        if (e) {
            print_filter_key(&f, filter_socket->zc);
            return 1;
        }
        construct_filter_key(&f, &h, &dst, &h, BLOCK_EGRESS, BLOCK_HOP_BY_HOP, l4);
        HASH_FIND(hh, filter_socket->filter_list, &f, sizeof(FilterKey), e);
        if (e) {
            print_filter_key(&f, filter_socket->zc);
            return 1;
        }
        construct_filter_key(&f, &h, &dst, &dst, BLOCK_INGRESS, BLOCK_HOP_BY_HOP, l4);
        HASH_FIND(hh, filter_socket->filter_list, &f, sizeof(FilterKey), e);
        if (e) {
            print_filter_key(&f, filter_socket->zc);
            return 1;
        }
    }
    return 0;
}

void construct_filter_key(
        FilterKey *f, const SCIONAddr *src, const SCIONAddr *dst, const SCIONAddr *hop,
        uint8_t on_egress, uint8_t is_end2end, int l4)
{
    memset(f, 0, sizeof(FilterKey));
    memcpy(&f->src, src, sizeof(SCIONAddr));
    memcpy(&f->dst, dst, sizeof(SCIONAddr));
    memcpy(&f->hop, hop, sizeof(SCIONAddr));
    f->on_egress = on_egress;
    f->is_end2end = is_end2end;
    f->protocol = l4;
}
