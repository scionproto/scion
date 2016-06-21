#define _GNU_SOURCE // required to get struct in6_pktinfo definition
#include <errno.h>
#include <netinet/in.h>

#include <zlog.h>

#include "filter.h"

#define DSTADDR(x) (((struct in_pktinfo *)CMSG_DATA(x))->ipi_addr)
#define DSTV6ADDR(x) (((struct in6_pktinfo *)CMSG_DATA(x))->ipi6_addr)

int bind_filter_socket(FilterSocket *filter_socket);
void handle_filter(FilterSocket *filter_socket);
void add_new_filter(char *buf, FilterSocket *filter_socket);
int get_filter_fields(char *buf, char *fields[], int fields_size);
int set_filter_from_fields(char *fields[], FilterSocket *filter_socket);
int get_scionaddr_from_fields(SCIONAddr *ha, char **fields, zlog_category_t *zc);
void construct_filter_key(FilterKey *f, const SCIONAddr *src, const SCIONAddr *dst,
    const SCIONAddr *hop, uint8_t on_egress, uint8_t is_end2end, int l4);

int init_filter_socket(FilterSocket **filter_socket, zlog_category_t *zc)
{
    *filter_socket = (FilterSocket *)malloc(sizeof(FilterSocket));
    (*filter_socket)->zc = zc;
    (*filter_socket)->filter_list = NULL;
    /* Create the filter socket */
    (*filter_socket)->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if ((*filter_socket)->sockfd < 0) {
        zlog_fatal(zc, "failed to open filter socket");
        return -1;
    }
    /* Bind filter socket to SCION_UDP_EH_DATA_PORT */
    if (bind_filter_socket((*filter_socket)) < 0) {
        zlog_fatal(zc, "failed to bind filter socket");
        return -1;
    }
    (*filter_socket)->socket.fd = (*filter_socket)->sockfd;
    (*filter_socket)->socket.events = POLLIN;
    return 0;
}

int bind_filter_socket(FilterSocket *filter_socket)
{
    struct sockaddr_storage sa;
    sockaddr_in *sin = (sockaddr_in *)&sa;
    memset(sin, 0, sizeof(sockaddr_in));
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = INADDR_ANY;
    sin->sin_port = htons(SCION_FILTER_CMD_PORT);
    if (bind(filter_socket->sockfd, (struct sockaddr *)sin, sizeof(sockaddr_in)) < 0) {
        zlog_fatal(filter_socket->zc, "failed to bind filter socket to %s:%d, %s",
                inet_ntoa(sin->sin_addr), ntohs(sin->sin_port), strerror(errno));
        return -1;
    }
    zlog_info(filter_socket->zc, "filter socket bound to %s:%d", inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
    return 0;
}

void handle_filter(FilterSocket *filter_socket)
{
    char buf[FILTER_BUFSIZE];
    memset(buf, 0, sizeof(buf));

    int len = recv(filter_socket->sockfd, buf, FILTER_BUFSIZE, 0);
    if (len < 0) {
        zlog_error(filter_socket->zc, "error on recvfrom: %s", strerror(errno));
        return;
    }
    zlog_debug(filter_socket->zc, "msg received by filter socket: %s", buf);
    add_new_filter(buf, filter_socket);
}

void poll_filter(FilterSocket *filter_socket)
{
        int count = poll(&filter_socket->socket, 1, 0);
        if (count < 0)
            zlog_fatal(filter_socket->zc, "poll error: %s", strerror(errno));
        if (count > 0)
            handle_filter(filter_socket);
}

void add_new_filter(char *buf, FilterSocket *filter_socket)
{
    char *fields[FILTER_FIELD_COUNT];
    /* Get the fields of the filter from the message */
    int field_count = get_filter_fields(buf, fields, FILTER_FIELD_COUNT);
    if (field_count < FILTER_FIELD_COUNT) {
        zlog_error(filter_socket->zc, "expected a %d-tuple for the filter, received a %d-tuple",
                FILTER_FIELD_COUNT, field_count);
        return;
    }
    /* Set a filter in the filter_list using the obtained fields */
    if (set_filter_from_fields(fields, filter_socket) < 0) {
        zlog_error(filter_socket->zc, "filter not added: received badly formatted request");
        return;
    }
}

int get_filter_fields(char *buf, char *fields[], int fields_count)
{
    char *field = strtok(buf, " ");
    int i = 0;
    while (field != NULL && i < fields_count) {
        fields[i] = field;
        field = strtok(NULL, " ");
        i++;
    }
    return i;
}

int set_filter_from_fields(char *fields[], FilterSocket *filter_socket)
{
    /*
    Format of 'fields' of the filter should be:
    fields[0] = isd_as, fields[1] = ip, fields[2] = port, fields[3] = address type  (for source)
    fields[4] = isd_as, fields[5] = ip, fields[6] = port, fields[7] = address type  (for destination)
    fields[8] = isd_as, fields[9] = ip, fields[10] = port, fields[11] = address type  (for filter location)
    fields[12] = filter traffic at ingress/egress?
    fields[13] = filter traffic hop by hop or end2end
    fields[14] = L4 protocol
    */
    FilterKey f;
    memset(&f, 0, sizeof(f));

    if (get_scionaddr_from_fields(&f.src, fields, filter_socket->zc) < 0)
        return -1;
    if (get_scionaddr_from_fields(&f.dst, fields + 4, filter_socket->zc) < 0)
        return -1;
    if (get_scionaddr_from_fields(&f.hop, fields + 8, filter_socket->zc) < 0)
        return -1;
    errno = 0;
    f.on_egress = strtoul(fields[12], NULL, 10);
    if (errno) {
        zlog_error(filter_socket->zc, "Filter direction '%s' could not be parsed to an int: [errno = %d]", fields[12], errno);
        return -1;
    }
    errno = 0;
    f.is_end2end = strtol(fields[13], NULL, 10);
    if (errno) {
        zlog_error(filter_socket->zc, "Filtering mode '%s' could not be parsed to an int: [errno = %d]", fields[13], errno);
        return -1;
    }
    errno = 0;
    f.protocol = strtol(fields[14], NULL, 10);
    if (errno) {
        zlog_error(filter_socket->zc, "L4 protocol '%s' could not be parsed to an int: [errno = %d]", fields[14], errno);
        return -1;
    }

    Filter *e;
    HASH_FIND(hh, filter_socket->filter_list, &f, sizeof(FilterKey), e);
    if (e) {
        zlog_debug(filter_socket->zc, "entry present in the filter list already");
        return 0;
    }

    e = (Filter *)malloc(sizeof(Filter));
    memset(e, 0, sizeof(Filter));
    e->fkey = f;
    HASH_ADD(hh, filter_socket->filter_list, fkey, sizeof(FilterKey), e);
    zlog_debug(filter_socket->zc, "Adding a new filter key");
    print_filter_key(&f, filter_socket->zc);
    return 0;
}

int get_scionaddr_from_fields(SCIONAddr *ha, char **fields, zlog_category_t *zc)
{
    memset(ha, 0, sizeof(SCIONAddr));
    errno = 0;
    ha->isd_as = strtoul(fields[0], NULL, 10);
    if (errno) {
        zlog_error( zc, "isd_as '%s' could not be parsed to an int: [errno = %d]", fields[0], errno);
        return -1;
    }

    errno = 0;
    uint16_t port = strtoul(fields[2], NULL, 10);
    if (errno) {
        zlog_error(zc, "port '%s' could not be parsed to an int: [errno = %d]", fields[2], errno);
        return -1;
    }

    errno = 0;
    uint8_t addr_type = strtoul(fields[3], NULL, 10);
    if (errno) {
        zlog_error(zc, "addr_type '%s' could not be parsed to an int: [errno = %d]", fields[3], errno);
        return -1;
    }

    if (addr_type == ADDR_IPV4_TYPE || addr_type == ADDR_IPV6_TYPE) {
        sockaddr_in sa;
        sa.sin_family = (addr_type == 1) ? AF_INET : AF_INET6;
        sa.sin_port = port;
        /* IP address */
        if (inet_pton(sa.sin_family, fields[1], &sa.sin_addr) != 1) {
            zlog_error(zc, "%s not a valid IP", fields[1]);
            return -1;
        }
        if (sockaddr_to_hostaddr(&sa, &ha->host) < 0) {
            zlog_error(zc, "couldn't convert sockaddr to hostaddr");
            return -1;
        }
    }
    else if (addr_type == ADDR_SVC_TYPE) {
        ha->host.addr_type = addr_type;
        /* SVC address */
        errno = 0;
        uint16_t addr = strtoul(fields[1], NULL, 10);
        if (errno) {
            zlog_error(zc, "svc ip '%s' could not be parsed to an int: [errno = %d]", fields[1], errno);
            return -1;
        }
        memcpy(ha->host.addr, &addr, ADDR_SVC_LEN);
        ha->host.port = port;
    }
    else {
        zlog_error(zc, "called get_scionaddr_from_fields() for an unimplemented addr_type %d",
                addr_type);
        return -1;
    }
    return 0;
}

int sockaddr_to_hostaddr(const sockaddr_in *sa, HostAddr *ha)
{
    if (sa->sin_family == AF_INET) {
        ha->addr_type = ADDR_IPV4_TYPE;
        memcpy(ha->addr, &sa->sin_addr, ADDR_IPV4_LEN);
        ha->port = sa->sin_port;
    }
    else if (sa->sin_family == AF_INET6) {
        ha->addr_type = ADDR_IPV6_TYPE;
        memcpy(ha->addr, &sa->sin_addr, ADDR_IPV6_LEN);
        ha->port = sa->sin_port;
    }
    else {
        return -1;
    }
    return 0;
}

void print_filter_key(FilterKey *f, zlog_category_t *zc)
{
    print_scionaddr(&f->src, "src", zc);
    print_scionaddr(&f->dst, "dst", zc);
    print_scionaddr(&f->hop, "hop", zc);
    zlog_debug(zc, "on_egress : %d, is_end2end : %d, L4 protocol : %d", f->on_egress, f->is_end2end, f->protocol);
}

void print_scionaddr(SCIONAddr *addr, char *str, zlog_category_t *zc)
{
    char buf[MAX_HOST_ADDR_STR];
    format_host(addr->host.addr_type, addr->host.addr, buf, MAX_HOST_ADDR_STR);
    zlog_debug(zc, "%s: [ISD-AS : %d-%d, IP : %s, Port : %d]", str, ISD(addr->isd_as), AS(addr->isd_as), buf, addr->host.port);
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
    src.host.port = udp->src_port;

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
    dst.host.port = udp->dst_port;

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
        construct_filter_key(&f, &src, &dst, &src, BLOCK_EGRESS, BLOCK_END2END, l4);
        HASH_FIND(hh, filter_socket->filter_list, &f, sizeof(FilterKey), e);
        if (e) {
            return 1;
        }
        construct_filter_key(&f, &src, &dst, &h, BLOCK_INGRESS, BLOCK_END2END, l4);
        zlog_debug(filter_socket->zc, "Inside handle_send() filter checking:");
        print_filter_key(&f, filter_socket->zc);
        HASH_FIND(hh, filter_socket->filter_list, &f, sizeof(FilterKey), e);
        if (e) {
            return 1;
        }
        construct_filter_key(&f, &src, &h, &src, BLOCK_EGRESS, BLOCK_HOP_BY_HOP, l4);
        HASH_FIND(hh, filter_socket->filter_list, &f, sizeof(FilterKey), e);
        if (e) {
            return 1;
        }
        construct_filter_key(&f, &src, &h, &h, BLOCK_INGRESS, BLOCK_HOP_BY_HOP, l4);
        HASH_FIND(hh, filter_socket->filter_list, &f, sizeof(FilterKey), e);
        if (e) {
            return 1;
        }
    }
    else {  // Called from handle_data()
        construct_filter_key(&f, &src, &dst, &h, BLOCK_EGRESS, BLOCK_END2END, l4);
        zlog_debug(filter_socket->zc, "Inside handle_data() filter checking:");
        print_filter_key(&f, filter_socket->zc);
        HASH_FIND(hh, filter_socket->filter_list, &f, sizeof(FilterKey), e);
        if (e) {
            return 1;
        }
        construct_filter_key(&f, &src, &dst, &dst, BLOCK_INGRESS, BLOCK_END2END, l4);
        HASH_FIND(hh, filter_socket->filter_list, &f, sizeof(FilterKey), e);
        if (e) {
            return 1;
        }
        construct_filter_key(&f, &h, &dst, &h, BLOCK_EGRESS, BLOCK_HOP_BY_HOP, l4);
        HASH_FIND(hh, filter_socket->filter_list, &f, sizeof(FilterKey), e);
        if (e) {
            return 1;
        }
        construct_filter_key(&f, &h, &dst, &dst, BLOCK_INGRESS, BLOCK_HOP_BY_HOP, l4);
        HASH_FIND(hh, filter_socket->filter_list, &f, sizeof(FilterKey), e);
        if (e) {
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
