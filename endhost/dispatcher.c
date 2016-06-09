#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#include "zlog.h"

#include "scion.h"
#include "uthash.h"

#define APP_BUFSIZE 32
#define DATA_BUFSIZE 65535

#define MAX_SVCS_PER_ADDR 10

#define MAX_BACKLOG 128
#define MAX_SOCKETS 1024
#define APP_INDEX 0
#define DATA_INDEX 1

#define DSTADDR_DATASIZE (CMSG_SPACE(sizeof(struct in_pktinfo)))
#define DSTADDR(x) (((struct in_pktinfo *)CMSG_DATA(x))->ipi_addr)

#define IS_REG_CMD(x) ((x) & 1)
#define IS_SCMP_REQ(x) (((x) >> 1) & 1)

typedef struct sockaddr_in sockaddr_in;

typedef struct {
    uint16_t port;
    uint32_t isd_as;
    uint8_t host[MAX_HOST_ADDR_LEN];
    uint64_t flow_id;
} L4Key;

#define MIN_UDP_PORT 1025
#define MAX_UDP_PORT USHRT_MAX
static uint16_t next_port = MIN_UDP_PORT;

typedef struct {
    uint16_t addr;
    uint32_t isd_as;
    uint8_t host[MAX_HOST_ADDR_LEN];
} SVCKey;

typedef struct {
    SVCKey key;
    int count;
    int sockets[MAX_SVCS_PER_ADDR];
    UT_hash_handle hh;
} SVCEntry;

typedef struct Entry {
    L4Key l4_key;
    int sock;
    uint8_t scmp;
    struct Entry **list;
    SVCEntry *se;
    UT_hash_handle hh;
    UT_hash_handle pollhh;
} Entry;

Entry *ssp_flow_list = NULL;
Entry *ssp_wildcard_list = NULL;
Entry *udp_port_list = NULL;
Entry *poll_fd_list = NULL;

SVCEntry *svc_list = NULL;

static struct pollfd sockets[MAX_SOCKETS];
static int num_sockets = 2; // data_socket and app_socket

static int data_socket;
static int app_socket;

static zlog_category_t *zc;

void handle_signal(int signal);
int run();

int create_sockets();
int set_sockopts();
int bind_app_socket();
int bind_data_socket();

void handle_app();
void register_ssp(uint8_t *buf, int len, int sock);
void register_udp(uint8_t *buf, int len, int sock);
Entry * parse_request(uint8_t *buf, int len, int proto, int sock);
int find_available_port(Entry *list, L4Key *key);
void reply(int sock, int port);
static inline uint16_t get_next_port();

void handle_data();
void deliver_ssp(uint8_t *buf, uint8_t *l4ptr, int len, HostAddr *from);
void deliver_udp(uint8_t *buf, int len, HostAddr *from, sockaddr_in *dst);

void process_scmp(uint8_t *buf, SCMPL4Header *scmpptr, int len, sockaddr_in *from);
void send_scmp_echo_reply(uint8_t *buf, SCMPL4Header *scmpptr, sockaddr_in *from);
void deliver_scmp(uint8_t *buf, SCMPL4Header *l4ptr, int len, sockaddr_in *from);

void handle_send(int index);
void cleanup_socket(int sock, int index, int err);

int main(int argc, char **argv)
{
    signal(SIGTERM, handle_signal);
    signal(SIGQUIT, handle_signal);
    signal(SIGINT, handle_signal);
    signal(SIGPIPE, handle_signal);

    struct rlimit rl;
    int res;

    rl.rlim_cur = MAX_SOCKETS;
    rl.rlim_max = MAX_SOCKETS;
    if (setrlimit(RLIMIT_NOFILE, &rl)< 0) {
        fprintf(stderr, "failed to set fileno limit\n");
        return -1;
    }

    setenv("TZ", "UTC", 1);

    if (zlog_init("endhost/dispatcher.conf") < 0) {
        fprintf(stderr, "failed to init zlog\n");
        return -1;
    }
    zc = zlog_get_category("dispatcher");
    if (!zc) {
        fprintf(stderr, "failed to get dispatcher zlog category\n");
        zlog_fini();
        return -1;
    }

    zlog_info(zc, "dispatcher with zlog starting up");

    if (create_sockets() < 0)
        return -1;

    res = run();

    /* Would only get down here if poll failed */

    close(data_socket);
    close(app_socket);
    int i;
    for (i = 0; i < num_sockets; i++)
        close(sockets[i].fd);
    zlog_fini();
    return res;
}

void handle_signal(int sig)
{
    switch (sig) {
        case SIGPIPE:
            zlog_debug(zc, "Broken pipe");
            break;
        case SIGTERM:
            zlog_info(zc, "Received SIGTERM");
            unlink(SCION_DISPATCHER_ADDR);
            exit(0);
        default:
            zlog_info(zc, "Received signal %d", sig);
            unlink(SCION_DISPATCHER_ADDR);
            exit(1);
    }
}

int create_sockets()
{
    app_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    data_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (data_socket < 0 || app_socket < 0) {
        zlog_fatal(zc, "failed to open sockets");
        return -1;
    }
    if (set_sockopts() < 0) {
        zlog_fatal(zc, "failed to set socket options");
        return -1;
    }

    /* Bind app socket to SCION_DISPATCHER_ADDR */
    if (bind_app_socket() < 0)
        return -1;

    /* Bind data socket to SCION_UDP_EH_DATA_PORT */
    if (bind_data_socket() < 0)
        return -1;

    sockets[APP_INDEX].fd = app_socket;
    sockets[APP_INDEX].events = POLLIN;
    sockets[DATA_INDEX].fd = data_socket;
    sockets[DATA_INDEX].events = POLLIN;

    int i;
    for (i = 2; i < MAX_SOCKETS; i++) {
        sockets[i].fd = -1;
        sockets[i].events = 0;
        sockets[i].revents = 0;
    }

    return 0;
}

int set_sockopts()
{
    int optval = 1;
    /*
     * FIXME(kormat): This should go away once the dispatcher and the router no
     * longer try binding to the same socket.
     */
    int res = setsockopt(data_socket, SOL_SOCKET, SO_REUSEADDR,
            &optval, sizeof(optval));
    res |= setsockopt(data_socket, IPPROTO_IP, IP_PKTINFO, &optval, sizeof(optval));
    optval = 1 << 20;
    res |= setsockopt(data_socket, SOL_SOCKET, SO_RCVBUF, &optval, sizeof(optval));
    res |= fcntl(app_socket, F_SETFL, O_NONBLOCK);
    res |= fcntl(data_socket, F_SETFL, O_NONBLOCK);
    return res;
}

int bind_app_socket()
{
    struct sockaddr_un su;
    memset(&su, 0, sizeof(su));
    su.sun_family = AF_UNIX;
    strcpy(su.sun_path, SCION_DISPATCHER_ADDR);
    if (bind(app_socket, (struct sockaddr *)&su, sizeof(su)) < 0) {
        zlog_fatal(zc, "failed to bind app socket to %s", su.sun_path);
        return -1;
    }
    if (listen(app_socket, MAX_BACKLOG) < 0) {
        zlog_fatal(zc, "failed to listen on app socket");
        return -1;
    }
    zlog_info(zc, "app socket bound to %s", su.sun_path);
    return 0;
}

int bind_data_socket()
{
    sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port = htons(SCION_UDP_EH_DATA_PORT);
    if (bind(data_socket, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        zlog_fatal(zc, "failed to bind data socket to %s:%d, %s",
                inet_ntoa(sa.sin_addr), ntohs(sa.sin_port), strerror(errno));
        return -1;
    }
    zlog_info(zc, "data socket bound to %s:%d", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
    return 0;
}

int run()
{
    while (1) {
        int count = poll(sockets, num_sockets, -1);
        if (count < 0) {
            zlog_fatal(zc, "poll error: %s", strerror(errno));
            return -1;
        }
        int i;
        for (i = 0; i < num_sockets && count > 0; i++) {
            if (sockets[i].fd == -1 || sockets[i].revents == 0)
                continue;
            count--;
            switch (i) {
                case APP_INDEX:
                    handle_app();
                    break;
                case DATA_INDEX:
                    handle_data();
                    break;
                default:
                    handle_send(i);
                    break;
            }
        }
    }
    return 0; // shouldn't get here
}

void handle_app()
{
    if (num_sockets == MAX_SOCKETS) {
        zlog_warn(zc, "no room to allocate new socket");
        return;
    }

    uint8_t buf[APP_BUFSIZE];
    int sock = accept(app_socket, NULL, NULL);
    if (sock < 0) {
        zlog_error(zc, "error in accept: %s", strerror(errno));
        return;
    }
    zlog_info(zc, "new socket created: %d", sock);
    /*
     * Application message format:
     * cookie (8B) | addr_len (1B) | packet_len (4B) | addr (?B) | port (2B) | msg (?B)
     * addr and port denote first hop for outgoing packets
     * if addr_len == 0, addr and port fields are omitted (which is the case for registration messages)
     */
    int len = recv_all(sock, buf, DP_HEADER_LEN);
    if (len < 0) {
        zlog_error(zc, "error receiving registration request");
        close(sock);
        return;
    }
    int packet_len = 0;
    // Here addr_len will always be 0 and there will be no port number either
    parse_dp_header(buf, NULL, &packet_len);
    if (packet_len < 0) {
        zlog_error(zc, "invalid dispatcher header in registration packet");
        close(sock);
        return;
    }
    // addr_len is 0
    len = recv_all(sock, buf, packet_len);
    if (len > 2) { /* command (1B) | proto (1B) | id */
        unsigned char protocol = buf[1];
        zlog_info(zc, "received registration for proto: %d (%d bytes)", protocol, len);
        switch (protocol) {
            case L4_SSP:
                register_ssp(buf, len, sock);
                break;
            case L4_UDP:
                register_udp(buf, len, sock);
                break;
        }
    } else {
        zlog_error(zc, "invalid registration packet size");
        close(sock);
    }
}

void register_ssp(uint8_t *buf, int len, int sock)
{
    zlog_info(zc, "SSP registration request");
    Entry *e = parse_request(buf, len, L4_SSP, sock);
    if (!e)
        return;
    Entry *old = NULL;
    if (e->l4_key.flow_id != 0) {
        /* Find registered flow ID */
        HASH_FIND(hh, ssp_flow_list, &e->l4_key, sizeof(L4Key), old);
        if (old) {
            zlog_error(zc, "address-flow already registered");
            reply(sock, 0);
            return;
        }
        e->list = &ssp_flow_list;
        HASH_ADD(hh, ssp_flow_list, l4_key, sizeof(L4Key), e);
        zlog_info(zc, "flow registration success: %" PRIu64, e->l4_key.flow_id);
    } else {
        if (find_available_port(ssp_wildcard_list, &e->l4_key) < 0) {
            free(e);
            reply(sock, 0);
            return;
        }
        e->list = &ssp_wildcard_list;
        HASH_ADD(hh, ssp_wildcard_list, l4_key, sizeof(L4Key), e);
        zlog_info(zc, "wildcard registration success: %d", e->l4_key.port);
    }
    reply(sock, e->l4_key.port);
}

void register_udp(uint8_t *buf, int len, int sock)
{
    zlog_info(zc, "UDP registration request");
    Entry *e = parse_request(buf, len, L4_UDP, sock);
    if (!e)
        return;
    if (find_available_port(udp_port_list, &e->l4_key) < 0) {
        free(e);
        reply(sock, 0);
        return;
    }
    e->list = &udp_port_list;
    HASH_ADD(hh, udp_port_list, l4_key, sizeof(L4Key), e);
    reply(sock, e->l4_key.port);
}

Entry * parse_request(uint8_t *buf, int len, int proto, int sock)
{
    uint32_t isd_as = ntohl(*(uint32_t *)(buf + 2));
    uint16_t port = ntohs(*(uint16_t *)(buf + 6));
    int common = 9; // start of (protocol/addrtype)-dependent data

    zlog_info(zc, "registration for isd_as %x(%d,%d)", isd_as, ISD(isd_as), AS(isd_as));

    Entry *e = (Entry *)malloc(sizeof(Entry));
    if (!e) {
        zlog_fatal(zc, "malloc failed, abandon ship");
        exit(1);
    }
    memset(e, 0, sizeof(Entry));
    e->sock = sock;
    sockets[num_sockets].fd = sock;
    sockets[num_sockets].events = POLLIN;
    num_sockets++;
    HASH_ADD(pollhh, poll_fd_list, sock, sizeof(int), e);

    uint8_t type = *(uint8_t *)(buf + 8);
    if (type < ADDR_IPV4_TYPE || type > ADDR_IPV6_TYPE) {
        zlog_error(zc, "Invalid address type: %d", type);
        return NULL;
    }

    SVCKey svc_key;
    memset(&svc_key, 0, sizeof(SVCKey));

    int addr_len = get_addr_len(type);
    int end;

    if (proto == L4_SSP) {
    /* command (1B) | proto (1B) | isd_as (4B) | port (2B) | addr type (1B) | flow ID (8B) | addr (?B) | SVC (2B, optional) */
        e->l4_key.flow_id = *(uint64_t *)(buf + common);
        e->l4_key.port = port;
        e->l4_key.isd_as = isd_as;
        memcpy(e->l4_key.host, buf + common + 8, addr_len);
        end = addr_len + common + 8;
        zlog_info(zc, "registration for %s:%d:%" PRIu64,
                inet_ntoa(*(struct in_addr *)e->l4_key.host), e->l4_key.port, e->l4_key.flow_id);
    } else if (proto == L4_UDP) {
    /* command (1B) | proto (1B) | isd_as (4B) | port (2B) | addr type (1B) | addr (?B) | SVC (2B, optional) */
        e->l4_key.port = port;
        e->l4_key.isd_as = isd_as;
        memcpy(e->l4_key.host, buf + common, addr_len);
        end = addr_len + common;
        zlog_info(zc, "registration for %s:%d", inet_ntoa(*(struct in_addr *)e->l4_key.host), e->l4_key.port);
    }
    if (IS_SCMP_REQ(*buf))
        e->scmp = 1;

    if (len > end) {
        memcpy(svc_key.host, buf + end - addr_len, addr_len);
        svc_key.addr = ntohs(*(uint16_t *)(buf + end));
        svc_key.isd_as = isd_as;
        zlog_info(zc, "SVC (%d) registration included", svc_key.addr);
        SVCEntry *se;
        HASH_FIND(hh, svc_list, &svc_key, sizeof(svc_key), se);
        if (se) {
            if (se->count < MAX_SVCS_PER_ADDR)
                se->sockets[se->count++] = sock;
            else
                zlog_warn(zc, "Reached maximum SVC entries for this host");
        } else {
            se = (SVCEntry *)malloc(sizeof(SVCEntry));
            if (!se) {
                zlog_fatal(zc, "malloc failed, abandon ship");
                exit(1);
            }
            memset(se, 0, sizeof(SVCEntry));
            se->key = svc_key;
            se->sockets[se->count++] = sock;
            HASH_ADD(hh, svc_list, key, sizeof(SVCKey), se);
        }
        e->se = se;
    }

    return e;
}

int find_available_port(Entry *list, L4Key *key)
{
    Entry *old;
    int requested = 1;
    if (key->port == 0) {
        requested = 0;
        key->port = get_next_port();
    }
    int start_port = key->port;
    while (1) {
        // Find an available port number between 1025 and 65535.
        HASH_FIND(hh, ssp_wildcard_list, key, sizeof(L4Key), old);
        if (old) {
            if (requested) {
                // If app requested unavailable port number, reply with failure message
                zlog_error(zc, "requested port number %d not available", key->port);
                return -1;
            }
            zlog_debug(zc, "port %d already taken, find unused port", key->port);
            key->port = get_next_port();
            if (key->port == start_port) {
                zlog_error(zc, "no available ports");
                return -1;
            }
        } else {
            break;
        }
    }
    return 0;
}

void reply(int sock, int port)
{
    uint8_t buf[DP_HEADER_LEN + 2];
    write_dp_header(buf, NULL, 2);
    *(uint16_t *)(buf + DP_HEADER_LEN) = port;
    send_all(sock, buf, sizeof(buf));
    zlog_debug(zc, "sent reply %d on socket %d", port, sock);
}

static inline uint16_t get_next_port()
{
    uint16_t next = next_port;
    if (next_port == MAX_UDP_PORT)
        next_port = MIN_UDP_PORT;
    else
        next_port++;
    return next;
}

void handle_data()
{
    sockaddr_in src_si;
    sockaddr_in dst;
    uint8_t buf[DATA_BUFSIZE];

    struct msghdr msg;
    char control_buf[DSTADDR_DATASIZE];
    struct cmsghdr *cmsgptr;
    struct iovec iov[1];

    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof(buf);

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &src_si;
    msg.msg_namelen = sizeof(src_si);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control_buf;;
    msg.msg_controllen = sizeof(control_buf);

    int len = recvmsg(data_socket, &msg, 0);
    if (len < 0) {
        zlog_error(zc, "error on recvfrom: %s", strerror(errno));
        return;
    }

    for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL; cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {
        if (cmsgptr->cmsg_level == IPPROTO_IP && cmsgptr->cmsg_type == IP_PKTINFO) {
            dst.sin_addr = DSTADDR(cmsgptr);
        }
    }

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    if (sch->header_len > len || ntohs(sch->total_len) > len) {
        zlog_error(zc, "invalid SCION packet");
        return;
    }
    HostAddr from;
    memcpy(from.addr, &src_si.sin_addr, 4);
    from.addr_len = 4;
    from.port = ntohs(src_si.sin_port);
    uint8_t *l4ptr = buf;
    uint8_t l4 = get_l4_proto(&l4ptr);
    switch (l4) {
        case L4_SCMP:
            zlog_debug(zc, "incoming scmp packet for %s\n", inet_ntoa(dst.sin_addr));
            process_scmp(buf, (SCMPL4Header *)l4ptr, len, &src_si);
            break;
        case L4_SSP:
            deliver_ssp(buf, l4ptr, len, &from);
            break;
        case L4_UDP:
            deliver_udp(buf, len, &from, &dst);
            break;
    }
}

void deliver_ssp(uint8_t *buf, uint8_t *l4ptr, int len, HostAddr *from)
{
    uint8_t *dst_ptr = get_dst_addr(buf);
    int dst_len = get_dst_len(buf);
    Entry *e;
    L4Key key;
    memset(&key, 0, sizeof(key));
    key.port = ntohs(*(uint16_t *)(l4ptr + 8));
    key.isd_as = ntohl(*(uint32_t *)(dst_ptr - ISD_AS_LEN));
    memcpy(key.host, dst_ptr, dst_len);
    if (key.port != 0) {
        HASH_FIND(hh, ssp_wildcard_list, &key, sizeof(key), e);
        if (!e) {
            zlog_warn(zc, "no wildcard entry found for port %d at (%d,%d):%s",
                    key.port, ISD(key.isd_as), AS(key.isd_as), inet_ntoa(*(struct in_addr *)key.host));
            return;
        }
    } else {
        key.flow_id = be64toh(*(uint64_t *)l4ptr);
        HASH_FIND(hh, ssp_flow_list, &key, sizeof(key), e);
        if (!e) {
            zlog_warn(zc, "no flow entry found for %" PRIu64, key.flow_id);
            return;
        }
    }
    zlog_debug(zc, "incoming ssp packet for %s:%d:%" PRIu64, 
               inet_ntoa(*(struct in_addr *)dst_ptr), key.port, key.flow_id);
    send_dp_header(e->sock, from, len);
    send_all(e->sock, buf, len);
}

void deliver_udp(uint8_t *buf, int len, HostAddr *from, sockaddr_in *dst)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    uint8_t *l4ptr = buf;
    get_l4_proto(&l4ptr);
    SCIONUDPHeader *udp = (SCIONUDPHeader *)l4ptr;
    int sock;

    uint16_t checksum = scion_udp_checksum(buf);
    if (checksum != udp->checksum) {
        zlog_error(zc, "Bad UDP checksum in packet to %s. Expected:%04x Got:%04x",
                inet_ntoa(dst->sin_addr), ntohs(udp->checksum), ntohs(checksum));
        return;
    }

    if (DST_TYPE(sch) == ADDR_SVC_TYPE) {
        SVCKey svc_key;
        memset(&svc_key, 0, sizeof(SVCKey));
        svc_key.addr = ntohs(*(uint16_t *)get_dst_addr(buf));
        svc_key.isd_as = ntohl(*(uint32_t *)(get_dst_addr(buf) - ISD_AS_LEN));
        /* TODO: IPv6? */
        memcpy(svc_key.host, &dst->sin_addr.s_addr, 4);
        SVCEntry *se;
        HASH_FIND(hh, svc_list, &svc_key, sizeof(SVCKey), se);
        if (!se) {
            zlog_warn(zc, "Entry not found: ISD-AS: %d-%d SVC: %d IP: %s",
                    ISD(svc_key.isd_as), AS(svc_key.isd_as), svc_key.addr,
                    inet_ntoa(dst->sin_addr));
            return;
        }
        sock = se->sockets[rand() % se->count];
        zlog_debug(zc, "deliver UDP packet to (%d,%d):%s",
                ISD(svc_key.isd_as), AS(svc_key.isd_as), inet_ntoa(dst->sin_addr));
    } else {
        L4Key key;
        memset(&key, 0, sizeof(key));
        /* Find dst info in packet */
        key.port = ntohs(*(uint16_t *)(l4ptr + 2));
        key.isd_as = ntohl(*(uint32_t *)(get_dst_addr(buf) - ISD_AS_LEN));
        memcpy(key.host, get_dst_addr(buf), get_dst_len(buf));

        Entry *e;
        HASH_FIND(hh, udp_port_list, &key, sizeof(key), e);
        if (!e) {
            zlog_warn(zc, "entry for %s:%d not found",
                    inet_ntoa(*(struct in_addr *)(key.host)), key.port);
            return;
        }
        sock = e->sock;
    }
    send_dp_header(sock, from, len);
    send_all(sock, buf, len);
}

void process_scmp(uint8_t *buf, SCMPL4Header *scmp, int len, sockaddr_in *from)
{
    int calc_chk = scmp_checksum(buf);
    if (calc_chk != scmp->checksum) {
        zlog_error(zc, "SCMP header checksum (%x) doesn't match computed checksum (%x)\n",
                scmp->checksum, calc_chk);
        return;
    }
    if (htons(scmp->class_) == SCMP_GENERAL_CLASS && htons(scmp->type) == SCMP_ECHO_REQUEST) {
        send_scmp_echo_reply(buf, scmp, from);
    } else {
        deliver_scmp(buf, scmp, len, from);
    }
}

void send_scmp_echo_reply(uint8_t *buf, SCMPL4Header *scmp, sockaddr_in *from)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    reverse_packet(buf);
    scmp->type = htons(SCMP_ECHO_REPLY);
    update_scmp_checksum(buf);
    from->sin_port = htons(SCION_UDP_EH_DATA_PORT);
    zlog_debug(zc, "send echo reply to %s:%d\n", inet_ntoa(from->sin_addr), ntohs(from->sin_port));
    sendto(data_socket, buf, ntohs(sch->total_len), 0,
            (struct sockaddr *)from, sizeof(sockaddr_in));
}

void deliver_scmp(uint8_t *buf, SCMPL4Header *scmp, int len, sockaddr_in *from)
{
    SCMPPayload *pld;
    pld = scmp_parse_payload(scmp);
    if (pld->meta->l4_proto != L4_UDP && pld->meta->l4_proto != L4_NONE) {
        zlog_error(zc, "SCMP not supported for protocol %d\n", pld->meta->l4_proto);
        return;
    }
    SCIONCommonHeader *sch = pld->cmnhdr;
    if (SRC_TYPE(sch) == ADDR_SVC_TYPE) {
        zlog_error(zc, "SCMP does not support SVC source.\n");
        return;
    }
    L4Key key;
    memset(&key, 0, sizeof(key));
    /* Find src info in payload */
    key.port = ntohs(*(uint16_t *)(pld->l4hdr));
    key.isd_as = ntohl(*(uint32_t *)(pld->addr));
    memcpy(key.host, get_src_addr((uint8_t * )pld->cmnhdr), get_src_len((uint8_t * )pld->cmnhdr));

    Entry *e;
    HASH_FIND(hh, udp_port_list, &key, sizeof(key), e);
    if (!e) {
        zlog_error(zc, "entry for %s:%d not found\n",
                inet_ntoa(*(struct in_addr *)(key.host)), key.port);
        return;
    }
    zlog_debug(zc, "entry for %s:%d found\n",
            inet_ntoa(*(struct in_addr *)(key.host)), key.port);

    HostAddr host;
    memcpy(host.addr, &from->sin_addr.s_addr, 4);
    host.addr_len = 4;
    host.port = ntohs(from->sin_port);

    send_dp_header(e->sock, &host, len);
    send_all(e->sock, buf, len);
}

void handle_send(int index)
{
    uint8_t buf[DATA_BUFSIZE];
    int res;
    int sock = sockets[index].fd;

    /*
     * Application message format:
     * cookie (8B) | addr_len (1B) | packet_len (4B) | addr (?B) | port (2B) | msg (?B)
     * addr and port denote first hop for outgoing packets
     */
    res = recv_all(sock, buf, DP_HEADER_LEN);
    if (res <= 0) {
        cleanup_socket(sock, index, errno);
        return;
    }

    int addr_len, packet_len;
    parse_dp_header(buf, &addr_len, &packet_len);
    if (packet_len < 0 || addr_len == 0) {
        zlog_error(zc, "invalid header sent from app - Cookie: %" PRIx64, *(uint64_t *)buf);
        zlog_error(zc, "addr_len = %d, packet_len = %d", addr_len, packet_len);
        cleanup_socket(sock, index, EIO);
        return;
    }
    if (recv_all(sock, buf, addr_len + 2 + packet_len) < 0) {
        zlog_error(zc, "error reading from application");
        cleanup_socket(sock, index, errno);
        return;
    }
    // TODO: Don't assume IPv4
    struct sockaddr_in hop;
    memset(&hop, 0, sizeof(hop));
    hop.sin_family = AF_INET;
    memcpy(&hop.sin_addr, buf, addr_len);
    hop.sin_port = htons(*(uint16_t *)(buf + addr_len));
    sendto(data_socket, buf + addr_len + 2, packet_len, 0, (struct sockaddr *)&hop, sizeof(hop));
    uint8_t *l4ptr = buf + addr_len + 2;
    uint8_t l4 = get_l4_proto(&l4ptr);
    zlog_debug(zc, "packet (l4 = %d) sent to %s:%d", l4, inet_ntoa(hop.sin_addr), ntohs(hop.sin_port));
}

void cleanup_socket(int sock, int index, int err)
{
    if (err == 0)
        zlog_info(zc, "socket %d closed from remote end", sock);
    else
        zlog_error(zc, "error on socket %d: %s", sock, strerror(err));
    close(sock);
    sockets[index] = sockets[--num_sockets];
    sockets[num_sockets].fd = -1;
    sockets[num_sockets].events = 0;
    sockets[num_sockets].revents = 0;
    zlog_info(zc, "num_sockets now %d", num_sockets);

    Entry *e = NULL;
    HASH_FIND(pollhh, poll_fd_list, &sock, sizeof(sock), e);
    if (e) {
        HASH_DELETE(pollhh, poll_fd_list, e);
        HASH_DELETE(hh, *(e->list), e);
        if (e->se) {
            int i;
            for (i = 0; i < e->se->count; i++) {
                int fd = e->se->sockets[i];
                if (fd == sock) {
                    int count = e->se->count - 1;
                    e->se->sockets[i] = e->se->sockets[count];
                    e->se->sockets[count] = -1;
                    e->se->count = count;
                    zlog_info(zc, "removed socket from SVC listeners for host");
                    if (count == 0) {
                        HASH_DELETE(hh, svc_list, e->se);
                        free(e->se);
                        e->se = NULL;
                        zlog_info(zc, "no more SVC listeners on host, remove entry");
                    }
                    break;
                }
            }
        }
        free(e);
        zlog_info(zc, "deleted entry from hash table");
    }
}
