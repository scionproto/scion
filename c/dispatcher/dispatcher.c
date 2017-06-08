#define _GNU_SOURCE // required to get struct in6_pktinfo definition
//#define USE_FILTER_SOCKET // required to run filter code
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
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#include <zlog.h>
#include <uthash.h>

#include "scion/scion.h"
#include "tcp/middleware.h"

#define APP_BUFSIZE 32
#define DATA_BUFSIZE 65535

#define MAX_SVCS_PER_ADDR 10

#define MAX_BACKLOG 128
#define MAX_SOCKETS 1024
#define APP_INDEX 0
#define DATA_V4_INDEX 1
#define DATA_V6_INDEX 2

#ifdef USE_FILTER_SOCKET
#include "filter/filter.h"
#define FILTER_INDEX 3
FilterSocket *filter_socket = NULL;
#endif

#define DSTADDR_DATASIZE (CMSG_SPACE(sizeof(struct in6_pktinfo)))
#define DSTADDR(x) (((struct in_pktinfo *)CMSG_DATA(x))->ipi_addr)
#define DSTV6ADDR(x) (((struct in6_pktinfo *)CMSG_DATA(x))->ipi6_addr)

#define IS_REG_CMD(x) ((x) & 1)
#define IS_SCMP_REQ(x) (((x) >> 1) & 1)

typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr_in6 sockaddr_in6;

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
static int num_sockets;

static int data_v4_socket;
static int data_v6_socket;
static int app_socket;

static zlog_category_t *zc;

void handle_signal(int signal);
int init_tcpmw();
int run();

int create_sockets();
int set_sockopts();
int bind_app_socket();
int bind_data_sockets();

void handle_app();
void register_ssp(uint8_t *buf, int len, int sock);
void register_udp(uint8_t *buf, int len, int sock);
Entry * parse_request(uint8_t *buf, int len, int proto, int sock);
int find_available_port(Entry *list, L4Key *key);
void reply(int sock, int port);
static inline uint16_t get_next_port();

void handle_data(int v6);
void deliver_ssp(uint8_t *buf, uint8_t *l4ptr, int len, HostAddr *from);
void deliver_tcp(uint8_t *buf, int len, HostAddr *from);
void deliver_udp(uint8_t *buf, int len, HostAddr *from, HostAddr *dst);
void deliver_udp_svc(uint8_t *buf, int len, HostAddr *from, HostAddr *dst);

void process_scmp(uint8_t *buf, SCMPL4Header *scmpptr, int len, HostAddr *from);
void send_scmp_echo_reply(uint8_t *buf, SCMPL4Header *scmpptr, HostAddr *from);
void deliver_scmp(uint8_t *buf, SCMPL4Header *l4ptr, int len, HostAddr *from);

void handle_send(int index);
void cleanup_socket(int sock, int index, int err);

int send_data(uint8_t *buf, int len, HostAddr *first_hop);

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif
char socket_path[UNIX_PATH_MAX];

int main(int argc, char **argv)
{
    signal(SIGTERM, handle_signal);
    signal(SIGQUIT, handle_signal);
    signal(SIGINT, handle_signal);
    signal(SIGPIPE, handle_signal);

    int res;

    setenv("TZ", "UTC", 1);

    char *zlog_cfg = getenv("ZLOG_CFG");
    if (!zlog_cfg)
        zlog_cfg = "c/dispatcher/dispatcher.conf";
    if (zlog_init(zlog_cfg) < 0) {
        fprintf(stderr, "failed to init zlog (cfg: %s)\n", zlog_cfg);
        return -1;
    }
    zc = zlog_get_category("dispatcher");
    if (!zc) {
        fprintf(stderr, "failed to get dispatcher zlog category\n");
        zlog_fini();
        return -1;
    }

    /* TCPMW uses many open files, set limit as high as possible */
    struct rlimit rlim;
    if (getrlimit(RLIMIT_NOFILE, &rlim) < 0){
        zlog_fatal(zc, "getrlimit(): %s", strerror(errno));
        return -1;
    }
    zlog_debug(zc, "Changing RLIMIT_NOFILE %lu -> %lu", rlim.rlim_cur, rlim.rlim_max);
    rlim.rlim_cur = rlim.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &rlim) < 0){
        zlog_fatal(zc, "setrlimit(): %s", strerror(errno));
        return -1;
    }

    zlog_info(zc, "dispatcher with zlog starting up");

    if (create_sockets() < 0)
        return -1;

    if (init_tcpmw() < 0)
        return -1;

    res = run();

    /* Would only get down here if poll failed */
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
            unlink(socket_path);
            exit(0);
        default:
            zlog_info(zc, "Received signal %d", sig);
            unlink(socket_path);
            exit(1);
    }
}

int create_sockets()
{
    app_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    data_v4_socket = socket(AF_INET, SOCK_DGRAM, 0);
    data_v6_socket = socket(AF_INET6, SOCK_DGRAM, 0);
    if (app_socket < 0) {
        zlog_fatal(zc, "failed to open app socket");
        return -1;
    }
    if (data_v4_socket < 0)
        zlog_info(zc, "IPv4 not supported on this host");
    if (data_v6_socket < 0)
        zlog_info(zc, "IPv6 not supported on this host");

    if (set_sockopts() < 0) {
        zlog_fatal(zc, "failed to set socket options");
        return -1;
    }

    /* Bind app socket to SCION_DISPATCHER_ADDR */
    if (bind_app_socket() < 0)
        return -1;

    /* Bind data socket to SCION_UDP_EH_DATA_PORT */
    if (bind_data_sockets() < 0)
        return -1;

    sockets[APP_INDEX].fd = app_socket;
    sockets[APP_INDEX].events = POLLIN;
    num_sockets++;
    if (data_v4_socket > 0) {
        sockets[DATA_V4_INDEX].fd = data_v4_socket;
        sockets[DATA_V4_INDEX].events = POLLIN;
        num_sockets++;
    }
    if (data_v6_socket > 0) {
        sockets[DATA_V6_INDEX].fd = data_v6_socket;
        sockets[DATA_V6_INDEX].events = POLLIN;
        num_sockets++;
    }

    if (num_sockets < 2) {
        zlog_fatal(zc, "Could not open any IP sockets");
        return -1;
    }

#ifdef USE_FILTER_SOCKET
    filter_socket = init_filter_socket(zc);
    if (filter_socket == NULL) {
        zlog_fatal(zc, "Failed to initialize filter socket");
        return -1;
    }
    sockets[FILTER_INDEX].fd = filter_socket->sock;
    sockets[FILTER_INDEX].events = POLLIN;
    num_sockets++;
#endif

    int i;
    for (i = num_sockets; i < MAX_SOCKETS; i++) {
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
    int res = 0;
    if (data_v4_socket > 0) {
        res |= setsockopt(data_v4_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
        res |= setsockopt(data_v4_socket, IPPROTO_IP, IP_PKTINFO, &optval, sizeof(optval));
    }
    if (data_v6_socket > 0) {
        res |= setsockopt(data_v6_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
        res |= setsockopt(data_v6_socket, IPPROTO_IPV6, IPV6_RECVPKTINFO, &optval, sizeof(optval));
        res |= setsockopt(data_v6_socket, SOL_IPV6, IPV6_V6ONLY, &optval, sizeof(optval));
    }
    optval = 1 << 20;
    res |= fcntl(app_socket, F_SETFL, O_NONBLOCK);
    if (data_v4_socket > 0) {
        res |= setsockopt(data_v4_socket, SOL_SOCKET, SO_RCVBUF, &optval, sizeof(optval));
        res |= fcntl(data_v4_socket, F_SETFL, O_NONBLOCK);
    }
    if (data_v6_socket > 0) {
        res |= setsockopt(data_v6_socket, SOL_SOCKET, SO_RCVBUF, &optval, sizeof(optval));
        res |= fcntl(data_v6_socket, F_SETFL, O_NONBLOCK);
    }
    return res;
}

int bind_app_socket()
{
    struct sockaddr_un su;
    memset(&su, 0, sizeof(su));
    su.sun_family = AF_UNIX;
    char *env = getenv("DISPATCHER_ID");
    if (!env)
        env = (char *)DEFAULT_DISPATCHER_ID;
    snprintf(su.sun_path, sizeof(su.sun_path), "%s/%s.sock", DISPATCHER_DIR, env);
    strncpy(socket_path, su.sun_path, sizeof(su.sun_path));
    if (mkdir(DISPATCHER_DIR, 0755)) {
        if (errno != EEXIST) {
            zlog_fatal(zc, "failed to create dispatcher socket directory: %s", strerror(errno));
            return -1;
        }
    }
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

int bind_data_sockets()
{
    struct sockaddr_storage sa;

    if (data_v4_socket > 0) {
        sockaddr_in *sin = (sockaddr_in *)&sa;
        memset(sin, 0, sizeof(sockaddr_in));
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = INADDR_ANY;
        sin->sin_port = htons(SCION_UDP_EH_DATA_PORT);
        if (bind(data_v4_socket, (struct sockaddr *)sin, sizeof(sockaddr_in)) < 0) {
            zlog_fatal(zc, "failed to bind data socket to %s:%d, %s",
                    inet_ntoa(sin->sin_addr), ntohs(sin->sin_port), strerror(errno));
            return -1;
        }
        zlog_info(zc, "data socket bound to %s:%d", inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
    }

    if (data_v6_socket > 0) {
        sockaddr_in6 *sin6 = (sockaddr_in6 *)&sa;
        memset(sin6, 0, sizeof(sockaddr_in6));
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = in6addr_any;
        sin6->sin6_port = htons(SCION_UDP_EH_DATA_PORT);
        char str[MAX_HOST_ADDR_STR];
        inet_ntop(AF_INET6, &sin6->sin6_addr, str, 50);
        if (bind(data_v6_socket, (struct sockaddr *)sin6, sizeof(sockaddr_in6)) < 0) {
            zlog_fatal(zc, "failed to bind v6 data socket to %s : %d, %s",
                    str, ntohs(sin6->sin6_port), strerror(errno));
            return -1;
        }
        zlog_info(zc, "data v6 socket bound to %s:%d", str, ntohs(sin6->sin6_port));
    }
    return 0;
}

int init_tcpmw()
{
    pthread_t tid;
    tcp_scion_output = &send_data;
    zc_tcp = zc;
    if (pthread_create(&tid, NULL, &tcpmw_main_thread, NULL)){
        zlog_fatal(zc, "pthread_create(): %s", strerror(errno));
        return -1;
    }
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
                case DATA_V4_INDEX:
                    handle_data(0);
                    break;
                case DATA_V6_INDEX:
                    handle_data(1);
                    break;
#ifdef USE_FILTER_SOCKET
                case FILTER_INDEX:
                    handle_filter(filter_socket);
                    break;
#endif
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
     * cookie (8B) | addr_type (1B) | packet_len (4B) | addr (?B) | port (2B) | msg (?B)
     * addr and port denote first hop for outgoing packets
     * if addr_type == 0, addr and port fields are omitted (which is the case for registration messages)
     */
    int len = recv_all(sock, buf, DP_HEADER_LEN);
    if (len < 0) {
        zlog_error(zc, "error receiving registration request");
        close(sock);
        return;
    }
    int packet_len = 0;
    // Here addr_type will always be 0 and there will be no port number either
    parse_dp_header(buf, NULL, &packet_len);
    if (packet_len < 0) {
        zlog_error(zc, "invalid dispatcher header in registration packet");
        close(sock);
        return;
    }
    // addr_type is 0
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
            reply(sock, 1);
            cleanup_socket(sock, num_sockets - 1, EINVAL);
            return;
        }
        e->list = &ssp_flow_list;
        HASH_ADD(hh, ssp_flow_list, l4_key, sizeof(L4Key), e);
        zlog_info(zc, "flow registration success: %" PRIu64, e->l4_key.flow_id);
    } else {
        if (find_available_port(ssp_wildcard_list, &e->l4_key) < 0) {
            reply(sock, 0);
            cleanup_socket(sock, num_sockets - 1, EINVAL);
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
        reply(sock, 0);
        cleanup_socket(sock, num_sockets - 1, EINVAL);
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

    zlog_info(zc, "registration for isd_as %x(%d-%d)", isd_as, ISD(isd_as), AS(isd_as));

    Entry *e = (Entry *)malloc(sizeof(Entry));
    if (!e) {
        zlog_fatal(zc, "malloc failed, abandon ship");
        exit(1);
    }
    memset(e, 0, sizeof(Entry));
    e->sock = sock;

    uint8_t type = *(uint8_t *)(buf + 8);
    if (type < ADDR_IPV4_TYPE || type > ADDR_IPV6_TYPE) {
        zlog_error(zc, "Invalid address type: %d", type);
        close(sock);
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
                addr_to_str(e->l4_key.host, type, NULL), e->l4_key.port, e->l4_key.flow_id);
    } else if (proto == L4_UDP) {
        /* command (1B) | proto (1B) | isd_as (4B) | port (2B) | addr type (1B) | addr (?B) | SVC (2B, optional) */
        e->l4_key.port = port;
        e->l4_key.isd_as = isd_as;
        memcpy(e->l4_key.host, buf + common, addr_len);
        end = addr_len + common;
        zlog_info(zc, "registration for %s:%d", addr_to_str(e->l4_key.host, type, NULL), e->l4_key.port);
    } else {
        zlog_error(zc, "unsupported L4 proto %d", proto);
        close(sock);
        free(e);
        return NULL;
    }
    sockets[num_sockets].fd = sock;
    sockets[num_sockets].events = POLLIN;
    num_sockets++;
    HASH_ADD(pollhh, poll_fd_list, sock, sizeof(int), e);

    if (IS_SCMP_REQ(*buf)) {
        zlog_info(zc, "SCMP registration included");
        e->scmp = 1;
    }

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
        HASH_FIND(hh, list, key, sizeof(L4Key), old);
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
    *(uint16_t *)(buf + DP_HEADER_LEN) = htons(port);
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

void handle_data(int v6)
{
    struct sockaddr_storage src;
    HostAddr dst;
    uint8_t buf[DATA_BUFSIZE];

    struct msghdr msg;
    char control_buf[DSTADDR_DATASIZE];
    struct cmsghdr *cmsgptr;
    struct iovec iov[1];

    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof(buf);

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &src;
    msg.msg_namelen = sizeof(src);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control_buf;;
    msg.msg_controllen = sizeof(control_buf);

    int sock = v6 ? data_v6_socket : data_v4_socket;
    int len = recvmsg(sock, &msg, 0);
    if (len < 0) {
        zlog_error(zc, "error on recvmsg: %s", strerror(errno));
        return;
    }

    for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL; cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {
        if (cmsgptr->cmsg_level == IPPROTO_IP && cmsgptr->cmsg_type == IP_PKTINFO) {
            dst.addr_type = ADDR_IPV4_TYPE;
            memcpy(dst.addr, &(DSTADDR(cmsgptr)), ADDR_IPV4_LEN);
        }
        if (cmsgptr->cmsg_level == IPPROTO_IPV6 && cmsgptr->cmsg_type == IPV6_PKTINFO) {
            dst.addr_type = ADDR_IPV6_TYPE;
            memcpy(dst.addr, &(DSTV6ADDR(cmsgptr)), ADDR_IPV6_LEN);
        }
    }

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    if (sch->header_len > len || ntohs(sch->total_len) > len) {
        zlog_error(zc, "invalid SCION packet");
        return;
    }
    HostAddr from;
    if (v6) {
        sockaddr_in6 *sin6 = (sockaddr_in6 *)&src;
        memcpy(from.addr, &sin6->sin6_addr, ADDR_IPV6_LEN);
        from.addr_type = ADDR_IPV6_TYPE;
        from.port = ntohs(sin6->sin6_port);
    } else {
        sockaddr_in *sin = (sockaddr_in *)&src;
        memcpy(from.addr, &sin->sin_addr, ADDR_IPV4_LEN);
        from.addr_type = ADDR_IPV4_TYPE;
        from.port = ntohs(sin->sin_port);
    }
    uint8_t *l4ptr = buf;
    uint8_t l4 = get_l4_proto(&l4ptr);

#ifdef USE_FILTER_SOCKET
    SCIONAddr s_hop;
    s_hop.isd_as = get_dst_isd_as(buf);
    memcpy(&s_hop.host, &from, sizeof(HostAddr));
    if (is_blocked_by_filter(filter_socket, buf, &s_hop, EGRESS)) {
        zlog_debug(zc, "filtered packet at handle data");
        return;
    }
#endif

    switch (l4) {
        case L4_SCMP:
            process_scmp(buf, (SCMPL4Header *)l4ptr, len, &from);
            break;
        case L4_SSP:
            deliver_ssp(buf, l4ptr, len, &from);
            break;
        case L4_UDP:
            deliver_udp(buf, len, &from, &dst);
            break;
        case L4_TCP:
            deliver_tcp(buf, len, &from);
            break;
    }
}

void deliver_ssp(uint8_t *buf, uint8_t *l4ptr, int len, HostAddr *from)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    uint8_t *dst_ptr = get_dst_addr(buf);
    int dst_len = get_dst_len(buf);
    uint8_t dst_type = DST_TYPE(sch);
    Entry *e;
    L4Key key;
    memset(&key, 0, sizeof(key));
    key.port = ntohs(*(uint16_t *)(l4ptr + 8));
    key.isd_as = get_dst_isd_as(buf);
    memcpy(key.host, dst_ptr, dst_len);
    if (key.port != 0) {
        HASH_FIND(hh, ssp_wildcard_list, &key, sizeof(key), e);
        if (!e) {
            zlog_warn(zc, "no wildcard entry found for port %d at (%d-%d):%s",
                    key.port, ISD(key.isd_as), AS(key.isd_as), addr_to_str(key.host, dst_type, NULL));
            return;
        }
    } else {
        key.flow_id = be64toh(*(uint64_t *)l4ptr);
        HASH_FIND(hh, ssp_flow_list, &key, sizeof(key), e);
        if (!e) {
            zlog_warn(zc, "no flow entry found for (%d-%d):%s:%" PRIu64,
                    ISD(key.isd_as), AS(key.isd_as), addr_to_str(key.host, dst_type, NULL), key.flow_id);
            return;
        }
    }
    zlog_debug(zc, "incoming ssp packet for %s:%d:%" PRIu64,
               addr_to_str(dst_ptr, dst_type, NULL), key.port, key.flow_id);
    send_dp_header(e->sock, from, len);
    send_all(e->sock, buf, len);
}

void deliver_udp(uint8_t *buf, int len, HostAddr *from, HostAddr *dst)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    uint8_t *l4ptr = buf;
    get_l4_proto(&l4ptr);
    SCIONUDPHeader *udp = (SCIONUDPHeader *)l4ptr;
    int sock;

    uint16_t checksum = scion_udp_checksum(buf);
    if (checksum != udp->checksum) {
        zlog_error(zc, "Bad UDP checksum in packet to %s. Expected:%04x Got:%04x",
                addr_to_str(dst->addr, dst->addr_type, NULL), ntohs(udp->checksum), ntohs(checksum));
        return;
    }

    if (DST_TYPE(sch) == ADDR_SVC_TYPE) {
        deliver_udp_svc(buf, len, from, dst);
        return;
    }
    L4Key key;
    memset(&key, 0, sizeof(key));
    /* Find dst info in packet */
    key.port = ntohs(*(uint16_t *)(l4ptr + 2));
    key.isd_as = get_dst_isd_as(buf);
    memcpy(key.host, get_dst_addr(buf), get_dst_len(buf));

    Entry *e;
    HASH_FIND(hh, udp_port_list, &key, sizeof(key), e);
    if (!e) {
        zlog_warn(zc, "entry for (%d-%d):%s:%d not found",
                ISD(key.isd_as), AS(key.isd_as),
                addr_to_str(key.host, DST_TYPE(sch), NULL), key.port);
        return;
    }
    sock = e->sock;
    send_dp_header(sock, from, len);
    send_all(sock, buf, len);
}

void deliver_udp_svc(uint8_t *buf, int len, HostAddr *from, HostAddr *dst) {
    int sock;
    SVCKey svc_key;
    memset(&svc_key, 0, sizeof(SVCKey));
    uint16_t addr = ntohs(*(uint16_t *)get_dst_addr(buf));
    svc_key.addr = addr & ~SVC_MULTICAST;  // Mask off top multicast bit
    svc_key.isd_as = get_dst_isd_as(buf);
    memcpy(svc_key.host, dst->addr, get_addr_len(dst->addr_type));
    SVCEntry *se;
    HASH_FIND(hh, svc_list, &svc_key, sizeof(SVCKey), se);
    if (!se) {
        zlog_warn(zc, "Entry not found: ISD-AS: %d-%d SVC: %02x IP: %s",
                ISD(svc_key.isd_as), AS(svc_key.isd_as), svc_key.addr,
                addr_to_str(dst->addr, dst->addr_type, NULL));
        return;
    }
    char dststr[MAX_HOST_ADDR_STR];
    char svcstr[MAX_HOST_ADDR_STR];
    zlog_debug(zc, "deliver UDP packet to (%d-%d):%s SVC:%s",
            ISD(svc_key.isd_as), AS(svc_key.isd_as),
            addr_to_str(dst->addr, dst->addr_type, dststr),
            addr_to_str(get_dst_addr(buf), ADDR_SVC_TYPE, svcstr));
    if (!(addr & SVC_MULTICAST)) {  // Anycast SVC address
        sock = se->sockets[rand() % se->count];
        send_dp_header(sock, from, len);
        send_all(sock, buf, len);
        return;
    }
    // Multicast SVC address
    int i;
    for (i = 0; i < se->count; i++) {
        sock = se->sockets[i];
        send_dp_header(sock, from, len);
        send_all(sock, buf, len);
    }
}

void deliver_tcp(uint8_t *buf, int len, HostAddr *from)
{
    /* Allocate buffer for LWIP's processing. */
    struct pbuf *p = pbuf_alloc(PBUF_RAW, sizeof(HostAddr) + len, PBUF_RAM);
    memcpy(p->payload, from, sizeof(HostAddr));
    memcpy(p->payload + sizeof(HostAddr), buf, len);
    /* Put [from (HostAddr) || raw_spkt] to the TCP queue. */
    tcpip_input(p, (struct netif *)NULL);
}

void process_scmp(uint8_t *buf, SCMPL4Header *scmp, int len, HostAddr *from)
{
    int calc_chk = scmp_checksum(buf);
    if (calc_chk != scmp->checksum) {
        zlog_error(zc, "SCMP header checksum (%x) doesn't match computed checksum (%x)",
                ntohs(scmp->checksum), ntohs(calc_chk));
        return;
    }
    if (ntohs(scmp->class_) == SCMP_GENERAL_CLASS)  {
        if (ntohs(scmp->type) == SCMP_ECHO_REQUEST) {
            send_scmp_echo_reply(buf, scmp, from);
            return;
        } /*
            TODO(kormat): not implemented yet. Needs a hashmap so map SCMP echo IDs to programs

            else if (ntohs(scmp->type) == SCMP_ECHO_REPLY) {
            deliver_scmp_echo_reply(buf, scmp, from);
            return;
        }
        */
    }
    deliver_scmp(buf, scmp, len, from);
}

void send_scmp_echo_reply(uint8_t *buf, SCMPL4Header *scmp, HostAddr *from)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    reverse_packet(buf);
    scmp->type = htons(SCMP_ECHO_REPLY);
    update_scmp_checksum(buf);
    zlog_debug(zc, "send echo reply to %s:%d", addr_to_str(from->addr, from->addr_type, NULL), ntohs(from->port));
    send_data(buf, ntohs(sch->total_len), from);
}

void deliver_scmp(uint8_t *buf, SCMPL4Header *scmp, int len, HostAddr *from)
{
    SCMPPayload *pld;
    pld = scmp_parse_payload(scmp);
    if (pld->meta->l4_proto != L4_UDP && pld->meta->l4_proto != L4_SSP &&
            pld->meta->l4_proto != L4_NONE) {
        zlog_error(zc, "SCMP not supported for protocol %d", pld->meta->l4_proto);
        return;
    }
    SCIONCommonHeader *sch = pld->cmnhdr;
    if (sch == NULL) {
        zlog_info(zc, "SCMP payload has no common header snippet, ignoring");
        return;
    }
    if (SRC_TYPE(sch) == ADDR_SVC_TYPE) {
        zlog_error(zc, "SCMP does not support SVC source.");
        return;
    }

    Entry *e;
    L4Key key;
    memset(&key, 0, sizeof(key));
    key.isd_as = ntohl(*(uint32_t *)(pld->addr + ISD_AS_LEN));
    memcpy(key.host, get_src_addr((uint8_t * )pld->cmnhdr), get_src_len((uint8_t * )pld->cmnhdr));
    if (pld->meta->l4_proto == L4_SSP) {
        // reverse direction bit in flow id as this is a packet returned to sender
        key.flow_id = be64toh(*(uint64_t *)(pld->l4hdr)) ^ 1;
        HASH_FIND(hh, ssp_flow_list, &key, sizeof(key), e);
        if (!e) {
            zlog_error(zc, "SCMP entry for %d-%d %s:%" PRIu64 " not found",
                    ISD(key.isd_as), AS(key.isd_as),
                    addr_to_str(key.host, DST_TYPE((SCIONCommonHeader *)buf), NULL), key.flow_id);
            return;
        }
        zlog_debug(zc, "SCMP entry for %d-%d %s:%" PRIu64 " found",
                ISD(key.isd_as), AS(key.isd_as),
                addr_to_str(key.host, DST_TYPE((SCIONCommonHeader *)buf), NULL), key.flow_id);
    } else {
        /* Find src info in payload */
        key.port = ntohs(*(uint16_t *)(pld->l4hdr));
        HASH_FIND(hh, udp_port_list, &key, sizeof(key), e);
        if (!e) {
            zlog_info(zc, "SCMP entry for %d-%d %s:%d not found",
                    ISD(key.isd_as), AS(key.isd_as),
                    addr_to_str(key.host, DST_TYPE((SCIONCommonHeader *)buf), NULL), key.port);
            return;
        }
        zlog_debug(zc, "SCMP entry %d-%d for %s:%d found",
                ISD(key.isd_as), AS(key.isd_as),
                addr_to_str(key.host, DST_TYPE((SCIONCommonHeader *)buf), NULL), key.port);
    }

    send_dp_header(e->sock, from, len);
    send_all(e->sock, buf, len);
}

void handle_send(int index)
{
    uint8_t buf[DATA_BUFSIZE];
    int res;
    int sock = sockets[index].fd;

    /*
     * Application message format:
     * cookie (8B) | addr_type (1B) | packet_len (4B) | addr (?B) | port (2B) | msg (?B)
     * addr and port denote first hop for outgoing packets
     */
    res = recv_all(sock, buf, DP_HEADER_LEN);
    if (res <= 0) {
        cleanup_socket(sock, index, errno);
        return;
    }

    uint8_t addr_type;
    int packet_len;
    parse_dp_header(buf, &addr_type, &packet_len);
    if (packet_len < 0 || addr_type == 0) {
        zlog_error(zc, "invalid header sent from app - Cookie: %" PRIx64, *(uint64_t *)buf);
        zlog_error(zc, "addr_type = %d, packet_len = %d", addr_type, packet_len);
        cleanup_socket(sock, index, EIO);
        return;
    }
    int addr_len = get_addr_len(addr_type);
    if (recv_all(sock, buf, addr_len + 2 + packet_len) < 0) {
        zlog_error(zc, "error reading from application");
        cleanup_socket(sock, index, errno);
        return;
    }
    HostAddr hop;
    memset(&hop, 0, sizeof(hop));
    hop.addr_type = addr_type;
    memcpy(hop.addr, buf, addr_len);
    hop.port = ntohs(*(uint16_t *)(buf + addr_len));

#ifdef USE_FILTER_SOCKET
    SCIONAddr s_hop;
    s_hop.isd_as = get_src_isd_as(buf + addr_len + 2);
    memcpy(&s_hop.host, &hop, sizeof(HostAddr));
    if (is_blocked_by_filter(filter_socket, buf + addr_len + 2, &s_hop, INGRESS)) {
        zlog_debug(zc, "filtered packet at handle send");
        return;
    }
#endif

    send_data(buf + addr_len + 2, packet_len, &hop);
    uint8_t *l4ptr = buf + addr_len + 2;
    uint8_t l4 = get_l4_proto(&l4ptr);
    zlog_debug(zc, "%d byte packet (l4 = %d) sent to %s:%d",
            packet_len, l4, addr_to_str(hop.addr, hop.addr_type, NULL), hop.port);
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
        if (e->list)
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

int send_data(uint8_t *buf, int len, HostAddr *first_hop)
{
    int ret = 0;
    errno = 0;
    if (first_hop->addr_type == ADDR_IPV4_TYPE) {
        sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(first_hop->port);
        memcpy(&sa.sin_addr, first_hop->addr, ADDR_IPV4_LEN);
        ret = sendto(data_v4_socket, buf, len, 0, (struct sockaddr *)&sa, sizeof(sa));
    } else if (first_hop->addr_type == ADDR_IPV6_TYPE) {
        sockaddr_in6 sa6;
        memset(&sa6, 0, sizeof(sa6));
        sa6.sin6_family = AF_INET6;
        sa6.sin6_port = htons(first_hop->port);
        memcpy(&sa6.sin6_addr, first_hop->addr, ADDR_IPV6_LEN);
        ret = sendto(data_v6_socket, buf, len, 0, (struct sockaddr *)&sa6, sizeof(sa6));
    } else {
        zlog_error(zc, "Unsupported first hop address type %d", first_hop->addr_type);
        errno = EINVAL;
        ret = -1;
    }
    return ret;
}
