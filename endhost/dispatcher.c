#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "zlog.h"

#include "scion.h"
#include "uthash.h"

#define APP_BUFSIZE 32
#define DATA_BUFSIZE 65535

#define MAX_SVCS_PER_ADDR 10

#define DSTADDR_DATASIZE (CMSG_SPACE(sizeof(struct in_pktinfo)))
#define DSTADDR(x) (((struct in_pktinfo *)CMSG_DATA(x))->ipi_addr)

#define IS_REG_CMD(x) ((x) & 1)
#define IS_SCMP_REQ(x) (((x) >> 1) & 1)

typedef struct sockaddr_in sockaddr_in;

typedef struct {
    uint16_t port;
    uint32_t isd_as;
    uint64_t flow_id;
    uint8_t host[MAX_HOST_ADDR_LEN];
} SSPKey;

typedef struct {
    uint16_t port;
    uint32_t isd_as;
    uint8_t host[MAX_HOST_ADDR_LEN];
} UDPKey;

typedef struct {
    uint16_t addr;
    uint32_t isd_as;
    uint8_t host[MAX_HOST_ADDR_LEN];
} SVCKey;

typedef struct {
    sockaddr_in addr;
    UDPKey udp_key;
    SSPKey ssp_key;
    UT_hash_handle hh;
    uint8_t scmp;
} Entry;

typedef struct {
    SVCKey key;
    sockaddr_in addrs[MAX_SVCS_PER_ADDR];
    int count;
    UT_hash_handle hh;
} SVCEntry;

Entry *SSPFlows = NULL;
Entry *SSPWildcards = NULL;
Entry *UDPPorts = NULL;

SVCEntry *SVCEntries = NULL;

static int data_socket;
static int app_socket;

static zlog_category_t *zc;

int create_sockets();

void handle_app();
void register_ssp(uint8_t *buf, int len, sockaddr_in *addr);
void register_udp(uint8_t *buf, int len, sockaddr_in *addr);
Entry * parse_request(uint8_t *buf, int len, int proto, sockaddr_in *addr);
void reply(char code, sockaddr_in *addr);

void handle_data();
void deliver_ssp(uint8_t *buf, uint8_t *l4ptr, int len, sockaddr_in *addr);
void deliver_udp(uint8_t *buf, int len, sockaddr_in *from, sockaddr_in *dst);

void process_scmp(uint8_t *buf, SCMPL4Header *scmpptr, int len, sockaddr_in *from);
void send_scmp_echo_reply(uint8_t *buf, SCMPL4Header *scmpptr, sockaddr_in *from);
void deliver_scmp(uint8_t *buf, SCMPL4Header *l4ptr, int len, sockaddr_in *from);

int main(int argc, char **argv)
{
    int res;

    setenv("TZ", "UTC", 1);

    res = zlog_init("endhost/dispatcher.conf");
    if (res < 0) {
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

    fd_set fds;
    FD_ZERO(&fds);
    while (1) {
        int max = data_socket > app_socket ? data_socket : app_socket;
        FD_SET(data_socket, &fds);
        FD_SET(app_socket, &fds);
        res = select(max + 1, &fds, NULL, NULL, NULL);
        if (res < 0) {
            zlog_fatal(zc, "select error: %s", strerror(errno));
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
    zlog_fini();
    return res;
}

int create_sockets()
{
    int res;
    data_socket = socket(PF_INET, SOCK_DGRAM, 0);
    app_socket = socket(PF_INET, SOCK_DGRAM, 0);
    if (data_socket < 0 || app_socket < 0) {
        zlog_fatal(zc, "failed to open sockets");
        return -1;
    }
    int optval = 1;
    /*
     * FIXME(kormat): This should go away once the dispatcher and the router no
     * longer try binding to the same socket.
     */
    res = setsockopt(data_socket, SOL_SOCKET, SO_REUSEADDR,
            &optval, sizeof(optval));
    res |= setsockopt(data_socket, IPPROTO_IP, IP_PKTINFO, &optval, sizeof(optval));
    res |= setsockopt(app_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    optval = 1 << 20;
    res |= setsockopt(data_socket, SOL_SOCKET, SO_RCVBUF, &optval, sizeof(optval));
    if (res < 0) {
        zlog_fatal(zc, "failed to set socket options");
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
        zlog_fatal(zc, "failed to bind data socket to %s:%d",
                inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
        return -1;
    }
    zlog_info(zc, "data socket bound to %s:%d", inet_ntoa(sa.sin_addr), SCION_UDP_EH_DATA_PORT);

    /* Bind app socket to SCION_DISPATCHER_PORT */
    sa.sin_port = htons(SCION_DISPATCHER_PORT);
    sa.sin_addr.s_addr = inet_addr(SCION_DISPATCHER_HOST);
    res = bind(app_socket, (struct sockaddr *)&sa, sizeof(sa));
    if (res < 0) {
        zlog_fatal(zc, "failed to bind app socket to %s:%d",
                inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
        return -1;
    }
    zlog_info(zc, "app socket bound to %s:%d", inet_ntoa(sa.sin_addr), SCION_DISPATCHER_PORT);
    return 0;
}

void handle_app()
{
    sockaddr_in addr;
    socklen_t addrLen = sizeof(addr);
    uint8_t buf[APP_BUFSIZE];
    int len = recvfrom(app_socket, buf, APP_BUFSIZE, 0,
            (struct sockaddr *)&addr, &addrLen);
    if (len > 2) { /* command (1B) | proto (1B) | id */
        unsigned char protocol = buf[1];
        zlog_info(zc, "received registration for proto: %d (%d bytes)", protocol, len);
        switch (protocol) {
            case L4_SSP:
                register_ssp(buf, len, &addr);
                break;
            case L4_UDP:
                register_udp(buf, len, &addr);
                break;
        }
    }
}

void register_ssp(uint8_t *buf, int len, sockaddr_in *addr)
{
    zlog_info(zc, "SSP registration request");
    uint8_t cmd = *buf; /* 0 = unregister, 1 = register */
    Entry *e = parse_request(buf, len, L4_SSP, addr);
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
            zlog_debug(zc, "entry for flow %" PRIu64 " deleted", e->ssp_key.flow_id);
        }
        /* If command is "register", add new entry */
        if (IS_REG_CMD(cmd)) {
            HASH_ADD(hh, SSPFlows, ssp_key, sizeof(SSPKey), e);
            zlog_info(zc, "flow registration success: %" PRIu64, e->ssp_key.flow_id);
        }
    } else {
        /* Find registered wildcard port */
        HASH_FIND(hh, SSPWildcards, &e->ssp_key, sizeof(SSPKey), old);
        if (old) {
            /* Delete obsolete entry - this also serves as unregister */
            HASH_DELETE(hh, SSPWildcards, old);
            free(old);
            zlog_debug(zc, "entry for port %d deleted", e->ssp_key.port);
        }
        /* If command is "register", add new entry */
        if (IS_REG_CMD(cmd)) {
            HASH_ADD(hh, SSPWildcards, ssp_key, sizeof(SSPKey), e);
            zlog_info(zc, "wildcard registration success: %d", e->ssp_key.port);
        }
    }
    reply(1, addr);
}

void register_udp(uint8_t *buf, int len, sockaddr_in *addr)
{
    zlog_info(zc, "UDP registration request");

    uint8_t cmd = *buf; /* 0 = unregister, 1 = register */
    Entry *e = parse_request(buf, len, L4_UDP, addr);
    if (!e)
        return;
    Entry *old = NULL;
    HASH_FIND(hh, UDPPorts, &e->udp_key, sizeof(UDPKey), old);
    if (old) {
        /* Delete obsolete entry - this also serves as unregister */
        HASH_DELETE(hh, UDPPorts, old);
        free(old);
    }
    /* If command is "register", add new entry */
    if (IS_REG_CMD(cmd))
        HASH_ADD(hh, UDPPorts, udp_key, sizeof(UDPKey), e);
    reply(1, addr);
}

Entry * parse_request(uint8_t *buf, int len, int proto, sockaddr_in *addr)
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
    e->addr = *addr;

    uint8_t type = *(uint8_t *)(buf + 8);
    if (type < ADDR_IPV4_TYPE || type > ADDR_IPV6_TYPE) {
        zlog_error(zc, "Invalid address type: %d", type);
        return NULL;
    }

    SVCKey svc_key;
    memset(&svc_key, 0, sizeof(SVCKey));

    int ADDR_LENS[] = {4, 16, 2};
    int addr_len = ADDR_LENS[type - 1];
    int end;

    if (proto == L4_SSP) {
    /* command (1B) | proto (1B) | isd_as (4B) | port (2B) | addr type (1B) | flow ID (8B) | addr (?B) | SVC (2B, optional) */
        e->ssp_key.flow_id = *(uint64_t *)(buf + common);
        e->ssp_key.port = port;
        e->ssp_key.isd_as = isd_as;
        memcpy(e->ssp_key.host, buf + common + 8, addr_len);
        end = addr_len + common + 8;
    } else if (proto == L4_UDP) {
    /* command (1B) | proto (1B) | isd_as (4B) | port (2B) | addr type (1B) | addr (?B) | SVC (2B, optional) */
        e->udp_key.port = port;
        e->udp_key.isd_as = isd_as;
        memcpy(e->udp_key.host, buf + common, addr_len);
        end = addr_len + common;
        sockaddr_in reg_addr;
        memcpy(&reg_addr.sin_addr, e->udp_key.host, addr_len);
        zlog_info(zc, "registration for %s:%d", inet_ntoa(reg_addr.sin_addr), e->udp_key.port);
    }
    if (IS_SCMP_REQ(*buf))
        e->scmp = 1;

    if (len > end) {
        memcpy(svc_key.host, buf + end - addr_len, addr_len);
        svc_key.addr = ntohs(*(uint16_t *)(buf + end));
        svc_key.isd_as = isd_as;
        zlog_info(zc, "SVC (%d) registration included", svc_key.addr);
        SVCEntry *se;
        HASH_FIND(hh, SVCEntries, &svc_key, sizeof(svc_key), se);
        if (se) {
            if (se->count < MAX_SVCS_PER_ADDR)
                se->addrs[se->count++] = *addr;
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
            se->addrs[se->count++] = *addr;
            HASH_ADD(hh, SVCEntries, key, sizeof(SVCKey), se);
        }
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
    sockaddr_in dst;
    uint8_t buf[DATA_BUFSIZE];

    struct msghdr msg;
    char control_buf[DSTADDR_DATASIZE];
    struct cmsghdr *cmsgptr;
    struct iovec iov[1];

    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof(buf);

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &from;
    msg.msg_namelen = sizeof(from);
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
    uint8_t *l4ptr = buf;
    uint8_t l4 = get_l4_proto(&l4ptr);
    switch (l4) {
        case L4_SCMP:
            fprintf(stderr, "incoming scmp packet for %s\n", inet_ntoa(dst.sin_addr));
            process_scmp(buf, (SCMPL4Header *)l4ptr, len, &from);
            break;
        case L4_SSP:
            deliver_ssp(buf, l4ptr, len, &from);
            break;
        case L4_UDP:
            deliver_udp(buf, len, &from, &dst);
            break;
    }
}

void deliver_ssp(uint8_t *buf, uint8_t *l4ptr, int len, sockaddr_in *addr)
{
    uint8_t *dst_ptr = get_dst_addr(buf);
    int dst_len = get_dst_len(buf);
    Entry *e;
    SSPKey key;
    memset(&key, 0, sizeof(key));
    key.flow_id = be64toh(*(uint64_t *)l4ptr);
    key.port = 0;
    key.isd_as = ntohl(*(uint32_t *)(get_dst_addr(buf) - ISD_AS_LEN));
    memcpy(key.host, dst_ptr, dst_len);
    HASH_FIND(hh, SSPFlows, &key, sizeof(key), e);
    if (!e) {
        zlog_warn(zc, "no flow entry found for %" PRIu64, key.flow_id);
        key.flow_id = 0;
        key.port = ntohs(*(uint16_t *)(l4ptr + 8));
        HASH_FIND(hh, SSPWildcards, &key, sizeof(key), e);
        if (!e) {
            zlog_warn(zc, "no wildcard entry found for %d", key.port);
            return;
        }
    }
    socklen_t addrLen = sizeof(sockaddr_in);
    /* Append real first hop sender addr to end of message (needed by socket) */
    memcpy(buf + len, addr, addrLen);
    sendto(app_socket, buf, len + addrLen, 0,
            (struct sockaddr *)&e->addr, addrLen);
}

void deliver_udp(uint8_t *buf, int len, sockaddr_in *from, sockaddr_in *dst)
{
    sockaddr_in addr;
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    uint8_t *l4ptr = buf;
    get_l4_proto(&l4ptr);
    SCIONUDPHeader *udp = (SCIONUDPHeader *)l4ptr;

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
        HASH_FIND(hh, SVCEntries, &svc_key, sizeof(SVCKey), se);
        if (!se) {
            zlog_warn(zc, "Entry not found: ISD-AS: %d-%d SVC: %d IP: %s",
                    ISD(svc_key.isd_as), AS(svc_key.isd_as), svc_key.addr,
                    inet_ntoa(dst->sin_addr));
            return;
        }
        addr = se->addrs[random() % se->count];
    } else {
        UDPKey key;
        memset(&key, 0, sizeof(key));
        /* Find dst info in packet */
        key.port = ntohs(*(uint16_t *)(l4ptr + 2));
        key.isd_as = ntohl(*(uint32_t *)(get_dst_addr(buf) - ISD_AS_LEN));
        memcpy(key.host, get_dst_addr(buf), get_dst_len(buf));

        Entry *e;
        HASH_FIND(hh, UDPPorts, &key, sizeof(key), e);
        if (!e) {
            zlog_warn(zc, "entry for %s:%d not found\n",
                    inet_ntoa(*(struct in_addr *)(key.host)), key.port);
            return;
        }
        addr = e->addr;
    }
    socklen_t addrLen = sizeof(sockaddr_in);
    /* Append real first hop sender addr to end of message (needed by socket) */
    memcpy(buf + len, from, addrLen);
    sendto(app_socket, buf, len + addrLen, 0,
            (struct sockaddr *)&addr, addrLen);
}

void process_scmp(uint8_t *buf, SCMPL4Header *scmp, int len, sockaddr_in *from)
{
    int calc_chk = scmp_checksum(buf);
    if (calc_chk != scmp->checksum) {
        fprintf(stderr, "SCMP header checksum (%x) doesn't match computed checksum (%x)\n",
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
    fprintf(stderr, "send echo reply to %s:%d\n", inet_ntoa(from->sin_addr), ntohs(from->sin_port));
    sendto(data_socket, buf, ntohs(sch->total_len), 0,
            (struct sockaddr *)from, sizeof(sockaddr_in));
}

void deliver_scmp(uint8_t *buf, SCMPL4Header *scmp, int len, sockaddr_in *from)
{
    int addrlen = sizeof(sockaddr_in);
    memcpy(buf + len, from, addrlen);
    SCMPPayload *pld;
    pld = scmp_parse_payload(scmp);
    if (pld->meta->l4_proto != L4_UDP && pld->meta->l4_proto != L4_NONE) {
        fprintf(stderr, "SCMP not supported for protocol %d\n", pld->meta->l4_proto);
        return;
    }
    SCIONCommonHeader *sch = pld->cmnhdr;
    if (SRC_TYPE(sch) == ADDR_SVC_TYPE) {
        fprintf(stderr, "SCMP does not support SVC source.\n");
        return;
    }
    UDPKey key;
    memset(&key, 0, sizeof(key));
    /* Find src info in payload */
    key.port = ntohs(*(uint16_t *)(pld->l4hdr));
    key.isd_as = ntohl(*(uint32_t *)(pld->addr));
    memcpy(key.host, get_src_addr((uint8_t * )pld->cmnhdr), get_src_len((uint8_t * )pld->cmnhdr));

    Entry *e;
    HASH_FIND(hh, UDPPorts, &key, sizeof(key), e);
    if (!e) {
        fprintf(stderr, "entry for %s:%d not found\n",
                inet_ntoa(*(struct in_addr *)(key.host)), key.port);
        return;
    }
    fprintf(stderr, "entry for %s:%d found\n",
            inet_ntoa(*(struct in_addr *)(key.host)), key.port);
    sockaddr_in addr;
    addr = e->addr;
    socklen_t addrLen = sizeof(sockaddr_in);
    /* Append real first hop sender addr to end of message (needed by socket) */
    memcpy(buf + len, from, addrLen);
    sendto(app_socket, buf, len + addrLen, 0,
            (struct sockaddr *)&addr, addrLen);
}
