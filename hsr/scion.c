#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <rte_common.h>
#include <rte_vect.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>

#include "cJSON/cJSON.h"
#include "scion.h"
#include "libdpdk.h"
#include "lib/aesni.h"

#define RTE_LOGTYPE_HSR RTE_LOGTYPE_USER2
//#define RTE_LOG_LEVEL RTE_LOG_INFO
#define RTE_LOG_LEVEL RTE_LOG_DEBUG
#define VERIFY_OF

#define LOCAL_NETWORK_ADDRESS IPv4(10, 56, 0, 0)
#define GET_EDGE_ROUTER_IPADDR(IFID)                                           \
  rte_cpu_to_be_32((LOCAL_NETWORK_ADDRESS | IFID))

#define MAX_NUM_ROUTER 16
#define MAX_NUM_BEACON_SERVERS 10
#define MAX_NUM_PATH_SERVERS 10
#define MAX_NUM_CERT_SERVERS 10
#define MAX_NUM_DNS_SERVERS 10
#define MAX_IFID (2 << 12)

/// definition of functions
int l2fwd_send_packet(struct rte_mbuf *m, uint8_t port);
static inline int send_packet(struct rte_mbuf *m, uint8_t port);

static inline void deliver(struct rte_mbuf *m, uint32_t pclass,
                           uint8_t dpdk_rx_port);
static inline void forward_packet(struct rte_mbuf *m, uint32_t from_local_ad,
                                  uint8_t dpdk_rx_port);
static inline void egress_normal_forward(struct rte_mbuf *m,
                                         uint8_t dpdk_rx_port);

static inline void handle_ingress_xovr(struct rte_mbuf *m,
                                       uint8_t dpdk_rx_port);
static inline void ingress_shortcut_xovr(struct rte_mbuf *m,
                                         uint8_t dpdk_rx_port);
static inline void ingress_peer_xovr(struct rte_mbuf *m, uint8_t dpdk_rx_port);
static inline void ingress_core_xovr(struct rte_mbuf *m, uint8_t dpdk_rx_port);

static inline void handle_egress_xovr(struct rte_mbuf *m, uint8_t dpdk_rx_port);
static inline void egress_shortcut_xovr(struct rte_mbuf *m,
                                        uint8_t dpdk_rx_port);
static inline void egress_peer_xovr(struct rte_mbuf *m, uint8_t dpdk_rx_port);
static inline void egress_core_xovr(struct rte_mbuf *m, uint8_t dpdk_rx_port);

uint32_t beacon_servers[MAX_NUM_BEACON_SERVERS];
int beacon_server_count;
uint32_t certificate_servers[MAX_NUM_CERT_SERVERS];
int cert_server_count;
uint32_t path_servers[MAX_NUM_PATH_SERVERS];
int path_server_count;
uint32_t dns_servers[MAX_NUM_DNS_SERVERS];
int dns_server_count;

#define SERVER_MAC_ADDRESS
#ifdef SERVER_MAC_ADDRESS // in case that this router is directly connected with
                          // servers.
struct ether_addr ether_addr_beacon_servers[MAX_NUM_BEACON_SERVERS];
struct ether_addr ether_addr_certificate_servers[MAX_NUM_CERT_SERVERS];
struct ether_addr ether_addr_path_servers[MAX_NUM_PATH_SERVERS];
struct ether_addr ether_addr_dns_servers[MAX_NUM_DNS_SERVERS];

struct ether_addr ifid2ethaddr[MAX_IFID];
#endif

#define MAX_DPDK_PORT 16
struct port_map {
  uint8_t egress;
  uint8_t local;
} port_map[MAX_DPDK_PORT];

uint32_t neighbor_ip[MAX_DPDK_PORT]; // IP address of a neighbor AD router.
struct ether_addr
    neighbor_mac[MAX_DPDK_PORT]; // MAC addresses of neighbor routers.
struct ether_addr
    internal_router_mac[MAX_DPDK_PORT]; // MAC addresses of internal routers.

uint16_t my_ifid[MAX_DPDK_PORT];      // the current router's IFID
uint32_t interface_ip[MAX_DPDK_PORT]; // current router IP address (TODO: IPv6)
uint32_t internal_ip[MAX_DPDK_PORT];  // current router IP address (TODO: IPv6)

int my_isd; // ISD ID of this router
int my_ad;  // AD ID of this router
int neighbor_isd; // ISD ID of a neighbor AD
int neighbor_ad; // AD ID of a neighbor AD
uint32_t ifid2addr[MAX_IFID];
InterfaceState if_states[MAX_IFID];

struct keystruct rk; // AES-NI key structure

/* TODO: Handle IPv6 */
uint32_t parse_ip(cJSON *addr_obj)
{
    char *addr, *token;
    int i;
    long addr_ints[4];

    addr = addr_obj->valuestring;
    token = strtok(addr, "./");
    for (i = 0; i < 4; i++) {
        errno = 0;
        addr_ints[i] = strtol(token, NULL, 0);
        if (errno != 0) {
            fprintf(stderr, "invalid ip address\n");
            return 0;
        }
        token = strtok(NULL, "./");
    }
    return rte_cpu_to_be_32(
            IPv4(addr_ints[0], addr_ints[1], addr_ints[2], addr_ints[3]));
}

int get_servers(cJSON *root, char *name, uint32_t *arr)
{
    cJSON *server_root, *server;
    cJSON *addr_obj;
    int i = 0;

    server_root = cJSON_GetObjectItem(root, name);
    if (server_root) {
        for (server = server_root->child; server != NULL; server = server->next) {
            addr_obj = cJSON_GetObjectItem(server, "Addr");
            if (addr_obj == NULL)
                continue;
            arr[i] = parse_ip(addr_obj);
            if (arr[i] == 0)
                continue;
            i++;
        }
    }
    return i;
}

// TODO configurations of destination MAC addresses
int scion_init(int argc, char **argv)
{
    int router_id;
    char *map;
    int fd;
    int pagesize;
    cJSON *root;
    cJSON *router_root, *router;
    cJSON *server_rott, *server;
    cJSON *addr_obj;
    cJSON *key_obj;
    int i;
    int ret = -1;

    pagesize = getpagesize();

    /* Parse topology file */

    fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "failed to open topology file\n");
        goto FAIL;
    }
    map = (char *)mmap(NULL, pagesize, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        fprintf(stderr, "failed to map topology file\n");
        goto CLOSE_FD;
    }
    root = cJSON_Parse(map);
    if (root == NULL) {
        fprintf(stderr, "failed to parse topology file\n");
        goto UNMAP;
    }
    /* Get own interface info */
    router_root = cJSON_GetObjectItem(root, "EdgeRouters");
    if (router_root == NULL) {
        fprintf(stderr, "no edge routers specified in topology file\n");
        goto JSON;
    }
    for (router = router_root->child; router != NULL; router = router->next) {
        if (!strcmp(router->string, argv[0])) {
            cJSON *interface, *ifid_obj;
            char *ifid;
            /* Get internal address */
            addr_obj = cJSON_GetObjectItem(router, "Addr");
            if (!addr_obj) {
                fprintf(stderr, "no address for router\n");
                goto JSON;
            }
            internal_ip[0] = parse_ip(addr_obj);
            internal_ip[1] = internal_ip[0];
            if (internal_ip[0] == 0)
                goto JSON;

            /* Get outgoing interface address */
            interface = cJSON_GetObjectItem(router, "Interface");
            if (interface == NULL) {
                fprintf(stderr, "no interface for router\n");
                goto JSON;
            }
            addr_obj = cJSON_GetObjectItem(interface, "Addr");
            if (addr_obj == NULL) {
                fprintf(stderr, "no address for interface\n");
                goto JSON;
            }
            interface_ip[0] = parse_ip(addr_obj);
            interface_ip[1] = interface_ip[0];
            if (interface_ip[0] == 0)
                goto JSON;

            /* Get neighbor interface */
            addr_obj = cJSON_GetObjectItem(interface, "ToAddr");
            if (addr_obj == NULL) {
                fprintf(stderr, "no neighbor address\n");
                goto JSON;
            }
            neighbor_ip[0] = parse_ip(addr_obj);
            if (neighbor_ip[0] == 0) {
                fprintf(stderr, "invalid neighbor address\n");
                goto JSON;
            }
            neighbor_ip[1] = neighbor_ip[0];
            addr_obj = cJSON_GetObjectItem(interface, "NeighborISD");
            if (addr_obj == NULL) {
                fprintf(stderr, "no ISD specified for neighbor\n");
                goto JSON;
            }
            neighbor_isd = addr_obj->valueint;
            addr_obj = cJSON_GetObjectItem(interface, "NeighborAD");
            if (addr_obj == NULL) {
                fprintf(stderr, "no AD specified for neighbor\n");
                goto JSON;
            }
            neighbor_ad = addr_obj->valueint;

            /* Get IFID */
            ifid_obj = cJSON_GetObjectItem(interface, "IFID");
            if (ifid_obj == NULL) {
                fprintf(stderr, "no IFID specified\n");
                goto JSON;
            }
            printf("MY IFID %d\n", ifid_obj->valueint);
            my_ifid[0] = ifid_obj->valueint;
            my_ifid[1] = my_ifid[0];
            break;
        }
    }
    if (router == NULL) {
        fprintf(stderr, "router not found in topology file\n");
        goto JSON;
    }

    /* Get DNS servers */
    dns_server_count = get_servers(root, "DNSServers", dns_servers);
    if (dns_server_count == 0) {
        fprintf(stderr, "no valid DNS servers");
        goto JSON;
    }

    /* Get Beacon servers */
    beacon_server_count = get_servers(root, "BeaconServers", beacon_servers);

    /* Get Certificate servers */
    cert_server_count =
        get_servers(root, "CertificateServers", certificate_servers);

    /* Get Path servers */
    path_server_count = get_servers(root, "PathServers", path_servers);

    /* Get ISD/AD */
    addr_obj = cJSON_GetObjectItem(root, "ISDID");
    if (addr_obj == NULL) {
        fprintf(stderr, "no ISD info\n");
        goto JSON;
    }
    my_isd = addr_obj->valueint;
    addr_obj = cJSON_GetObjectItem(root, "ADID");
    if (addr_obj == NULL) {
        fprintf(stderr, "no AD info\n");
        goto JSON;
    }
    my_ad = addr_obj->valueint;

    /* Done with topology file */
    cJSON_Delete(root);
    munmap(map, pagesize);
    close(fd);

    // second router
    /*
       neighbor_ip[2] = neighbor_ip[3] =
       rte_cpu_to_be_32(IPv4(1, 1, 1, 1));
       port_map[2].egress = 2;
       port_map[2].local = 3;
       port_map[3].egress = 2;
       port_map[3].local = 3;
       my_ifid[2] = my_ifid[3] = 345; // ifid of NIC 2 and NIC 3 is 345
       */

    /* Parse config file */
    fd = open(argv[2], O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "failed to open config file\n");
        goto FAIL;
    }
    map = (char *)mmap(NULL, pagesize, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        fprintf(stderr, "failed to map config file\n");
        goto CLOSE_FD;
    }
    root = cJSON_Parse(map);
    if (root == NULL) {
        fprintf(stderr, "failed to parse config file\n");
        goto UNMAP;
    }
    key_obj = cJSON_GetObjectItem(root, "MasterADKey");
    if (key_obj == NULL) {
        fprintf(stderr, "no master key in config file\n");
        goto JSON;
    }
    unsigned char *key = key_obj->valuestring;
    if (key == NULL) {
        fprintf(stderr, "invalid master key\n");
        goto JSON;
    }

    //FIXME
    ifid2addr[1]=IPv4(100,64,0,12);

    // FIXME hardcoded MAC addresses
    // for integration test
    // unsigned char mac_egress[]={0x5a,0xf9,0x47,0x5a,0x67,0xb4};
    unsigned char mac_egress[] = {0x00, 0x00, 0x00,
        0x00, 0x00, 0xcc}; // mac address of er11-13
    unsigned char mac_ingress[] = {0x0a, 0x00, 0x27, 0x00, 0x00, 0x02};
    for (i = 0; i < MAX_DPDK_PORT; i++) {
        ether_addr_copy(mac_egress, neighbor_mac[i].addr_bytes);
        ether_addr_copy(mac_ingress, internal_router_mac[i].addr_bytes);
    }

#ifdef SERVER_MAC_ADDRESS // in case that this router is directly connected with
    // servers.
    unsigned char mac_beacon[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x8};
    unsigned char mac_cert[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x6};
    unsigned char mac_path[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x9};
    unsigned char mac_dns[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0xa};
    ether_addr_copy(mac_beacon, &ether_addr_beacon_servers[0]);
    ether_addr_copy(mac_cert, &ether_addr_certificate_servers[0]);
    ether_addr_copy(mac_path, &ether_addr_path_servers[0]);
    ether_addr_copy(mac_dns, &ether_addr_dns_servers[0]);

    unsigned char mac_ifid1[] = {0x0, 0x0, 0x0, 0x0, 0x10, 0x1};
    unsigned char mac_ifid2[] = {0x0, 0x0, 0x0, 0x0, 0x10, 0x2};
    ether_addr_copy(mac_ifid1, &ifid2ethaddr[1]);
    ether_addr_copy(mac_ifid2, &ifid2ethaddr[2]);
#endif

    RTE_LOG(DEBUG, HSR, "%x %x %x %x %x %x\n", neighbor_mac[0].addr_bytes[0],
            neighbor_mac[0].addr_bytes[1], neighbor_mac[0].addr_bytes[2],
            neighbor_mac[0].addr_bytes[3], neighbor_mac[0].addr_bytes[4],
            neighbor_mac[0].addr_bytes[5]);

    // AES-NI key setup
    rk.roundkey = aes_assembly_init(key);
    rk.iv = malloc(16 * sizeof(char));

    // DPDK setting

    port_map[0].egress = 0;
    port_map[0].local = 1;
    port_map[1].egress = 0;
    port_map[1].local = 1;

    memset(if_states, 0, sizeof(if_states));

    ret = 0;

JSON:
    cJSON_Delete(root);
UNMAP:
    munmap(map, pagesize);
CLOSE_FD:
    close(fd);
FAIL:
    return ret;
}

static inline int send_packet(struct rte_mbuf *m, uint8_t port)
{
    struct ipv4_hdr *ipv4_hdr;
    struct udp_hdr *udp_hdr;
    ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr));
    udp_hdr = (struct udp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr) +
            sizeof(struct ipv4_hdr));

    // update checksum
    // TODO hardware offloading
    ipv4_hdr->hdr_checksum = 0;
    ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
    udp_hdr->dgram_cksum = 0;
    udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, udp_hdr);

    RTE_LOG(DEBUG, HSR, "send_packet() dpdk_port=%d, %#x:%d\n", port, ipv4_hdr->dst_addr, ntohs(udp_hdr->dst_port));
    l2fwd_send_packet(m, port);
}

// send a packet to neighbor AD router
static inline int send_egress(struct rte_mbuf *m, uint8_t dpdk_rx_port)
{
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ipv4_hdr;
    struct udp_hdr *udp_hdr;
    eth_hdr = (struct eth_hdr *)(rte_pktmbuf_mtod(m, unsigned char *));
    ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr));
    udp_hdr = (struct udp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr) +
            sizeof(struct ipv4_hdr));

    // Update source IP address
    ipv4_hdr->src_addr = interface_ip[port_map[dpdk_rx_port].egress];

    // Update destination IP address and UDP port number
    ipv4_hdr->dst_addr = neighbor_ip[dpdk_rx_port];
    udp_hdr->dst_port = htons(SCION_ROUTER_PORT);

    ether_addr_copy(neighbor_mac[port_map[dpdk_rx_port].egress].addr_bytes,
            &eth_hdr->d_addr);

    RTE_LOG(DEBUG, HSR, "send_egress port=%d\n", port_map[dpdk_rx_port].egress);
    send_packet(m, port_map[dpdk_rx_port].egress);
}

// send a packet to the edge router that has next_ifid in this AD
static inline int send_ingress(struct rte_mbuf *m, uint32_t next_ifid,
        uint8_t dpdk_rx_port)
{
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ipv4_hdr;
    struct udp_hdr *udp_hdr;
    eth_hdr = (struct eth_hdr *)(rte_pktmbuf_mtod(m, unsigned char *));
    ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr));
    udp_hdr = (struct udp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr) +
            sizeof(struct ipv4_hdr));

    if (next_ifid != 0) {
        // Update source IP address
        ipv4_hdr->src_addr = internal_ip[port_map[dpdk_rx_port].local];

        // Update destination IP address and UDP port number
        //ipv4_hdr->dst_addr = GET_EDGE_ROUTER_IPADDR(next_ifid);
        ipv4_hdr->dst_addr = ntohl(ifid2addr[next_ifid]);
        printf("dst ip=%x\n",ipv4_hdr->dst_addr);
        udp_hdr->dst_port = htons(SCION_UDP_PORT);

        ether_addr_copy(
                internal_router_mac[port_map[dpdk_rx_port].local].addr_bytes,
                &eth_hdr->d_addr);
#ifdef SERVER_MAC_ADDRESS 
        ether_addr_copy(
                ifid2ethaddr[next_ifid].addr_bytes,
                &eth_hdr->d_addr);
#endif

        RTE_LOG(DEBUG, HSR, "next_ifid=%d\n", next_ifid);
        RTE_LOG(DEBUG, HSR, "egress dpdk_port=%d\n", DPDK_LOCAL_PORT);

        send_packet(m, port_map[dpdk_rx_port].local);
        return 1;
    }
    return -1;
}

extern struct rte_mempool *l2fwd_pktmbuf_pool;
static struct rte_mbuf *ifid_pkt;
static struct rte_mbuf *ifreq_pkt;

void create_ifid_packet(struct ether_addr *eth_addrs)
{
    /* Assume IPv4 (TODO: IPv6) */
    int size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
        sizeof(struct udp_hdr) + sizeof(SCIONCommonHeader) + 16 + 8 + 2 +
        4; // FIXME remove magic numbers
    struct ether_addr dst_mac;
    uint8_t *ptr;
    SCIONCommonHeader *sch;
    SCIONAddr src_addr, dst_addr;

    ifid_pkt = rte_pktmbuf_alloc(l2fwd_pktmbuf_pool);
    ifid_pkt->data_len = size;

    /* FIXME */
    ether_addr_copy(neighbor_mac[0].addr_bytes, dst_mac.addr_bytes);

    /* Fill in ethernet, IP, UDP headers */
    build_lower_layers(ifid_pkt, eth_addrs, &dst_mac, neighbor_ip[0], size);

    /* Fill in SCION common header */
    sch =
        (SCIONCommonHeader *)(rte_pktmbuf_mtod(ifid_pkt, unsigned char *)+sizeof(
                    struct ether_hdr) +
                sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
    build_cmn_hdr(sch, ADDR_IPV4_TYPE, ADDR_SVC_TYPE, L4_UDP);

    /* Fill in SCION addresses */
    src_addr.isd_ad = ISD_AD(my_isd, my_ad);
    *(uint32_t *)(src_addr.host_addr) = interface_ip[0];
    dst_addr.isd_ad = ISD_AD(neighbor_isd, neighbor_ad);
    *(uint16_t *)(dst_addr.host_addr) = htons(SVC_BEACON);
    build_addr_hdr(sch, &src_addr, &dst_addr);

    /* Fill in SCION UDP header */
    build_scion_udp(sch, 14);

    /* Fill in IFIDPayload */
    ptr = (uint8_t *)sch + sch->headerLen + 8;
    *ptr = IFID_CLASS;
    ptr++;
    *ptr = IFID_PAYLOAD_TYPE;
    ptr++;
    *(uint16_t *)ptr = 0;
    ptr += 2;
    *(uint16_t *)ptr = htons(my_ifid[0]);
    sch->totalLen = htons(sch->headerLen + 14);

    /* Calculate SCION UDP checksum */
    update_scion_udp_checksum(sch);
}

void sync_interface()
{
    RTE_LOG(DEBUG, HSR, "sync_interface()\n");
    send_egress(ifid_pkt, 0);
}

void create_ifreq_packet(struct ether_addr *eth_addrs)
{
    /* Assume IPv4 (TODO: IPv6) */
    int size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
        sizeof(struct udp_hdr) + sizeof(SCIONCommonHeader) + 16 + 8 + 2 +
        2; // FIXME remove magic numbers
    struct ether_addr dst_mac;
    uint8_t *ptr;
    SCIONCommonHeader *sch;
    SCIONAddr src_addr, dst_addr;

    ifreq_pkt = rte_pktmbuf_alloc(l2fwd_pktmbuf_pool);
    ifreq_pkt->data_len = size;

    /* Fill in ethernet, IP, UDP headers */
    build_lower_layers(ifreq_pkt, eth_addrs, &dst_mac, 0, size);

    /* Fill in SCION common header */
    sch =
        (SCIONCommonHeader *)(rte_pktmbuf_mtod(ifreq_pkt, unsigned char *)+sizeof(
                    struct ether_hdr) +
                sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
    build_cmn_hdr(sch, ADDR_IPV4_TYPE, ADDR_SVC_TYPE, L4_UDP);

    /* Fill in SCION addresses */
    src_addr.isd_ad = ISD_AD(my_isd, my_ad);
    //*(uint32_t *)(src_addr.host_addr) = interface_ip[0];
    *(uint32_t *)(src_addr.host_addr) = internal_ip[0];
    dst_addr.isd_ad = ISD_AD(neighbor_isd, neighbor_ad);
    *(uint16_t *)(dst_addr.host_addr) = htons(SVC_BEACON);
    build_addr_hdr(sch, &src_addr, &dst_addr);

    /* Fill in SCION UDP header */
    build_scion_udp(sch, 12);

    /* Fill in IFStateRequest */
    ptr = (uint8_t *)sch + sch->headerLen + 8;
    *ptr = PATH_CLASS;
    ptr++;
    *ptr = PMT_IFSTATE_REQ_TYPE;
    ptr++;
    *(uint16_t *)ptr = 0; // IFID
    sch->totalLen = htons(sch->headerLen + 12);

    /* Calculate SCION UDP checksum */
    update_scion_udp_checksum(sch);
}

void request_ifstates()
{
    int i;
    struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(ifreq_pkt, struct ether_hdr *);
    struct ipv4_hdr *ip = (struct ipv4_hdr *)(rte_pktmbuf_mtod(
                ifreq_pkt, unsigned char *)+sizeof(struct ether_hdr));

    // Update source IP address
    ip->src_addr = internal_ip[port_map[0].local]; // FIXME

    for (i = 0; i < beacon_server_count; i++) {
        ip->dst_addr = beacon_servers[i];
        ether_addr_copy(internal_router_mac[port_map[1].local].addr_bytes,
                &eth_hdr->d_addr);
#ifdef SERVER_MAC_ADDRESS
        ether_addr_copy(ether_addr_beacon_servers[0].addr_bytes, &eth_hdr->d_addr);
#endif

        RTE_LOG(DEBUG, HSR, "send IFState request to BS %d\n", i);
        send_packet(ifreq_pkt, port_map[1].local);
    }
}

static inline void process_ifid_request(struct rte_mbuf *m,
        uint8_t dpdk_rx_port)
{
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ipv4_hdr;
    struct udp_hdr *udp_hdr;
    IFIDHeader *ifid_hdr;

    RTE_LOG(DEBUG, HSR, "process ifid request\n");

    eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
    ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr));
    udp_hdr = (struct udp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr) +
            sizeof(struct ipv4_hdr));

    SCIONCommonHeader *sch =
        (SCIONCommonHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                    struct ether_hdr) +
                sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));

    ifid_hdr = (IFIDHeader *)((void *)sch + sch->headerLen +
            sizeof(struct udp_hdr) + 2); //+2 for class type

    ifid_hdr->reply_id =
        htons(my_ifid[dpdk_rx_port]); // complete with current interface
    // (self.interface.if_id)
    /* Calculate SCION UDP checksum */
    update_scion_udp_checksum(sch);

    // Update source IP address
    ipv4_hdr->src_addr = internal_ip[port_map[dpdk_rx_port].local];

    int i;
    for (i = 0; i < beacon_server_count; i++) {
        ipv4_hdr->dst_addr = beacon_servers[i];

        udp_hdr->dst_port = ntohs(SCION_UDP_PORT);
        ether_addr_copy(
                internal_router_mac[port_map[dpdk_rx_port].local].addr_bytes,
                &eth_hdr->d_addr);
#ifdef SERVER_MAC_ADDRESS
        ether_addr_copy(ether_addr_beacon_servers[0].addr_bytes, &eth_hdr->d_addr);
#endif
        send_packet(m, port_map[dpdk_rx_port].local);
    }
}

static inline void process_pcb(struct rte_mbuf *m, uint8_t from_bs,
        uint8_t dpdk_rx_port)
{
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ipv4_hdr;
    struct udp_hdr *udp_hdr;
    PathConstructionBeacon *pcb;

    RTE_LOG(DEBUG, HSR, "process pcb\n");

    eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
    ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr));
    udp_hdr = (struct udp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr) +
            sizeof(struct ipv4_hdr));
    //  pcb = (PathConstructionBeacon *)(rte_pktmbuf_mtod(m, unsigned char
    //  *)+sizeof(
    //                                       struct ether_hdr) +
    //                                   sizeof(struct ipv4_hdr) +
    //                                   sizeof(struct udp_hdr));

    // now PCB is on the SCION UDP
    SCIONCommonHeader *sch =
        (SCIONCommonHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                    struct ether_hdr) +
                sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
    pcb = (PathConstructionBeacon *)((void *)sch + sch->headerLen +
            sizeof(struct udp_hdr) +
            2); //+2 for class type

    if (from_bs) { // from local beacon server to neighbor router
        RTE_LOG(DEBUG, HSR, "from local bs to neighbor bs\n");
        uint8_t last_pcbm_index = sizeof(pcb->payload.ads) / sizeof(ADMarking) - 1;

        //FIXME
        /*
           HopOpaqueField *last_hof = &(pcb->payload).ads[last_pcbm_index].pcbm.hof;

           if (my_ifid != EGRESS_IF(last_hof)) {
        // Wrong interface set by BS.
        RTE_LOG(DEBUG, HSR, "Wrong Interface\n");
        return;
        }
        */
        // Update source IP address
        ipv4_hdr->src_addr = interface_ip[port_map[dpdk_rx_port].egress];

        ipv4_hdr->dst_addr = neighbor_ip[dpdk_rx_port];
        udp_hdr->dst_port = htons(SCION_ROUTER_PORT); // neighbor router port
        ether_addr_copy(neighbor_mac[port_map[dpdk_rx_port].egress].addr_bytes,
                &eth_hdr->d_addr);

        send_packet(m, port_map[dpdk_rx_port].egress);

    } else { // from neighbor router to local beacon server
        RTE_LOG(DEBUG, HSR, "from neighbor bs to local bs\n");
        pcb->payload.if_id = htons(my_ifid[dpdk_rx_port]);

        /* Calculate SCION UDP checksum */
        update_scion_udp_checksum(sch);

        // Update source IP address
        ipv4_hdr->src_addr = internal_ip[port_map[dpdk_rx_port].local];

        ipv4_hdr->dst_addr = beacon_servers[0];
        udp_hdr->dst_port = htons(SCION_UDP_PORT);
        ether_addr_copy(
                internal_router_mac[port_map[dpdk_rx_port].local].addr_bytes,
                &eth_hdr->d_addr);
#ifdef SERVER_MAC_ADDRESS
        ether_addr_copy(ether_addr_beacon_servers[0].addr_bytes, &eth_hdr->d_addr);
#endif
        send_packet(m, port_map[dpdk_rx_port].local);
    }
}

static inline void relay_cert_server_packet(struct rte_mbuf *m,
        uint8_t from_local_socket,
        uint8_t dpdk_rx_port)
{
    struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
    struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(
                m, unsigned char *)+sizeof(struct ether_hdr));
    struct udp_hdr *udp_hdr;
    udp_hdr = (struct udp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr) +
            sizeof(struct ipv4_hdr));

    if (from_local_socket) {
        ipv4_hdr->src_addr = interface_ip[port_map[dpdk_rx_port].egress];
        ipv4_hdr->dst_addr = neighbor_ip[dpdk_rx_port];
        udp_hdr->dst_port = SCION_ROUTER_PORT;
        ether_addr_copy(neighbor_mac[port_map[dpdk_rx_port].egress].addr_bytes,
                &eth_hdr->d_addr);

        send_packet(m, port_map[dpdk_rx_port].egress);
    } else {
        ipv4_hdr->src_addr = internal_ip[port_map[dpdk_rx_port].local];
        ipv4_hdr->dst_addr = certificate_servers[0];

        udp_hdr->dst_port = htons(SCION_UDP_PORT);
        ether_addr_copy(
                internal_router_mac[port_map[dpdk_rx_port].local].addr_bytes,
                &eth_hdr->d_addr);
#ifdef SERVER_MAC_ADDRESS
        ether_addr_copy(ether_addr_certificate_servers[0].addr_bytes,
                &eth_hdr->d_addr);
#endif

        send_packet(m, port_map[dpdk_rx_port].local);
    }
}

static inline void process_path_mgmt_packet(struct rte_mbuf *m,
        uint8_t from_local_ad,
        uint8_t dpdk_rx_port)
{
    RTE_LOG(DEBUG, HSR, "process_path_mgmt_packet()\n");

    SCIONCommonHeader *sch;
    HopOpaqueField *hof;
    InfoOpaqueField *iof;

    sch = (SCIONCommonHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr) +
            sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
    hof = (HopOpaqueField *)((unsigned char *)sch +
            sch->currentOF); // currentOF is an offset
    // from
    // common header
    iof = (InfoOpaqueField *)((unsigned char *)sch +
            sch->currentIOF); // currentOF is an offset
    // from
    // common header

    uint8_t payload_type = get_payload_type(sch);
    if (payload_type == PMT_IFSTATE_INFO_TYPE) {
        uint8_t *ptr = (uint8_t *)sch + sch->headerLen;
        ptr += sizeof(SCIONUDPHeader) + 2;
        while (ptr - (uint8_t *)sch < ntohs(sch->totalLen)) {
            uint16_t ifid = ntohs(*(uint16_t *)ptr);
            ptr += 2;
            InterfaceState *state = if_states + ifid;
            state->is_active = ntohs(*(uint16_t *)ptr);
            ptr += 2;
            memcpy(state->rev_info, ptr, REV_TOKEN_LEN);
            ptr += REV_TOKEN_LEN;
        }
        return;
    } else if (payload_type == PMT_REVOCATION_TYPE) {
        return;
    }

    if (from_local_ad == 0 && is_last_path_of(sch)) {
        deliver(m, PATH_MGMT_PACKET, dpdk_rx_port);
    } else {
        forward_packet(m, from_local_ad, dpdk_rx_port);
    }
}

static inline void deliver(struct rte_mbuf *m, uint32_t ptype,
        uint8_t dpdk_rx_port)
{
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ipv4_hdr;
    struct udp_hdr *udp_hdr;
    SCIONCommonHeader *sch;

    RTE_LOG(DEBUG, HSR, "deliver\n");
    eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
    ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr));
    udp_hdr = (struct udp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr) +
            sizeof(struct ipv4_hdr));

    sch = (SCIONCommonHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr) +
            sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));

    ether_addr_copy(internal_router_mac[port_map[dpdk_rx_port].local].addr_bytes,
            &eth_hdr->d_addr);
    ipv4_hdr->src_addr = internal_ip[port_map[dpdk_rx_port].local];
    udp_hdr->dst_port = htons(SCION_UDP_PORT);

    // TODO support IPv6
    if (ptype == PATH_MGMT_PACKET) {
        printf("to path server\n");
        ipv4_hdr->dst_addr = path_servers[0];
#ifdef SERVER_MAC_ADDRESS
        ether_addr_copy(ether_addr_path_servers[0].addr_bytes, &eth_hdr->d_addr);
#endif
    } else {

        printf("to end host\n");

        // update destination IP address to the end host adress
        // rte_memcpy((void *)&ipv4_hdr->dst_addr,
        //           (void *)&scion_hdr->dst_Addr + SCION_ISD_AD_LEN,
        //           SCION_HOST_ADDR_LEN);
        void *dst_addr = get_dst_addr(sch);
        // TODO: IPv6?
        rte_memcpy((void *)&ipv4_hdr->dst_addr, dst_addr, ADDR_IPV4_LEN);

#ifdef SERVER_MAC_ADDRESS
        // FIXME
        // HSR does not know client MAC address
        // uint8_t bcast_addr[]={0xff,0xff,0xff,0xff,0xff,0xff};
        // ether_addr_copy(bcast_addr,&eth_hdr->d_addr);
        uint8_t host_addr[] = {0x0, 0x0, 0x0, 0x0, 0x1, 0x3};
        ether_addr_copy(host_addr, &eth_hdr->d_addr);
#endif
        udp_hdr->dst_port = htons(SCION_UDP_EH_DATA_PORT);

        // FIXME
        // get scion udp port number
        struct udp_hdr *scion_udp_hdr =
            (struct udp_hdr *)((uint8_t *)sch + sch->headerLen);
        udp_hdr->dst_port = scion_udp_hdr->dst_port;
        printf("udp dport=%d\n", ntohs(udp_hdr->dst_port));
    }

    send_packet(m, port_map[dpdk_rx_port].local);
}

static inline uint8_t verify_of(HopOpaqueField *hof, HopOpaqueField *prev_hof,
        uint32_t ts)
{
#ifndef VERIFY_OF
    return 1;
#endif

#define MAC_LEN 3

    unsigned char input[16];
    unsigned char mac[16];

    RTE_LOG(DEBUG, HSR, "verify_of\n");

    // setup input vector
    // rte_mov32 ((void*)input, (void *)hof+1); //copy exp_type and
    // ingress/egress IF (4bytes)
    // rte_mov64 ((void*)input+4, (void *)prev_hof+1); //copy previous OF except
    // info field (7bytes)
    // rte_mov32 ((void*)input+11, (void*)&ts);

    rte_memcpy((void *)input, (void *)hof + 1,
            4); // copy exp_type and  ingress/egress IF (4bytes)
    if(prev_hof != 0)
        rte_memcpy((void *)input + 4, (void *)prev_hof + 1,
                7); // copy previous OF except info field (7bytes)
    else
        memset((void *)input + 4, 0, sizeof(HopOpaqueField) -1);
    rte_memcpy((void *)input + 11, (void *)&ts, 4);

    // pkcs7_padding
    input[15] = 1;

    // call AES-NI
    // int i;
    // for (i = 0; i < 16; i++)
    //  printf("%02x", input[i]);
    // printf("\n");
    CBCMAC1BLK(rk.roundkey, rk.iv, input, mac);
    // for (i = 0; i < 16; i++)
    //  printf("%02x", mac[i]);
    // printf("\n");

    if (memcmp((void *)hof + 5, &mac,
                MAC_LEN)) { // (void *)hof + 5 is address of mac.
        return 1;
    } else {
        RTE_LOG(WARNING, HSR, "invalid MAC\n");
        // return 0;
        // TODO DEBUG, currently disable MAC check
        return 1;
    }
}

static inline void handle_ingress_xovr(struct rte_mbuf *m,
        uint8_t dpdk_rx_port)
{
    SCIONCommonHeader *sch;
    HopOpaqueField *hof;
    InfoOpaqueField *iof;

    RTE_LOG(DEBUG, HSR, "handle ingress xovr\n");
    sch = (SCIONCommonHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr) +
            sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
    hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF);
    iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF);
    RTE_LOG(DEBUG, HSR, "iof->info %d\n", iof->info);

    if (iof->info >> 1 == OFT_SHORTCUT) {
        ingress_shortcut_xovr(m, dpdk_rx_port);
    } else if (iof->info >> 1 == OFT_INTRA_ISD_PEER ||
            iof->info >> 1 == OFT_INTER_ISD_PEER) {
        ingress_peer_xovr(m, dpdk_rx_port);
    } else if (iof->info >> 1 == OFT_CORE) {
        ingress_core_xovr(m, dpdk_rx_port);
    } else {
        RTE_LOG(DEBUG, HSR, "Invalid iof->info %d\n", iof->info);
    }
}

static inline void ingress_shortcut_xovr(struct rte_mbuf *m,
        uint8_t dpdk_rx_port)
{
    SCIONCommonHeader *sch;
    HopOpaqueField *hof;
    HopOpaqueField *prev_hof;
    InfoOpaqueField *iof;

    RTE_LOG(DEBUG, HSR, "ingress shortcut xovr\n");
    sch = (SCIONCommonHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr) +
            sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
    hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF);
    iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF);

    prev_hof = hof + 1;
    if (verify_of(hof, prev_hof, iof->timestamp) == 0) {
        return;
    }

    // switch to next segment
    sch->currentIOF = sch->currentOF + sizeof(HopOpaqueField) * 2;
    sch->currentOF += sizeof(HopOpaqueField) * 4;

    hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF);
    iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF);

    if (INGRESS_IF(hof) == 0 && is_last_path_of(sch)) {
        prev_hof = hof - 1;
        if (verify_of(hof, prev_hof, iof->timestamp) == 0) {
            return;
        }

        deliver(m, DATA_PACKET, dpdk_rx_port);
    } else {
        send_ingress(m, EGRESS_IF(hof), dpdk_rx_port);
    }
}
static inline void ingress_peer_xovr(struct rte_mbuf *m, uint8_t dpdk_rx_port)
{
    SCIONCommonHeader *sch;
    HopOpaqueField *hof;
    HopOpaqueField *prev_hof;
    InfoOpaqueField *iof;

    RTE_LOG(DEBUG, HSR, "ingress peer xovr\n");
    sch = (SCIONCommonHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr) +
            sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
    hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF);
    iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF);

    uint16_t fwd_if;
    if (is_on_up_path(iof)) {
        prev_hof = hof + 2;
        fwd_if = INGRESS_IF(hof + 1);
    } else {
        prev_hof = hof + 1;
        fwd_if = EGRESS_IF(hof + 1);
    }

    if (verify_of(hof, prev_hof, iof->timestamp) == 0) {
        return;
    }

    sch->currentOF += sizeof(HopOpaqueField);

    if (is_last_path_of(sch))
        deliver(m, DATA_PACKET, dpdk_rx_port);
    else
        send_ingress(m, fwd_if, dpdk_rx_port);
}
static inline void ingress_core_xovr(struct rte_mbuf *m, uint8_t dpdk_rx_port)
{
    SCIONCommonHeader *sch;
    HopOpaqueField *hof;
    HopOpaqueField *prev_hof;
    InfoOpaqueField *iof;

    RTE_LOG(DEBUG, HSR, "ingress core xovr\n");
    sch = (SCIONCommonHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr) +
            sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
    hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF);
    iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF);

    uint32_t fwd_if;
    if (is_on_up_path(iof)) {
        prev_hof = NULL;
    } else {
        prev_hof = hof - 1;
    }

    if (verify_of(hof, prev_hof, iof->timestamp) == 0) {
        return;
    }

    if (is_last_path_of(sch))
        deliver(m, DATA_PACKET, dpdk_rx_port);
    else {
        // Switch to next path segment
        sch->currentIOF = sch->currentOF + sizeof(HopOpaqueField);
        sch->currentOF += sizeof(HopOpaqueField) * 2;
        iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF);
        hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF);

        if (is_on_up_path(iof)) {
            send_ingress(m, INGRESS_IF(hof), dpdk_rx_port);
        } else {
            send_ingress(m, EGRESS_IF(hof), dpdk_rx_port);
        }
    }
}

static inline void ingress_normal_forward(struct rte_mbuf *m,
        uint8_t dpdk_rx_port)
{
    SCIONCommonHeader *sch;
    HopOpaqueField *hof;
    HopOpaqueField *prev_hof;
    InfoOpaqueField *iof;

    RTE_LOG(DEBUG, HSR, "ingress normal forward\n");
    sch = (SCIONCommonHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr) +
            sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
    hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF);
    iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF);

    printf("Ingress %d, Egress %d\n", INGRESS_IF(hof), EGRESS_IF(hof));
    uint16_t next_ifid;
    if (is_on_up_path(iof)) {
        next_ifid = INGRESS_IF(hof);
        prev_hof = hof + 1;
    } else {
        next_ifid = EGRESS_IF(hof);
        prev_hof = hof - 1;
    }

    printf("Next ifid %d\n", next_ifid);

    if (verify_of(hof, prev_hof, iof->timestamp) == 0) {
        return;
    }

    if (next_ifid == 0 && is_last_path_of(sch)) {
        deliver(m, DATA_PACKET, dpdk_rx_port);
    } else {
        send_ingress(m, next_ifid, dpdk_rx_port);
    }
}

static inline void handle_egress_xovr(struct rte_mbuf *m,
        uint8_t dpdk_rx_port)
{
    SCIONCommonHeader *sch;
    HopOpaqueField *hof;
    InfoOpaqueField *iof;

    RTE_LOG(DEBUG, HSR, "handle egress xovr\n");
    sch = (SCIONCommonHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr) +
            sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
    iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF);

    if (iof->info >>1 == OFT_SHORTCUT) {
        egress_shortcut_xovr(m, dpdk_rx_port);
    } else if (iof->info >>1 == OFT_INTRA_ISD_PEER ||
            iof->info  >>1== OFT_INTER_ISD_PEER) {
        egress_peer_xovr(m, dpdk_rx_port);
    } else if (iof->info  >>1== OFT_CORE) {
        egress_core_xovr(m, dpdk_rx_port);
    } else {
        // invalid OF
        RTE_LOG(DEBUG, HSR, "Invalid iof->info %d\n", iof->info);
    }
}

static inline void egress_shortcut_xovr(struct rte_mbuf *m,
        uint8_t dpdk_rx_port)
{
    RTE_LOG(DEBUG, HSR, "egress_shortcut_xovr\n");
    egress_normal_forward(m, dpdk_rx_port);
}

static inline void egress_peer_xovr(struct rte_mbuf *m, uint8_t dpdk_rx_port)
{
    struct ether_hdr *eth_hdr;
    SCIONCommonHeader *sch;
    HopOpaqueField *hof;
    HopOpaqueField *prev_hof;
    InfoOpaqueField *iof;

    RTE_LOG(DEBUG, HSR, "egress_peer_xovr \n");
    sch = (SCIONCommonHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr) +
            sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
    hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF);
    iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF);

    if (is_on_up_path(iof)) {
        prev_hof = hof - 1;
        if (verify_of(hof, prev_hof, iof->timestamp) == 0) {
            return;
        }

        // Switch to next segment
        sch->currentIOF = sch->currentOF + sizeof(HopOpaqueField) * 2;
        sch->currentOF += sizeof(HopOpaqueField) * 4;
    } else {
        prev_hof = hof - 2;
        if (verify_of(hof, prev_hof, iof->timestamp) == 0) {
            return;
        }
        sch->currentOF += sizeof(HopOpaqueField);
    }

    send_egress(m, dpdk_rx_port);
}

static inline void egress_core_xovr(struct rte_mbuf *m, uint8_t dpdk_rx_port)
{
    struct ether_hdr *eth_hdr;
    SCIONCommonHeader *sch;
    HopOpaqueField *hof;
    HopOpaqueField *prev_hof;
    InfoOpaqueField *iof;

    RTE_LOG(DEBUG, HSR, "egress core xovr\n");
    sch = (SCIONCommonHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr) +
            sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
    hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF);
    iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF);

    if (is_on_up_path(iof)) {
        prev_hof = NULL;
    } else {
        prev_hof = hof + 1;
    }

    if (verify_of(hof, prev_hof, iof->timestamp) == 0) {
        return;
    }

    sch->currentOF += sizeof(HopOpaqueField);
    send_egress(m, dpdk_rx_port);
}

static inline void egress_normal_forward(struct rte_mbuf *m,
        uint8_t dpdk_rx_port)
{
    struct ether_hdr *eth_hdr;
    SCIONCommonHeader *sch;
    HopOpaqueField *hof;
    HopOpaqueField *prev_hof;
    InfoOpaqueField *iof;

    RTE_LOG(DEBUG, HSR, "egress normal forward\n");
    sch = (SCIONCommonHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr) +
            sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
    hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF);
    iof = (InfoOpaqueField *)((unsigned char *)sch + sch->currentIOF);

    // printf("Ingress %d, Egress %d\n", INGRESS_IF(hof), EGRESS_IF(hof));
    if (is_on_up_path(iof)) {
        prev_hof = hof + 1;
    } else {
        prev_hof = hof - 1;
    }

    // TODO  verify MAC
    if (verify_of(hof, prev_hof, iof->timestamp) == 0) {
        return;
    }

    sch->currentOF += sizeof(HopOpaqueField);

    // send packet to neighbor AD's router
    send_egress(m, dpdk_rx_port);
}

static inline void forward_packet(struct rte_mbuf *m, uint32_t from_local_ad,
        uint8_t dpdk_rx_port)
{
    SCIONCommonHeader *sch;
    HopOpaqueField *hof;
    InfoOpaqueField *iof;

    sch = (SCIONCommonHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr) +
            sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
    hof = (HopOpaqueField *)((unsigned char *)sch + sch->currentOF);

    RTE_LOG(DEBUG, HSR, "forward_packet: hof->info=%#x\n", hof->info);

    if (from_local_ad == 0) {
        // Ingress entry point
        if (hof->info == OFT_XOVR_POINT) {
            handle_ingress_xovr(m, dpdk_rx_port);
        } else {
            ingress_normal_forward(m, dpdk_rx_port);
        }
    } else {
        // Egress entry point
        if (hof->info == OFT_XOVR_POINT) {
            handle_egress_xovr(m, dpdk_rx_port);
        } else {
            egress_normal_forward(m, dpdk_rx_port);
        }
    }
}

int needs_local_processing(SCIONCommonHeader *sch)
{
    uint8_t src_type = SRC_TYPE(sch);
    uint8_t src_len = get_src_len(sch);
    uint8_t dst_type = DST_TYPE(sch);
    uint8_t dst_len = get_dst_len(sch);
    uint8_t *dst_ptr = (uint8_t *)sch + sizeof(*sch) + src_len + SCION_ISD_AD_LEN;
    uint32_t dst_isd_ad = ntohl(*(uint32_t *)dst_ptr);
    // TODO: support dst_addr > 4 bytes
    uint32_t dst_addr = *(uint32_t *)(dst_ptr + SCION_ISD_AD_LEN);

    if ((sch->headerLen == sizeof(*sch) + src_len + dst_len) &&
        (dst_type == ADDR_SVC_TYPE))
        return 1;
    if (src_type == ADDR_SVC_TYPE)
        return 1;
    if (dst_isd_ad == ISD_AD(my_isd, my_ad)) {
        if (dst_addr == internal_ip[0] || dst_addr == interface_ip[0])
            return 1;
        if (dst_type == ADDR_SVC_TYPE)
            return 1;
    }
    return 0;
}

void handle_request(struct rte_mbuf *m, uint8_t dpdk_rx_port)
{
    struct ether_hdr *eth_hdr;
    struct udp_hdr *udp_hdr;
    SCIONCommonHeader *sch;
    RTE_LOG(DEBUG, HSR, "==============\n");
    RTE_LOG(DEBUG, HSR, "packet recieved, dpdk_port=%d\n", dpdk_rx_port);

    eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
    udp_hdr = (struct udp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr) +
            sizeof(struct ipv4_hdr));
    // RTE_LOG(DEBUG, HSR, "type=%x\n", eth_hdr->ether_type);

    uint64_t src, dst;
    src = *(uint64_t *)(eth_hdr->s_addr.addr_bytes) & 0xffffffffffff;
    dst = *(uint64_t *)(eth_hdr->d_addr.addr_bytes) & 0xffffffffffff;

    // if (m->ol_flags & PKT_RX_IPV4_HDR )
    if ((m->ol_flags & PKT_RX_IPV4_HDR || eth_hdr->ether_type == ntohs(0x0800)) &&
            (udp_hdr->dst_port == htons(SCION_UDP_PORT) ||
             udp_hdr->dst_port == htons(SCION_ROUTER_PORT))) {

        // from local socket?
        uint8_t from_local_socket = dpdk_rx_port & 1;

        sch =
            (SCIONCommonHeader *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                        struct ether_hdr) +
                    sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));

        // FIXME: sample code to show extension finding works, should be deleted
        uint8_t *ptr = find_extension(sch, END_TO_END, PATH_TRANSPORT);
        if (ptr)
            printf(">>>> path transport extension found <<<<\n");

        if (needs_local_processing(sch)) {
            uint8_t pclass = get_payload_class(sch);
            switch (pclass) {
            case IFID_CLASS:
                if (!from_local_socket)
                    process_ifid_request(m, dpdk_rx_port);
                else
                    RTE_LOG(WARNING, HSR, "IFID packet from local socket\n");
                break;
            case PCB_CLASS:
                process_pcb(m, from_local_socket, dpdk_rx_port);
                break;
            case CERT_CLASS:
                relay_cert_server_packet(m, from_local_socket, dpdk_rx_port);
                break;
            case PATH_CLASS:
                process_path_mgmt_packet(m, from_local_socket, dpdk_rx_port);
                break;
            default:
                RTE_LOG(DEBUG, HSR, "unknown packet class %d ?\n", pclass);
                break;
            }
        }
        else {
            forward_packet(m, from_local_socket, dpdk_rx_port);
        }
    } else {
        RTE_LOG(DEBUG, HSR, "Non SCION packet: ether_type=%x\n",
                ntohs(eth_hdr->ether_type));
        RTE_LOG(DEBUG, HSR, "destinaton port=%d\n", ntohs(udp_hdr->dst_port));
    }
}
