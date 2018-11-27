/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <rte_arp.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_kni.h>
#include <rte_log.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_mbuf.h>
#include <rte_prefetch.h>
#include <rte_udp.h>

#include <linux/rtnetlink.h>
#include <libmnl/libmnl.h>
#include <uthash.h>
#include <zlog.h>

#include "hsr_interface.h"
#include "scion.h"

// change value to control amount of logging (heavily affects performance)
// can result in compile warnings for unused variables
#define LOGLEVEL 1
#if LOGLEVEL > 1
#undef zlog_debug
#define zlog_debug(...)
#if LOGLEVEL > 2
#undef zlog_info
#define zlog_info(...)
#if LOGLEVEL > 3
#undef zlog_warn
#define zlog_warn(...)
#if LOGLEVEL > 4
#undef zlog_error
#define zlog_error(...)
#if LOGLEVEL > 5
#undef zlog_fatal
#define zlog_fatal(...)
#endif // LOGLEVEL > 5
#endif // LOGLEVEL > 4
#endif // LOGLEVEL > 3
#endif // LOGLEVEL > 2
#endif // LOGLEVEL > 1

#define MBUF_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define NB_MBUF   8192

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512

/* ethernet addresses of ports */
struct ether_addr hsr_ports_eth_addr[RTE_MAX_ETHPORTS];

struct mbuf_table {
    unsigned len;
    struct rte_mbuf *m_table[MAX_PKT_BURST];
};

static struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];

static const struct rte_eth_conf port_conf = {
    .rxmode = {
        .split_hdr_size = 0,
        .header_split   = 0, /**< Header Split disabled */
        .hw_ip_checksum = 0, /**< IP checksum offload disabled */
        .hw_vlan_filter = 0, /**< VLAN filtering disabled */
        .jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
        .hw_strip_crc   = 0, /**< CRC stripped by hardware */
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};

struct rte_mempool * hsr_pktmbuf_pool = NULL;

/* ARP cache */
typedef struct {
    UT_hash_handle hh;
    uint32_t ip;
    struct ether_addr mac;
} ARPEntry;
ARPEntry *arp_table = NULL;

/* handle for NETLINK socket */
static struct mnl_socket *netlink_socket;
static int netlink_ready = 0;

static pthread_mutex_t tx_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t eth_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t netlink_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t netlink_cond = PTHREAD_COND_INITIALIZER;

typedef struct {
    UT_hash_handle hh;
    uint8_t addr[MAX_HOST_ADDR_LEN];
    int portid;
} PortEntry;

static PortEntry *addr2port;

#define MAX_DPDK_PORTS 10
static struct sockaddr_storage local_addrs[MAX_DPDK_PORTS];
struct rte_kni *kni_objs[MAX_DPDK_PORTS];

/* Dummy sockets to hand packets off to kernel */
static int sockets[MAX_DPDK_PORTS];

#define LPM_V4_MAX_RULES 1024
#define LPM_V4_TBL8S (1 << 8)
#define LPM_V6_MAX_RULES 1024
#define LPM_V6_TBL8S (1 << 16)
static struct rte_lpm *next_hop_v4;
static struct rte_lpm6 *next_hop_v6;
typedef struct {
    uint8_t ip[MAX_HOST_ADDR_LEN];
    struct ether_addr mac;
    uint8_t addr_type;
    uint8_t has_ip;
    uint8_t has_mac;
} ForwardingEntry;
#define MAX_FORWARDING_ENTRIES 256
static ForwardingEntry forwarding_table[MAX_FORWARDING_ENTRIES];
static uint32_t forwarding_table_top;

zlog_category_t *zc;

#define ETH_HDR(m) (struct ether_hdr *)(rte_pktmbuf_mtod((m), uint8_t *))
#define IPV4_HDR(m) (struct ipv4_hdr *)(ETH_HDR(m) + 1)
#define IPV6_HDR(m) (struct ipv6_hdr *)(ETH_HDR(m) + 1)
#define UDP_HDR(m) (struct udp_hdr *)(IPV4_HDR(m) + 1)
#define CMN_HDR(m) (SCIONCommonHeader *)(UDP_HDR(m) + 1)

#define IP_DEFTTL  64   /* from RFC 1340. */
#define IP_VERSION 0x40
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)

static inline void initialize_eth_header(struct ether_hdr *eth, struct ether_addr *src_mac,
        struct ether_addr *dst_mac, uint16_t ether_type,
        uint8_t vlan_enabled, uint16_t van_id);
static inline uint16_t initialize_ipv4_header(struct ipv4_hdr *ip_hdr, uint32_t src_addr,
        uint32_t dst_addr, uint16_t pkt_data_len);
static inline uint16_t initialize_ipv6_header(struct ipv6_hdr *ip_hdr, uint8_t *src_addr,
		uint8_t *dst_addr, uint16_t pkt_data_len);
static inline uint16_t initialize_udp_header(struct udp_hdr *udp, uint16_t src_port,
        uint16_t dst_port, uint16_t pkt_data_len);
static inline void build_lower_layers(struct rte_mbuf *m, int dpdk_port,
        struct ether_addr *dst_mac, RouterPacket *packet, size_t size);

void * handle_kni(void *arg);
static inline int setup_kni();
void * run_netlink_core(void *arg);

static inline int dpdk_output_packet(struct rte_mbuf *m, uint8_t port);
static inline int handle_packet(RouterPacket *packet, struct rte_mbuf *m, uint8_t dpdk_rx_port);
static inline int fill_packet(struct rte_mbuf *m, uint8_t dpdk_rx_port, RouterPacket *packet);
static inline struct udp_hdr *get_udp_hdr(struct rte_mbuf *m);

static inline int kni_alloc(uint8_t port_id);

static inline unsigned setup_netlink_socket(unsigned seq);
static inline int handle_message(const struct nlmsghdr *nlh, void *data);
static inline int handle_attributes(const struct nlattr *attr, void *data);
static inline void handle_arp_update(const struct nlmsghdr *nlh);
static inline void handle_route_update(const struct nlmsghdr *nlh);

static inline int open_sockets();

static inline int eth_addr_type(int family);

/*
 * Utility functions to deal with low-level headers (eth and overlay)
 * Mostly copied from DPDK SDK examples
 * app/test/packet_burst_generator.c
 */

static inline void initialize_eth_header(struct ether_hdr *eth, struct ether_addr *src_mac,
        struct ether_addr *dst_mac, uint16_t ether_type,
        uint8_t vlan_enabled, uint16_t van_id)
{
    ether_addr_copy(dst_mac, &eth->d_addr);
    ether_addr_copy(src_mac, &eth->s_addr);

    if (vlan_enabled) {
        struct vlan_hdr *vhdr = (struct vlan_hdr *)((uint8_t *)eth +
                sizeof(struct ether_hdr));

        eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_VLAN);

        vhdr->eth_proto =  rte_cpu_to_be_16(ether_type);
        vhdr->vlan_tci = van_id;
    } else {
        eth->ether_type = rte_cpu_to_be_16(ether_type);
    }
}

static inline uint16_t initialize_ipv4_header(struct ipv4_hdr *ip_hdr, uint32_t src_addr,
        uint32_t dst_addr, uint16_t pkt_data_len)
{
    uint16_t pkt_len;

    /*
     * Initialize IP header.
     */
    pkt_len = (uint16_t) (pkt_data_len + sizeof(struct ipv4_hdr));

    ip_hdr->version_ihl   = IP_VHL_DEF;
    ip_hdr->type_of_service   = 0;
    ip_hdr->fragment_offset = 0;
    ip_hdr->time_to_live   = IP_DEFTTL;
    ip_hdr->next_proto_id = IPPROTO_UDP;
    ip_hdr->packet_id = 0;
    ip_hdr->total_length   = rte_cpu_to_be_16(pkt_len);
    ip_hdr->src_addr = src_addr;
    ip_hdr->dst_addr = dst_addr;
    ip_hdr->hdr_checksum = 0;
    ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

    return pkt_len;
}

static inline uint16_t initialize_ipv6_header(struct ipv6_hdr *ip_hdr, uint8_t *src_addr,
		uint8_t *dst_addr, uint16_t pkt_data_len)
{
	ip_hdr->vtc_flow = 0;
	ip_hdr->payload_len = pkt_data_len;
	ip_hdr->proto = IPPROTO_UDP;
	ip_hdr->hop_limits = IP_DEFTTL;

	rte_memcpy(ip_hdr->src_addr, src_addr, sizeof(ip_hdr->src_addr));
	rte_memcpy(ip_hdr->dst_addr, dst_addr, sizeof(ip_hdr->dst_addr));

	return (uint16_t) (pkt_data_len + sizeof(struct ipv6_hdr));
}

static inline uint16_t initialize_udp_header(struct udp_hdr *udp, uint16_t src_port,
        uint16_t dst_port, uint16_t pkt_data_len)
{
    uint16_t pkt_len;

    pkt_len = (uint16_t) (pkt_data_len + sizeof(struct udp_hdr));

    udp->src_port = src_port;
    udp->dst_port = dst_port;
    udp->dgram_len = htons(pkt_len);
    udp->dgram_cksum = 0; /* No UDP checksum. */

    return pkt_len;
}

static inline void build_lower_layers(struct rte_mbuf *m, int dpdk_port,
        struct ether_addr *dst_mac, RouterPacket *packet, size_t size)
{
    struct ether_hdr *eth = ETH_HDR(m);
    struct ipv4_hdr *ipv4 = IPV4_HDR(m);
    struct ipv6_hdr *ipv6 = IPV6_HDR(m);
    struct udp_hdr *udp;
    int ip_size = 0;
    struct sockaddr_storage *src = &local_addrs[dpdk_port];
    int addr_type = eth_addr_type(src->ss_family);

    initialize_eth_header(
            eth, &hsr_ports_eth_addr[dpdk_port], dst_mac, addr_type, 0, 0);
    if (addr_type == ETHER_TYPE_IPv4) {
        initialize_ipv4_header(ipv4,
                *(uint32_t *)get_ss_addr(src),
                *(uint32_t *)get_ss_addr(packet->dst),
                size - sizeof(struct ether_hdr) - sizeof(struct ipv4_hdr));
        ip_size = sizeof(struct ipv4_hdr);
    } else if (addr_type == ETHER_TYPE_IPv6) {
        initialize_ipv6_header(ipv6,
                get_ss_addr(src), get_ss_addr(packet->dst),
                size - sizeof(struct ether_hdr) - sizeof(struct ipv6_hdr));
        ip_size = sizeof(struct ipv6_hdr);
    }
    udp = get_udp_hdr(m);
    // port is at the same offset for sockaddr_in and sockaddr_in6
    initialize_udp_header(udp,
            ((struct sockaddr_in *)src)->sin_port,
            ((struct sockaddr_in *)packet->dst)->sin_port,
            size - sizeof(struct ether_hdr) - ip_size - sizeof(struct udp_hdr));

    m->nb_segs = 1;
    m->pkt_len = size;
    m->l2_len = sizeof(struct ether_hdr);
    m->l3_len = ip_size;
}

/* End of low-level utility functions */

/* Initialization functions */

pthread_t kni_thread, netlink_thread;

int create_lib_threads()
{
    pthread_create(&kni_thread, NULL, handle_kni, NULL);
    pthread_create(&netlink_thread, NULL, run_netlink_core, NULL);
    if (setup_kni() != 0) {
        return 1;
    }
    if (open_sockets() != 0) {
        return 1;
    }
    return 0;
}

void join_lib_threads()
{
    pthread_join(kni_thread, NULL);
    pthread_join(netlink_thread, NULL);
}

int router_init(char *zlog_cfg, char *zlog_cat, int argc, char **argv)
{
    int ret;
    uint8_t nb_ports;
    uint8_t portid;

    if (zlog_init(zlog_cfg) < 0) {
        fprintf(stderr, "failed to load zlog config (%s)\n", zlog_cfg);
        return 1;
    }
    zc = zlog_get_category(zlog_cat);
    if (!zc) {
        fprintf(stderr, "failed to get zlog category '%s' from %s\n", zlog_cat, zlog_cfg);
        zlog_fini();
        return 1;
    }

    /* init EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        zlog_fatal(zc, "Invalid EAL argumentsn");
        return 1;
    }

    /* create the mbuf pool */
    hsr_pktmbuf_pool =
        rte_mempool_create("mbuf_pool", NB_MBUF,
                MBUF_SIZE, 32,
                sizeof(struct rte_pktmbuf_pool_private),
                rte_pktmbuf_pool_init, NULL,
                rte_pktmbuf_init, NULL,
                rte_socket_id(), 0);
    if (hsr_pktmbuf_pool == NULL) {
        zlog_fatal(zc, "Cannot init mbuf pool");
        return 1;
    }

    nb_ports = rte_eth_dev_count();
    if (nb_ports == 0) {
        zlog_fatal(zc, "No Ethernet ports available");
        return 1;
    }

    if (nb_ports > RTE_MAX_ETHPORTS) {
        zlog_fatal(zc, "Found Ethernet ports (%d) > Max (%d)", nb_ports, RTE_MAX_ETHPORTS);
        return 1;
    }

    rte_kni_init(nb_ports);

    /* Initialise each port */
    for (portid = 0; portid < nb_ports; portid++) {
        /* init port */
        zlog_info(zc, "Initializing port %u... ", (unsigned) portid);
        ret = rte_eth_dev_configure(portid, 1, 1, &port_conf);
        if (ret < 0) {
            zlog_fatal(zc, "Cannot configure device: err=%d, port=%u", ret, (unsigned) portid);
            return 1;
        }

        rte_eth_macaddr_get(portid,&hsr_ports_eth_addr[portid]);

        /* init one RX queue */
        ret = rte_eth_rx_queue_setup(portid, 0, RTE_TEST_RX_DESC_DEFAULT,
                rte_eth_dev_socket_id(portid),
                NULL,
                hsr_pktmbuf_pool);
        if (ret < 0) {
            zlog_fatal(zc, "rte_eth_rx_queue_setup:err=%d, port=%u", ret, (unsigned) portid);
            return 1;
        }

        /* init one TX queue on each port */
        ret = rte_eth_tx_queue_setup(portid, 0, RTE_TEST_TX_DESC_DEFAULT,
                rte_eth_dev_socket_id(portid),
                NULL);
        if (ret < 0) {
            zlog_fatal(zc, "rte_eth_tx_queue_setup:err=%d, port=%u\n", ret, (unsigned) portid);
            return 1;
        }

        /* Start device */
        ret = rte_eth_dev_start(portid);
        if (ret < 0) {
            zlog_fatal(zc, "rte_eth_dev_start:err=%d, port=%u\n", ret, (unsigned) portid);
            return 1;
        }

        zlog_info(zc, "done:");

        rte_eth_promiscuous_enable(portid);

        zlog_info(zc, "Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
                (unsigned) portid,
                hsr_ports_eth_addr[portid].addr_bytes[0],
                hsr_ports_eth_addr[portid].addr_bytes[1],
                hsr_ports_eth_addr[portid].addr_bytes[2],
                hsr_ports_eth_addr[portid].addr_bytes[3],
                hsr_ports_eth_addr[portid].addr_bytes[4],
                hsr_ports_eth_addr[portid].addr_bytes[5]);

        if (kni_alloc(portid) != 0) {
            return 1;
        }
    }

    return 0;
}

/* End of initialization functions */

/* Packet handling functions */

/* Send the burst of packets on an output interface */
static inline int dpdk_output_burst(unsigned n, uint8_t port)
{
    struct rte_mbuf **m_table;
    unsigned ret;
    unsigned queueid =0;

    m_table = (struct rte_mbuf **)tx_mbufs[port].m_table;

    pthread_mutex_lock(&eth_mutex);
    ret = rte_eth_tx_burst(port, (uint16_t) queueid, m_table, (uint16_t) n);
    pthread_mutex_unlock(&eth_mutex);
    if (unlikely(ret < n)) {
        do {
            rte_pktmbuf_free(m_table[ret]);
        } while (++ret < n);
    }

    return 0;
}

/* Enqueue packets for TX and prepare them to be sent */
static inline int dpdk_output_packet(struct rte_mbuf *m, uint8_t port)
{
    unsigned len;

    pthread_mutex_lock(&tx_mutex);
    len = tx_mbufs[port].len;
    tx_mbufs[port].m_table[len] = m;
    len++;

    /* enough pkts to be sent */
    if (unlikely(len == MAX_PKT_BURST)) {
        dpdk_output_burst(len, port);
        len = 0;
    }

    tx_mbufs[port].len = len;
    pthread_mutex_unlock(&tx_mutex);
    return 0;
}

/* main processing loop */
int get_packets(RouterPacket *packets, int min_packets, int max_packets, int timeout)
{
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    struct rte_mbuf *m;
    struct rte_mbuf *m_next;
    uint64_t diff_tsc, cur_tsc, start_tsc;
    static uint64_t prev_tsc;
    unsigned i, portid, nb_rx, nb_ports;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
    const uint64_t timeout_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * timeout;
    int count = 0;

    start_tsc = rte_rdtsc();
    nb_ports = rte_eth_dev_count();

    while (count < min_packets) {
        /*
         * TX burst queue drain
         */
        cur_tsc = rte_rdtsc();
        diff_tsc = cur_tsc - prev_tsc;
        if (unlikely(diff_tsc > drain_tsc)) {
            pthread_mutex_lock(&tx_mutex);
            for (portid = 0; portid < nb_ports; portid++) {
                if (tx_mbufs[portid].len == 0)
                    continue;
                dpdk_output_burst(tx_mbufs[portid].len, (uint8_t) portid);
                tx_mbufs[portid].len = 0;
            }
            pthread_mutex_unlock(&tx_mutex);
            prev_tsc = cur_tsc;
        }

        /*
         * NIC lcore
         * Read packet from RX queues
         */
        for (portid = 0; portid < nb_ports; portid++) {
            pthread_mutex_lock(&eth_mutex);
            nb_rx = rte_eth_rx_burst((uint8_t) portid, 0,
                    pkts_burst, max_packets - count);
            pthread_mutex_unlock(&eth_mutex);
            for (i = 0; i < nb_rx; i++) {
                m = pkts_burst[i];
                //rte_prefetch0(rte_pktmbuf_mtod(m, void *));
                if(i < nb_rx -1){
                    m_next = pkts_burst[i+1];
                    rte_prefetch0(rte_pktmbuf_mtod(m_next, void *)); //prefetch next packet
                    rte_prefetch0(rte_pktmbuf_mtod(m_next, void *) +64); //prefetch next packet
                }
                if (!handle_packet(&packets[count], m, portid)) {
                    rte_pktmbuf_free(m);
                    pkts_burst[i] = NULL;
                } else {
                    count++;
                }
            }
            if (count == max_packets)
                break;
        }
        if (timeout != -1) {
            cur_tsc = rte_rdtsc();
            if (unlikely(cur_tsc - start_tsc > timeout_tsc))
                break;
        }
    }

    return count;
}

int send_packet(RouterPacket *packet)
{
    struct rte_mbuf *m;
    struct ipv4_hdr *ipv4;
    struct ipv6_hdr *ipv6;
    struct udp_hdr *udp;
    SCIONCommonHeader *sch;
    struct ether_addr *mac = NULL;
    ARPEntry *e;
    uint32_t hop_index;
    int ret;
    uint8_t *hop_addr;

    m = rte_pktmbuf_alloc(hsr_pktmbuf_pool);
    if (!m) {
        zlog_error(zc, "Unable to allocate mbuf");
        return -1;
    }

    ipv4 = IPV4_HDR(m);
    ipv6 = IPV6_HDR(m);
    sch = (SCIONCommonHeader *)packet->buf;

    ret = rte_lpm_lookup(next_hop_v4, ntohl(*(uint32_t *)get_ss_addr(packet->dst)), &hop_index);

    if (ret == 0) {
        if (forwarding_table[hop_index].has_ip) {
            hop_addr = forwarding_table[hop_index].ip;
            if (forwarding_table[hop_index].has_mac)
                mac = &forwarding_table[hop_index].mac;
        } else {
            hop_addr = get_ss_addr(packet->dst);
            zlog_debug(zc, "LPM entry with no gateway: %s", inet_ntoa(*(struct in_addr *)hop_addr));
            HASH_FIND(hh, arp_table, hop_addr, ADDR_IPV4_LEN, e);
            if (e)
                mac = &e->mac;
        }
    } else {
        zlog_error(zc, "do not know how to reach %s (error %d)",
                addr_to_str(get_ss_addr(packet->dst), family_to_type(packet->dst->ss_family), NULL),
                ret);
        rte_pktmbuf_free(m);
        return -1;
    }

    if (unlikely(!mac)) {
        struct sockaddr_in6 sin6;
        memset(&sin6, 0, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        // port is at the same offset for sockaddr_in and sockaddr_in6
        sin6.sin6_port = ((struct sockaddr_in *)packet->dst)->sin_port;
        if (packet->dst->ss_family == AF_INET) {
            *(uint16_t *)(sin6.sin6_addr.s6_addr + 10) = 0xffff;
            memcpy(sin6.sin6_addr.s6_addr + 12, hop_addr, ADDR_IPV4_LEN);
        } else {
            memcpy(&sin6.sin6_addr, hop_addr, sizeof(sin6.sin6_addr));
        }
        zlog_debug(zc, "no MAC for %s (port %d), send through socket %d (fd %d)",
                addr_to_str(hop_addr, family_to_type(packet->dst->ss_family), NULL),
                ntohs(sin6.sin6_port), packet->port_id, sockets[packet->port_id]);
        ret = sendto(sockets[packet->port_id], sch, ntohs(sch->total_len), 0,
                (struct sockaddr *)&sin6, sizeof(sin6));
        if (ret < 0) {
            zlog_error(zc, "error in sendto: %s", strerror(errno));
            return -1;
        }
        zlog_debug(zc, "sent %d bytes", ret);
        rte_pktmbuf_free(m);
        return 0;
    }

    m->data_len = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
        sizeof(struct udp_hdr) + ntohs(sch->total_len);
    build_lower_layers(m, packet->port_id, mac, packet, m->data_len);

    // update checksum
    // TODO hardware offloading
    udp = get_udp_hdr(m);
    uint8_t *payload = (uint8_t *)(udp + 1);
    memcpy(payload, packet->buf, ntohs(sch->total_len));
    if (packet->dst->ss_family == AF_INET)
        udp->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4, udp);
    else
        udp->dgram_cksum = rte_ipv6_udptcp_cksum(ipv6, udp);

    zlog_info(zc, "send_packet() packet->port_id=%d, %s:%d",
            packet->port_id,
            inet_ntoa(*(struct in_addr *)&ipv4->dst_addr),
            ntohs(udp->dst_port));

    return dpdk_output_packet(m, packet->port_id);
}

int send_packets(RouterPacket *packets, int count)
{
    int sent = 0;
    int ret;
    int i;
    for (i = 0; i < count; i++) {
        ret = send_packet(&packets[i]);
        if (ret < 0)
            zlog_error(zc, "error occurred while sending packet %d", i);
        else
            sent++;
    }
    return sent;
}

static inline int handle_packet(RouterPacket *packet, struct rte_mbuf *m, uint8_t dpdk_rx_port)
{
    struct ether_hdr *eth = ETH_HDR(m);

    zlog_info(zc, "==== packet received, dpdk port %d", dpdk_rx_port);

    if (!fill_packet(m, dpdk_rx_port, packet))
        return 1;

    zlog_debug(zc, "Non SCION packet: ether_type=%x", ntohs(eth->ether_type));
    if (ntohs(eth->ether_type) == ETHER_TYPE_ARP) {
        struct arp_hdr *arp_hdr = (struct arp_hdr *)(eth + 1);
        zlog_debug(zc, "ARP packet");
        char buf1[30], buf2[30];
        inet_ntop(AF_INET, &arp_hdr->arp_data.arp_sip, buf1, 30);
        inet_ntop(AF_INET, &arp_hdr->arp_data.arp_tip, buf2, 30);
        zlog_debug(zc, "type: %d, src ip: %s, dst ip: %s",
                ntohs(arp_hdr->arp_op), buf1, buf2);
    }
    if (!kni_objs[0])
        return 0;
    zlog_debug(zc, "Forward to kernel");
    rte_kni_tx_burst(kni_objs[dpdk_rx_port], &m, 1);
    return 0;
}

static inline int fill_packet(struct rte_mbuf *m, uint8_t dpdk_rx_port, RouterPacket *packet)
{
    struct ether_hdr *eth = ETH_HDR(m);
    struct ipv4_hdr *ipv4 = IPV4_HDR(m);
    struct ipv6_hdr *ipv6 = IPV6_HDR(m);
    struct udp_hdr *udp = get_udp_hdr(m);
    uint16_t len;

    if (!udp) {
        zlog_debug(zc, "Not UDP packet");
        return -1;
    }

    if (udp->dst_port != ((struct sockaddr_in *)&local_addrs[dpdk_rx_port])->sin_port) {
        zlog_debug(zc, "Incorrect UDP port: %d, expected %d",
                ntohs(udp->dst_port),
                ntohs(((struct sockaddr_in *)&local_addrs[dpdk_rx_port])->sin_port));
        return -1;
    }

    packet->port_id = dpdk_rx_port;

    if (ntohs(eth->ether_type) == ETHER_TYPE_IPv4) {
        struct sockaddr_in *sin = (struct sockaddr_in *)packet->src;
        sin->sin_family = AF_INET;
        sin->sin_port = udp->src_port;
        memcpy(&sin->sin_addr, &ipv4->src_addr, ADDR_IPV4_LEN);
    } else if (ntohs(eth->ether_type) == ETHER_TYPE_IPv6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)packet->src;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = udp->src_port;
        memcpy(&sin6->sin6_addr, &ipv6->src_addr, ADDR_IPV6_LEN);
    }

    len = ntohs(udp->dgram_len) - sizeof(struct udp_hdr);
    memcpy(packet->buf, udp + 1, len);
    packet->buflen = len;
    rte_pktmbuf_free(m);
    return 0;
}

static inline struct udp_hdr *get_udp_hdr(struct rte_mbuf *m)
{
    struct ether_hdr *eth = ETH_HDR(m);
    struct ipv4_hdr *ipv4 = IPV4_HDR(m);
    struct ipv6_hdr *ipv6 = IPV6_HDR(m);

    switch (ntohs(eth->ether_type)) {
        case ETHER_TYPE_IPv4:
            if (ipv4->next_proto_id != IPPROTO_UDP)
                return NULL;
            return (struct udp_hdr *)((uint8_t *)ipv4 +
                    (ipv4->version_ihl & IPV4_HDR_IHL_MASK) * IPV4_IHL_MULTIPLIER);
        case ETHER_TYPE_IPv6:
            if (ipv6->proto != IPPROTO_UDP)
                return NULL;
            return (struct udp_hdr *)(ipv6 + 1);
        default:
            return NULL;
    }
}

/* End of packet handling functions */

/* KNI functions */

void * handle_kni(void *arg)
{
    uint8_t nb_ports = rte_eth_dev_count();
    if (!kni_objs[0]) {
        zlog_info(zc, "nothing for KNI to do");
        return NULL;
    }
    while (1) {
        unsigned i;
        for (i = 0; i < nb_ports; i++) {
            unsigned num;
            struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
            /* Burst rx from kni */
            num = rte_kni_rx_burst(kni_objs[i], pkts_burst, MAX_PKT_BURST);
            if (unlikely(num > MAX_PKT_BURST)) {
                zlog_error(zc, "Error receiving from KNI");
                return NULL;
            }
            if (num > 0) {
                zlog_debug(zc, "%d outgoing packets through KNI", num);
                struct ether_hdr *eth =
                    (struct ether_hdr *)rte_pktmbuf_mtod(pkts_burst[0], uint8_t *);
                zlog_debug(zc, "outgoing kni packet has eth type %x", ntohs(eth->ether_type));
                if (ntohs(eth->ether_type) == ETHER_TYPE_IPv4) {
                    struct ipv4_hdr *ip = IPV4_HDR(pkts_burst[0]);
                    zlog_debug(zc, "ipv4 packet to %s",
                            addr_to_str((uint8_t *)&ip->dst_addr, ADDR_IPV4_TYPE, NULL));
                } else if (ntohs(eth->ether_type) == ETHER_TYPE_IPv6) {
                    struct ipv6_hdr *ip = IPV6_HDR(pkts_burst[0]);
                    zlog_debug(zc, "ipv6 packet to %s",
                            addr_to_str((uint8_t *)&ip->dst_addr, ADDR_IPV6_TYPE, NULL));
                } else if (ntohs(eth->ether_type) == ETHER_TYPE_ARP) {
                    struct arp_hdr *arp_hdr = (struct arp_hdr *)(eth + 1);
                    zlog_debug(zc, "ARP packet");
                    char buf1[30], buf2[30];
                    inet_ntop(AF_INET, &arp_hdr->arp_data.arp_sip, buf1, 30);
                    inet_ntop(AF_INET, &arp_hdr->arp_data.arp_tip, buf2, 30);
                    zlog_debug(zc, "type: %d, src ip: %s, dst ip: %s",
                            ntohs(arp_hdr->arp_op), buf1, buf2);
                }
            }
            unsigned j;
            for (j = 0; j < num; j++)
                dpdk_output_packet(pkts_burst[j], i);
            rte_kni_handle_request(kni_objs[i]);
        }
    }
    return NULL;
}

static inline int setup_kni()
{
    char cmd[100];
    int i;
    int res;
    uint8_t ports = rte_eth_dev_count();

    if (!kni_objs[0])
        return 0;

    pthread_mutex_lock(&netlink_mutex);
    while (!netlink_ready)
        pthread_cond_wait(&netlink_cond, &netlink_mutex);
    pthread_mutex_unlock(&netlink_mutex);

    for (i = 0; i < ports; i++) {
        sprintf(cmd, "sudo brctl addif br%d vEth%d", i, i);
        res = system(cmd);
        zlog_debug(zc, "cmd = %s: res = %d", cmd, res);
        if (res != 0) {
            zlog_fatal(zc, "Error adding interface to bridge. (%s returned %d)", cmd, res);
            return 1;
        }
        sprintf(cmd, "sudo ip link set vEth%d up address %02x:%02x:%02x:%02x:%02x:%02x",
                i,
                hsr_ports_eth_addr[i].addr_bytes[0],
                hsr_ports_eth_addr[i].addr_bytes[1],
                hsr_ports_eth_addr[i].addr_bytes[2],
                hsr_ports_eth_addr[i].addr_bytes[3],
                hsr_ports_eth_addr[i].addr_bytes[4],
                hsr_ports_eth_addr[i].addr_bytes[5]);
        res = system(cmd);
        zlog_debug(zc, "cmd = %s: res = %d", cmd, res);
        if (res != 0) {
            zlog_fatal(zc, "Error bringing up interface. (%s returned %d)", cmd, res);
            return 1;
        }
    }
    return 0;
}

static inline int kni_alloc(uint8_t port_id)
{
    struct rte_kni *kni;
    struct rte_kni_conf conf;
    uint8_t nb_ports = rte_eth_dev_count();

    memset(&conf, 0, sizeof(conf));
    snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%u", port_id);
    conf.core_id = port_id + nb_ports;
    conf.force_bind = 1;
    conf.group_id = (uint16_t)port_id;
    conf.mbuf_size = MAX_PACKET_LEN;
    struct rte_kni_ops ops;
    struct rte_eth_dev_info dev_info;

    memset(&dev_info, 0, sizeof(dev_info));
    rte_eth_dev_info_get(port_id, &dev_info);
    if (!dev_info.pci_dev) {
        // Probably using PCAP driver
        return 0;
    }
    conf.addr = dev_info.pci_dev->addr;
    conf.id = dev_info.pci_dev->id;

    memset(&ops, 0, sizeof(ops));
    ops.port_id = port_id;

    kni = rte_kni_alloc(hsr_pktmbuf_pool, &conf, &ops);

    if (!kni) {
        zlog_fatal(zc, "Fail to create kni for port: %d", port_id);
        return 1;
    }
    kni_objs[port_id] = kni;
    return 0;
}

/*
static inline int kni_free(uint8_t port_id)
{
	rte_kni_release(kni_objs[port_id]);
	rte_eth_dev_stop(port_id);
	return 0;
}
*/

/* End of KNI functions */

/* Netlink socket functions */

void * run_netlink_core(void *arg)
{
    int len;
    char buf[8192];
    unsigned int seq, portid;

    seq = time(NULL);
    pthread_mutex_lock(&netlink_mutex);
    seq = setup_netlink_socket(seq);
    netlink_ready = 1;
    pthread_cond_broadcast(&netlink_cond);
    pthread_mutex_unlock(&netlink_mutex);

    portid = mnl_socket_get_portid(netlink_socket);

    while (1) {
        len = mnl_socket_recvfrom(netlink_socket, buf, sizeof(buf));
        zlog_debug(zc, "read %d bytes from netlink socket", len);
        if (len < 0) {
            zlog_error(zc, "error on netlink socket: %s", strerror(errno));
            return NULL;
        }
        if (len == 0) {
            zlog_debug(zc, "EOF on netlink socket");
            return NULL;
        }

        mnl_cb_run(buf, len, seq++, portid, handle_message, NULL);
    }
    return NULL;
}

static inline unsigned setup_netlink_socket(unsigned seq)
{
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct rtmsg *rtm;
    struct ndmsg *ndm;
    int len;
    unsigned portid;

    netlink_socket = mnl_socket_open(NETLINK_ROUTE);
    if (!netlink_socket) {
        zlog_fatal(zc, "failed to open netlink socket");
        exit(1);
    }
    if (mnl_socket_bind(netlink_socket, RTMGRP_IPV4_ROUTE | RTMGRP_NEIGH,
                MNL_SOCKET_AUTOPID) < 0) {
        zlog_fatal(zc, "failed to bind netlink socket: %s", strerror(errno));
        exit(1);
    }

    portid = mnl_socket_get_portid(netlink_socket);

    zlog_debug(zc, "query routing table, seq = %d", seq);
    memset(buf, 0, MNL_SOCKET_BUFFER_SIZE);
    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_GETROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = ++seq;
    rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
    rtm->rtm_family = AF_INET;
    mnl_socket_sendto(netlink_socket, nlh, nlh->nlmsg_len);
    memset(buf, 0, MNL_SOCKET_BUFFER_SIZE);
    len = mnl_socket_recvfrom(netlink_socket, buf, sizeof(buf));
    mnl_cb_run(buf, len, seq, portid, handle_message, NULL);

    zlog_debug(zc, "query neighbor table, seq = %d", seq);
    memset(buf, 0, MNL_SOCKET_BUFFER_SIZE);
    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_GETNEIGH;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = ++seq;
    ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ndmsg));
    ndm->ndm_family = AF_INET;
    ndm->ndm_state = NUD_REACHABLE;
    mnl_socket_sendto(netlink_socket, nlh, nlh->nlmsg_len);
    len = mnl_socket_recvfrom(netlink_socket, buf, sizeof(buf));
    mnl_cb_run(buf, len, seq, portid, handle_message, NULL);

    return seq;
}

int handle_message(const struct nlmsghdr *nlh, void *data)
{
    zlog_debug(zc, ">>>>> received message %d (type %d) on netlink socket <<<<<",
            nlh->nlmsg_seq, nlh->nlmsg_type);
    switch (nlh->nlmsg_type) {
        case RTM_NEWNEIGH:
            handle_arp_update(nlh);
            break;
        case RTM_NEWROUTE:
            handle_route_update(nlh);
            break;
    }
    return MNL_CB_OK;
}

static int attr_max;

int handle_attributes(const struct nlattr *attr, void *data)
{
    const struct nlattr **attrs = data;
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, attr_max) < 0) {
        zlog_error(zc, "invalid attribute");
        return MNL_CB_ERROR;
    }
    attrs[type] = attr;
    return MNL_CB_OK;
}

static inline void handle_arp_update(const struct nlmsghdr *nlh)
{
    struct nlattr *attrs[NDA_MAX + 1] = {};
    struct ndmsg *ndm = mnl_nlmsg_get_payload(nlh);
    zlog_debug(zc, "new neighbor entry");
    zlog_debug(zc, "family = %d, ifindex = %d, state = %d, flags = %#x, type = %d",
            ndm->ndm_family, ndm->ndm_ifindex, ndm->ndm_state,
            ndm->ndm_flags, ndm->ndm_type);
    attr_max = NDA_MAX;
    if (mnl_attr_parse(nlh, sizeof(*ndm), handle_attributes, attrs) < 0)
        return;
    if (attrs[NDA_DST] && attrs[NDA_LLADDR]) {
        uint32_t *ip = (uint32_t *)mnl_attr_get_payload(attrs[NDA_DST]);
        uint8_t *mac = (uint8_t *)mnl_attr_get_payload(attrs[NDA_LLADDR]);
        if (ndm->ndm_state == NUD_REACHABLE) {
            ARPEntry *e;
            HASH_FIND(hh, arp_table, ip, ADDR_IPV4_LEN, e);
            if (e) {
                ether_addr_copy((struct ether_addr *)mac, &e->mac);
            } else {
                e = (ARPEntry *)malloc(sizeof(ARPEntry));
                memset(e, 0, sizeof(ARPEntry));
                e->ip = *ip;
                ether_addr_copy((struct ether_addr *)mac, &e->mac);
                HASH_ADD(hh, arp_table, ip, ADDR_IPV4_LEN, e);
            }
            zlog_debug(zc, "cached ARP entry for %s",
                    inet_ntoa(*(struct in_addr *)ip));
            size_t i;
            for (i = 0; i < MAX_FORWARDING_ENTRIES; i++) {
                if (!memcmp(forwarding_table[i].ip, ip, ADDR_IPV4_LEN)) {
                    ether_addr_copy(&e->mac, &forwarding_table[i].mac);
                    forwarding_table[i].has_mac = 1;
                }
            }
        }
    }
}

static inline void handle_route_update(const struct nlmsghdr *nlh)
{
    struct nlattr *attrs[RTA_MAX + 1] = {};
    struct rtmsg *rtm = mnl_nlmsg_get_payload(nlh);
    zlog_debug(zc, "new route entry");
    zlog_debug(zc, "family = %d, src len = %d, dst len = %d, table = %d, type = %d",
            rtm->rtm_family, rtm->rtm_src_len, rtm->rtm_dst_len, rtm->rtm_table, rtm->rtm_type);
    attr_max = RTA_MAX;
    if (mnl_attr_parse(nlh, sizeof(struct rtmsg), handle_attributes, attrs) < 0)
        return;
    if (attrs[RTA_DST] && rtm->rtm_type == RTN_UNICAST) {
        struct in_addr *dst = mnl_attr_get_payload(attrs[RTA_DST]);
        uint32_t index = 0;
        int ret = rte_lpm_is_rule_present(next_hop_v4, ntohl(*(uint32_t *)dst),
                rtm->rtm_dst_len, &index);
        if (!ret) {
            if (forwarding_table_top == MAX_FORWARDING_ENTRIES) {
                zlog_warn(zc, "forwarding table full");
                return;
            }
            index = forwarding_table_top++;
        }
        forwarding_table[index].addr_type = ADDR_IPV4_TYPE;
        if (attrs[RTA_GATEWAY]) {
            struct in_addr *gateway = mnl_attr_get_payload(attrs[RTA_GATEWAY]);
            memcpy(forwarding_table[index].ip, gateway, ADDR_IPV4_LEN);
            forwarding_table[index].has_ip = 1;
            ARPEntry *e;
            HASH_FIND(hh, arp_table, gateway, ADDR_IPV4_LEN, e);
            if (e) {
                ether_addr_copy(&forwarding_table[index].mac, &e->mac);
                forwarding_table[index].has_mac = 1;
            }
        }
        ret = rte_lpm_add(next_hop_v4, ntohl(*(uint32_t *)dst), rtm->rtm_dst_len, index);
        if (ret < 0)
            zlog_error(zc, "error adding to lpm: %d", ret);
        else
            zlog_debug(zc, "rule added to lpm for %s/%d", inet_ntoa(*dst), rtm->rtm_dst_len);
    }
}

/* End of netlink socket functions */

/* Network setup functions */

int setup_network(struct sockaddr_storage *addrs, int num_addrs)
{
    struct rte_lpm_config config_v4;
    struct rte_lpm6_config config_v6;
    int i;
    for (i = 0; i < num_addrs; i++) {
        PortEntry *e = (PortEntry *)malloc(sizeof(PortEntry));
        memset(e, 0, sizeof(PortEntry));
        memcpy(e->addr, get_ss_addr(&addrs[i]), MAX_HOST_ADDR_LEN);
        e->portid = i;
        HASH_ADD(hh, addr2port, addr, MAX_HOST_ADDR_LEN, e);
        zlog_debug(zc, "added dpdk port entry for %s",
                addr_to_str(get_ss_addr(&addrs[i]), family_to_type(addrs[i].ss_family), NULL));
        memcpy(&local_addrs[i], &addrs[i], sizeof(struct sockaddr_storage));
    }

    config_v4.max_rules = LPM_V4_MAX_RULES;
    config_v4.number_tbl8s = LPM_V4_TBL8S;
    config_v4.flags = 0;
    next_hop_v4 = rte_lpm_create("HSR_IPv4_LPM", 0, &config_v4);
    if (!next_hop_v4) {
        zlog_fatal(zc, "failed to create IPv4 LPM table");
        return 1;
    }

    config_v6.max_rules = LPM_V6_MAX_RULES;
    config_v6.number_tbl8s = LPM_V6_TBL8S;
    config_v6.flags = 0;
    next_hop_v6 = rte_lpm6_create("HSR_IPv6_LPM", 0, &config_v6);
    if (!next_hop_v6) {
        zlog_fatal(zc, "failed to create IPV6 LPM table");
        return 1;
    }
    return 0;
}

static inline int open_sockets()
{
    int i;
    for (i = 0; i < MAX_DPDK_PORTS; i++) {
        if (local_addrs[i].ss_family == 0) {
            sockets[i] = -1;
            continue;
        }
        sockets[i] = socket(AF_INET6, SOCK_DGRAM, 0);
        if (sockets[i] < 0) {
            zlog_fatal(zc, "unable to open socket: %s", strerror(errno));
            return 1;
        }

        struct sockaddr_in6 sin6;
        memset(&sin6, 0, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port = ((struct sockaddr_in6 *)&local_addrs[i])->sin6_port;
        if (local_addrs[i].ss_family == AF_INET) {
            *(uint16_t *)(sin6.sin6_addr.s6_addr + 10) = 0xffff;
            memcpy(sin6.sin6_addr.s6_addr + 12, get_ss_addr(&local_addrs[i]), ADDR_IPV4_LEN);
        } else {
            memcpy(&sin6.sin6_addr, get_ss_addr(&local_addrs[i]), sizeof(sin6.sin6_addr));
        }
        if (bind(sockets[i], (struct sockaddr *)&sin6, sizeof(sin6)) < 0) {
            zlog_fatal(zc, "error binding socket to addr %s", strerror(errno));
            return 1;
        }
    }
    return 0;
}

/* End of network setup functions */

static inline int eth_addr_type(int family)
{
    switch (family) {
        case AF_INET:
            return ETHER_TYPE_IPv4;
        case AF_INET6:
            return ETHER_TYPE_IPv6;
        default:
            return 0;
    }
    return 0;
}
