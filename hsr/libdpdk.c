#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_log.h>
#include <rte_udp.h>

#include "libdpdk.h"
#include "scion.h"

void initialize_eth_header(struct ether_hdr *eth_hdr, struct ether_addr *src_mac,
        struct ether_addr *dst_mac, uint16_t ether_type,
        uint8_t vlan_enabled, uint16_t van_id)
{
    ether_addr_copy(dst_mac, &eth_hdr->d_addr);
    ether_addr_copy(src_mac, &eth_hdr->s_addr);

    if (vlan_enabled) {
        struct vlan_hdr *vhdr = (struct vlan_hdr *)((uint8_t *)eth_hdr +
                sizeof(struct ether_hdr));

        eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_VLAN);

        vhdr->eth_proto =  rte_cpu_to_be_16(ether_type);
        vhdr->vlan_tci = van_id;
    } else {
        eth_hdr->ether_type = rte_cpu_to_be_16(ether_type);
    }
}

uint16_t initialize_ipv4_header(struct ipv4_hdr *ip_hdr, uint32_t src_addr,
        uint32_t dst_addr, uint16_t pkt_data_len)
{
    uint16_t pkt_len;
    uint16_t *ptr16;
    uint32_t ip_cksum;

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
    ip_hdr->src_addr = rte_cpu_to_be_32(src_addr);
    ip_hdr->dst_addr = rte_cpu_to_be_32(dst_addr);

    /*
     * Compute IP header checksum.
     */
    ptr16 = (uint16_t *)ip_hdr;
    ip_cksum = 0;
    ip_cksum += ptr16[0]; ip_cksum += ptr16[1];
    ip_cksum += ptr16[2]; ip_cksum += ptr16[3];
    ip_cksum += ptr16[4];
    ip_cksum += ptr16[6]; ip_cksum += ptr16[7];
    ip_cksum += ptr16[8]; ip_cksum += ptr16[9];

    /*
     * Reduce 32 bit checksum to 16 bits and complement it.
     */
    ip_cksum = ((ip_cksum & 0xFFFF0000) >> 16) +
        (ip_cksum & 0x0000FFFF);
    ip_cksum %= 65536;
    ip_cksum = (~ip_cksum) & 0x0000FFFF;
    if (ip_cksum == 0)
        ip_cksum = 0xFFFF;
    ip_hdr->hdr_checksum = (uint16_t) ip_cksum;

    return pkt_len;
}

uint16_t initialize_udp_header(struct udp_hdr *udp_hdr, uint16_t src_port,
        uint16_t dst_port, uint16_t pkt_data_len)
{
    uint16_t pkt_len;

    pkt_len = (uint16_t) (pkt_data_len + sizeof(struct udp_hdr));

    udp_hdr->src_port = rte_cpu_to_be_16(src_port);
    udp_hdr->dst_port = rte_cpu_to_be_16(dst_port);
    udp_hdr->dgram_len = rte_cpu_to_be_16(pkt_len);
    udp_hdr->dgram_cksum = 0; /* No UDP checksum. */

    return pkt_len;
}

void copy_buf_to_pkt_segs(void *buf, unsigned len, struct rte_mbuf *pkt,
        unsigned offset)
{
    struct rte_mbuf *seg;
    void *seg_buf;
    unsigned copy_len;

    seg = pkt;
    while (offset >= seg->data_len) {
        offset -= seg->data_len;
        seg = seg->next;
    }
    copy_len = seg->data_len - offset;
    seg_buf = rte_pktmbuf_mtod(seg, char *) + offset;
    while (len > copy_len) {
        rte_memcpy(seg_buf, buf, (size_t) copy_len);
        len -= copy_len;
        buf = ((char *) buf + copy_len);
        seg = seg->next;
        seg_buf = rte_pktmbuf_mtod(seg, void *);
    }
    rte_memcpy(seg_buf, buf, (size_t) len);
}

void copy_buf_to_pkt(void *buf, unsigned len, struct rte_mbuf *pkt, unsigned offset)
{
    if (offset + len <= pkt->data_len) {
        rte_memcpy(rte_pktmbuf_mtod(pkt, char *) + offset, buf, (size_t) len);
        return;
    }
    copy_buf_to_pkt_segs(buf, len, pkt, offset);
}

extern uint32_t interface_ip[];

void build_lower_layers(struct rte_mbuf *pkt, struct ether_addr *eth_addrs,
        struct ether_addr *dst_mac, uint32_t dst_ip, size_t size)
{
    struct ether_hdr eth;
    struct ipv4_hdr ip;
    struct udp_hdr udp;

    /* TODO: Actual dst MAC address? */
    //memset(dst_mac->addr_bytes, 1, ETHER_ADDR_LEN);
    initialize_eth_header(&eth, &eth_addrs[0], dst_mac,
            ETHER_TYPE_IPv4, 0, 0);
    copy_buf_to_pkt(&eth, sizeof(eth), pkt, 0);
    initialize_ipv4_header(&ip,
            interface_ip[0], dst_ip,
            size - sizeof(eth) - sizeof(ip));
    copy_buf_to_pkt(&ip, sizeof(ip), pkt, sizeof(eth));
    initialize_udp_header(&udp,
            SCION_UDP_PORT, SCION_UDP_PORT,
            size - sizeof(eth) - sizeof(ip) - sizeof(udp));
    copy_buf_to_pkt(&udp, sizeof(udp), pkt, sizeof(eth) + sizeof(ip));

    pkt->nb_segs = 1;
    pkt->pkt_len = size;
    pkt->l2_len = sizeof(eth);

    /* TODO: IPv6 */
    pkt->vlan_tci = ETHER_TYPE_IPv4;
    pkt->l3_len = sizeof(ip);
    pkt->ol_flags = PKT_RX_IPV4_HDR;
}

// Check source IP address and return whether the packet is from local network.
// This function is used in case of single-NIC configuration.
uint8_t from_local_socket(struct rte_mbuf *m)
{
    struct ipv4_hdr *ipv4_hdr;
    ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *)+sizeof(
                struct ether_hdr));

    //FIXME
#define LOCAL_NETWORK_ADDRESS IPv4(192,168,0,0)
#define LOCAL_NETMASK htonl(0xffff0000)
    uint32_t network_address = ipv4_hdr->src_addr & LOCAL_NETMASK;
    if(network_address == LOCAL_NETWORK_ADDRESS){
        return 1;
    }
    return 0;
}
