#ifndef LIB_HSR_H
#define LIB_HSR_H

#include <sys/socket.h>

#define MAX_PACKET_LEN 2048

typedef struct {
    uint8_t *buf; // Packet data starting at SCH, size MAX_PACKET_LEN
    size_t buflen; // Length of data actually written in buf
    struct sockaddr_storage *src; // Overlay src addr
    struct sockaddr_storage *dst; // Overlay dst addr
    uint8_t port_id; // DPDK port index packet came through
} RouterPacket;

/*
 * Create threads needed by router library (if any)
 * router_threads: Number of worker threads created by application for packet handling
 * returns: 0 on success, 1 on error
 */
int create_lib_threads();
/*
 * Wait on threads created by router library (if any)
 */
void join_lib_threads();
/*
 * Initialize router library
 * zlog_cfg: Path to Zlog config
 * zlog_cat: ZLog category name to use
 * argc: Number of command line arguments
 * argv: Command line arguments
 * returns: 0 on success, 1 on error
 */
int router_init(char *zlog_cfg, char *zlog_cat, int argc, char **argv);

/*
 * Get packets from router library
 * packets: Array of packets (data filled in by router library)
 * min_packets: Minimum number of packets to read before returning
 * max_packets: Maximum capacity of packets array
 * timeout: Timeout to return whether min_packets are ready or not, in microseconds (-1 for no timeout)
 * returns: Number of packets filled in
 */
int get_packets(RouterPacket *packets, int min_packets, int max_packets, int timeout);
/*
 * Send packet
 * Before calling, packet->src/dst must both be updated to reflect the addresses
 * and ports that will go in the IP/UDP overlay headers.
 * packet: Packet to send
 * returns: 0 on success, -1 on error
 */
int send_packet(RouterPacket *packet);
/*
 * Send burst of packets
 * Same conditions as send_packet
 * packets: Array of packets to send
 * count: Number of packets in array
 * returns: Number of packets successfully sent
 */
int send_packets(RouterPacket *packets, int count);

/*
 * Miscellaneous network setup - store local/neighbor addresses, setup KNI, etc.
 *
 * The argument 'addrs' is an array of sockaddr_storage structs with 
 * 'num_addrs' elements, each representing an addresses used by the router.
 * These must be sorted by the PCI slot ID of the corresponding NIC in
 * ascending order. For now HSR assumes a one-to-one mapping between IP and NIC.
 *
 * addrs: Array of addresses used by router
 * num_addrs: Number of router-local addresses in addrs
 * returns: 0 on success, 1 on error
 */
int setup_network(struct sockaddr_storage *addrs, int num_addrs);

#endif
