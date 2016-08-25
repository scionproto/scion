#ifndef LIB_HSR_H
#define LIB_HSR_H

#include <sys/socket.h>

#define MAX_PACKET_LEN 2048

typedef struct {
    uint8_t *buf; // Packet data starting at SCH, size MAX_PACKET_LEN
    struct sockaddr_storage *src; // Overlay src addr
    struct sockaddr_storage *dst; // Overlay dst addr
    uint8_t port_id; // DPDK port index packet came through
} RouterPacket;

/*
 * Create threads needed by router library (if any)
 * router_threads: Number of worker threads created by application for packet handling
 */
void create_lib_threads();
/*
 * Wait on threads created by router library (if any)
 */
void join_lib_threads();
/*
 * Initialize router library
 * argc: Number of command line arguments
 * argv: Command line arguments
 * returns: Number of command line args consumed
 */
int router_init(int argc, char **argv);

/*
 * Get packets from router library
 * packets: Array of packets (data filled in by router library)
 * returns: Number of packets filled in
 */
int get_packets(RouterPacket *packets, int max_packets);
/*
 * Send packet
 * Before calling, packet->src/dst must both be updated to reflect the addresses
 * and ports that will go in the IP/UDP overlay headers.
 * packet: Packet to send
 * returns: 0 on success, -1 on error
 */
int send_packet(RouterPacket *packet);

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
 */
void setup_network(struct sockaddr_storage *addrs, int num_addrs);

#endif
