// Copyright 2025 SCION Association
//
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/icmpv6.h>
#include "bpf_helpers.h"

// sockfilter: XDP program that redirects packets to AF_XDP sockets.
// The purpose of this program is to redirect packets destined to selected address/port pairs
// directly to userspace via AF_XDP sockets, bypassing the kernel network stack entirely.
// This provides zero-copy user-space packet processing with minimal latency.

typedef struct {
  __u8 ip_addr[16];
  __u16 port; // in network byte order
  __u8 type;
  __u8 padding; // just to make it clear what the real size of the struct is.
} addrPort;

// sock_map_flt tells our bpf program which address/port(s) should be redirected to AF_XDP sockets.
// The ports must be in network byte order.
//
// This is the same data used by kfilter to perform the opposite filtering. We may have several
// pairs to filter for a given AF_XDP socket. We could have several sockets, each with a one-pair
// filter, but we do not want to be bound by that constraint (and it may be less efficient).
// So we need a map with multiple pairs.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, addrPort); // An IP address and a port number.
  __type(value, __u8); // Nothing. The map is just a set of keys.
  __uint(max_entries, 64);
} sock_map_flt SEC(".maps");

// XSKMAP: Special eBPF map type used by AF_XDP.
// Maps RX queue IDs to AF_XDP socket file descriptors.
//
// Key:   queue_id (u32)
// Value: socket FD (u32)
//
// Userspace inserts entries so the kernel knows
// which AF_XDP socket should receive packets for which queue.
struct {
  __uint(type, BPF_MAP_TYPE_XSKMAP);
  __uint(max_entries, 64); // Maximum number of RX queues supported
  __type(key, __u32);      // Queue index
  __type(value, __u32);    // AF_XDP socket FD
} xsks_map SEC(".maps");

// Helper function to copy memory with bounds checking
static __always_inline int safe_memcpy(
  __u8 *dst, const void *src,
  __u32 size,
  const void *data_end
) {
  if ((void *)src + size > data_end)
    return -1;

  for (__u32 i = 0; i < size && i < 16; i++) {
    dst[i] = *((__u8 *)src + i);
  }
  return 0;
}

// XDP program entrypoint.
// This is a hot path that runs for every received packet (!).
SEC("xdp")
int bpf_sock_filter(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  // Parse Ethernet header
  struct ethhdr *eth = data;
  // Verify Ethernet header fits in packet bounds.
  if ((void *)(eth + 1) > data_end)
    return XDP_DROP;

  __u16 ethtype = __builtin_bswap16(eth->h_proto);

  // Accept ARP packets and pass them to the kernel.
  if (ethtype == ETH_P_ARP) {
    return XDP_PASS;
  }

  __u8 ipproto;
  addrPort key = {0};

  // IPv4
  if (ethtype == ETH_P_IP) {
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
      return XDP_DROP;

    ipproto = ip->protocol;

    // Forward non-UDP packets to kernel.
    if (ipproto != IPPROTO_UDP)
      return XDP_PASS;

    key.type = 4;

    // Copy destination IP address.
    if (safe_memcpy(key.ip_addr, &ip->daddr, 4, data_end) < 0)
      return XDP_DROP;

    // Parse UDP header with variable IP header length.
    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
      return XDP_DROP;

    struct udphdr *udp = (void *)((void *)ip + ip_hdr_len);
    if ((void *)(udp + 1) > data_end)
      return XDP_DROP;

    key.port = udp->dest;
  }
  // IPv6
  else if (ethtype == ETH_P_IPV6) {
    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
      return XDP_DROP;

    ipproto = ip6->nexthdr;

    // Accept ICMPv6 packets and pass them to kernel.
    if (ipproto == IPPROTO_ICMPV6)
      return XDP_PASS;

    // Forward non-UDP packets to kernel.
    if (ipproto != IPPROTO_UDP)
      return XDP_PASS;

    key.type = 6;

    // Copy destination IP address.
    if (safe_memcpy(key.ip_addr, &ip6->daddr, 16, data_end) < 0)
      return XDP_DROP;

    struct udphdr *udp = (void *)(ip6 + 1);
    if ((void *)(udp + 1) > data_end)
      return XDP_DROP;

    key.port = udp->dest;
  }
  else {
    // Pass unknown ethertype to kernel.
    return XDP_PASS;
  }

  // Check if this address/port pair should be redirected to AF_XDP
  __u8 *allowed = bpf_map_lookup_elem(&sock_map_flt, &key);
  if (allowed == NULL) {
    // Not in our filter map - pass to kernel
    return XDP_PASS;
  }

  // Redirect to AF_XDP socket for this queue
  __u32 qid = ctx->rx_queue_index;
  return bpf_redirect_map(&xsks_map, qid, 0);
}

// GPL license required for bpf_redirect_map helper
char __license[] SEC("license") = "GPL";
