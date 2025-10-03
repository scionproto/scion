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
#include "bpf_helpers.h"

// sockfilter: The socket-level filter. The purpose of this program is to ensure that the associated
// AF_PACKET socket processes only the packets destined to selected address/port pairs. AF_PACKET
// sockets receive cloned traffic; all of it. We drop everything we don't want. The traffic that we
// do want also gets to the kernel networking stack. Another filter (kfilter.c) has to drop it.
//
// This is still not ideal because I have yet to find a way to dispatch traffic before it is
// cloned for AF_PACKET handling but after it is turned into an SKB. To solve that problem we need
// to go to XDP.
//
// This might not be as bad as it looks though: traffic is cloned via c-o-w and it might even not be
// cloned until the AF_PACKET tap has made a drop/keep decision. The traffic that we keep is
// definitely cloned; so...  dear cow, a third swiss industry is now counting on you.

typedef struct {
  __u8 ip_addr[16];
  __u16 port; // in network byte order
  __u8 type;
  __u8 padding; // just to make it clear what the real size of the struct is.
} addrPort;

// sock_map_flt tells our bpf program which address/port(s) go to the AF_PACKET socket (and not the
// kernel). The ports must be in network byte order.
//
// This is the same data used by kfilter to perform the opposite filtering. We may have several
// pairs to filter for a given raw socket. We could have several sockets, each with a one-pair
// filter, but we do not want to be bound by that constraint (and it may be less efficient).
// So we need a map with multiple pairs.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, addrPort); // An IP address and a port number.
  __type(value, __u8); // Nothing. The map is just a set of keys.
  __uint(max_entries, 64);
} sock_map_flt SEC(".maps");

// This is a very simple classifier type of filter: it looks at the packet's protocol and dest
// port. If it is UDP and if the port is found in sock_map_filt (or it is icmp), then the packet is
// accepted Otherwise the regular networking stack will have a chance to process it. Note that icmp
// packets are processed by both the regular kernel stack and AF_PACKETS sockets.
SEC("socket")
int bpf_sock_filter(struct __sk_buff *skb)
{
  __u16 ethtype;
  bpf_skb_load_bytes(skb, 12, &ethtype, 2);
  if (ethtype == 0x0608) {
    return skb->len;
  }

  __u8 ipproto;
  addrPort key = {0};

  if (ethtype == 0x0008) {
    bpf_skb_load_bytes(skb, 14 + offsetof(struct iphdr, protocol), &ipproto, 1);
    if (ipproto != IPPROTO_UDP) {
      return 0;
    }
    key.type = 4;
    bpf_skb_load_bytes(skb, 14 + offsetof(struct iphdr, daddr), key.ip_addr, 4);
    bpf_skb_load_bytes(skb, 14 + sizeof(struct iphdr) + offsetof(struct udphdr, dest),
        &key.port, 2);
  } else if (ethtype == 0xDD86) {
    bpf_skb_load_bytes(skb, 14 + offsetof(struct ipv6hdr, nexthdr), &ipproto, 1);
    if (ipproto == IPPROTO_ICMPV6) {
      return skb->len;
    }
    if (ipproto != IPPROTO_UDP) {
      return 0;
    }
    key.type = 6;
    bpf_skb_load_bytes(skb, 14 + offsetof(struct ipv6hdr, daddr), key.ip_addr, 16);
    bpf_skb_load_bytes(skb, 14 + sizeof(struct ipv6hdr) + offsetof(struct udphdr, dest),
		       &key.port, 2);
  } else {
    return 0;
  }

  __u8 *allowed = bpf_map_lookup_elem(&sock_map_flt, &key);
  if (allowed == NULL) {
      return 0;
  }
  return skb->len;
}

// This program only uses non-gpl_only helpers. So we can use our normal license.
char __license[] SEC("license") = "Apache-2.0";
