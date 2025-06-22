// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025 SCION Association

//go:build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include "bpf_helpers.h"

// This tells our bpf program which port goes to the AF_PACKET socket (and not the kernel).
//
// This is a set of port numbers. Those must be in network byte order.
//
// This is the same data used by kfilter to perform the opposite filtering. We may have several
// ports to filter for a given raw socket. We can have several sockets, each with a one-port
// filter, but we do not want to be bound by that constraint (and it may be less efficient).
// So we need a map with multiple ports.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u16); // A port number.
  __type(value, __u8); // Nothing. The map is just a set of keys.
  __uint(max_entries, 64);
} sock_map_flt SEC(".maps");

// AF_PACKET sockets receive cloned traffic; all of it. We drop everything we
// don't want. This is the purpose of this program. In the same time, the
// traffic that we do want also gets to the kernel networking stack. Another
// filter (kfilter.c) has to drop it.
//
// This is far from ideal because I have yet to find a way to dispatch traffic
// before it is cloned for AF_PACKET handling but after it is turned into an
// SKB. To solve that problem we need to go to XDP.
//
// This might not be as bad as it looks though: traffic is cloned via c-o-w
// and it might even not be cloned until the AF_PACKET tap has made a
// drop/keep decision. The traffic that we keep is definitely cloned; so...
// dear cow, a third swiss industry is now counting on you.
//
// This is a very simple socket filter: it looks at the packet's protocol and
// dest port. If it is UDP and if the port is found in sock_map_filt, then the
// packet is accepted. Else, dropped. The userland code just adds allowed ports
// to the map. We also let ARP through (both here and in kfilter).
SEC("socket")
int bpf_sock_filter(struct __sk_buff *skb)
{
  __u16 ethtype;
  bpf_skb_load_bytes(skb, 12, &ethtype, 2);
  if (ethtype == 0x0608) {
    return skb->len;
  }

  __u8 ipproto;
  __u16 portNbo;

  if (ethtype == 0x0008) {
    bpf_skb_load_bytes(skb, 14 + offsetof(struct iphdr, protocol), &ipproto, 1);
    if (ipproto != IPPROTO_UDP) {
      return 0;
    }
    bpf_skb_load_bytes(skb, 14 + sizeof(struct iphdr) + offsetof(struct udphdr, dest), &portNbo, 2);
  } else if (ethtype == 0xDD86) {
    bpf_skb_load_bytes(skb, 14 + offsetof(struct ipv6hdr, nexthdr), &ipproto, 1);
    if (ipproto == IPPROTO_ICMPV6) {
      return skb->len;
    }
    if (ipproto != IPPROTO_UDP) {
      return 0;
    }
    bpf_skb_load_bytes(skb, 14 + sizeof(struct ipv6hdr) + offsetof(struct udphdr, dest),
		       &portNbo, 2);
  } else {
    return 0;
  }

  __u8 *allowed = bpf_map_lookup_elem(&sock_map_flt, &portNbo);
  if (allowed == NULL) {
      return 0;
  }
  return skb->len;
}

// This program only uses non-gpl_only helpers. So we can use our normal license.
char __license[] SEC("license") = "Apache-2.0";
