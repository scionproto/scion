// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025 SCION Association

//go:build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include "bpf_helpers.h"

// This tells our bpf program which port(s) goes to the AF_PACKET socket and therefore not to the
// kernel.
//
// This is a set of port numbers. Those must be in network byte order.
//
// This is the same data used by sockfilter to perform the opposite filtering. We may have many
// ports to filter for a given interface. We could have several one-port filters in series, we would
// easily exceed the number of filters that can be attached to an interface (not mentionning this
// would be inefficient). So we need a map with multiple ports.

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u16); // A port number.
  __type(value, __u8); // Nothing. The map is just a set of keys.
  __uint(max_entries, 64);
} k_map_flt SEC(".maps");

// The traffic that goes to the AF_PACKET socket, must not get to the regular kernel networking
// stack; else it will expand resources processing it, generating ICMP responses AND sending them!
// That is the purpose of this program.
// 
// This is a very simple classifier type of filter: it looks at the packet's protocol and dest
// port. If it is UDP and if the port is found in sock_map_filt, then the packet is dropped (because
// the AF_PACKET socket will get and process it).
//
// This is not ideal because I have yet to find a way to dispatch traffic before it is cloned
// for AF_PACKET handling but after it is turned into an SKB. To solve that problem we need to go to
// XDP.
//
// This might not be as bad as it looks though: traffic is cloned via c-o-w and it might even not be
// cloned until the AF_PACKET tap has made a drop/keep decision. The traffic that we keep is
// definitely cloned; so...  dear cow, a third swiss industry is now counting on you.
SEC("tcx/ingress")
int bpf_k_filter(struct __sk_buff *skb)
{
  __u16 ethtype;
  bpf_skb_load_bytes(skb, 12, &ethtype, 2);

  __u8 ipproto;
  __u16 portNbo;

  if (ethtype == 0x0008) {
    bpf_skb_load_bytes(skb, 14 + offsetof(struct iphdr, protocol), &ipproto, 1);

    if (ipproto != IPPROTO_UDP) {
      return -1; // TC_NEXT
    }
    bpf_skb_load_bytes(skb, 14 + sizeof(struct iphdr) + offsetof(struct udphdr, dest),
        &portNbo, 2);
  } else if (ethtype == 0xDD86) {
    bpf_skb_load_bytes(skb, 14 + offsetof(struct ipv6hdr, nexthdr), &ipproto, 1);
    if (ipproto != IPPROTO_UDP) {
      return -1; // TC_NEXT
    }
    bpf_skb_load_bytes(skb, 14 + sizeof(struct ipv6hdr) + offsetof(struct udphdr, dest),
		       &portNbo, 2);
  } else {
      return -1; // TC_NEXT
  }

  __u8 *forbidden = bpf_map_lookup_elem(&k_map_flt, &portNbo);
  if (forbidden == NULL) {
    return -1; // TC_NEXT
  }
  return 2; // TC_DROP
}

// This program only uses non-gpl_only helpers. So we can use our normal license.
char __license[] SEC("license") = "Apache-2.0";
