// Copyright 2025 SCION Association
//
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include "bpf_helpers.h"

// kfilter: the kernel-side filter. The purpose of this program is to prevent the traffic that goes
// to the AF_PACKET socket from getting to the regular kernel networking stack as well. If it did,
// the kernel would expand resources processing the traffic, generating ICMP responses AND sending
// them!
//
// This is still not ideal because I have yet to find a way to dispatch traffic before it is cloned
// for AF_PACKET handling but after it is turned into an SKB. To solve that problem we would need to
// go to XDP.
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

// k_map_flt tells our bpf program which address/port(s) go to the AF_PACKET socket and therefore
// not to the kernel. Ports must be in network byte order.
//
// The same data is used by sockfilter to perform the opposite filtering. We may have many
// pairs to filter for a given interface. We could have several one-addrPort filters in series,
// but we would easily exceed the number of filters that can be attached to an interface (not
// mentionning this would be inefficient). So we need a map with multiple pairs.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, addrPort); // An IP address and a port number.
  __type(value, __u8); // Nothing. The map is just a set of keys.
  __uint(max_entries, 64);
} k_map_flt SEC(".maps");

// This is a very simple classifier type of filter: it looks at the packet's protocol and dest
// port. If it is UDP and if the port is found in sock_map_filt, then the packet is dropped (because
// the AF_PACKET socket will get and process it).
SEC("tcx/ingress")
int bpf_k_filter(struct __sk_buff *skb)
{
  __u16 ethtype;
  bpf_skb_load_bytes(skb, 12, &ethtype, 2);

  __u8 ipproto;
  addrPort key = {0};

  if (ethtype == 0x0008) {
    bpf_skb_load_bytes(skb, 14 + offsetof(struct iphdr, protocol), &ipproto, 1);
    if (ipproto != IPPROTO_UDP) {
      return -1; // TC_NEXT
    }
    key.type = 4;
    bpf_skb_load_bytes(skb, 14 + offsetof(struct iphdr, daddr), key.ip_addr, 4);
    bpf_skb_load_bytes(skb, 14 + sizeof(struct iphdr) + offsetof(struct udphdr, dest),
        &key.port, 2);
  } else if (ethtype == 0xDD86) {
    bpf_skb_load_bytes(skb, 14 + offsetof(struct ipv6hdr, nexthdr), &ipproto, 1);
    if (ipproto != IPPROTO_UDP) {
      return -1; // TC_NEXT
    }
    key.type = 6;
    bpf_skb_load_bytes(skb, 14 + offsetof(struct ipv6hdr, daddr), key.ip_addr, 16);
    bpf_skb_load_bytes(skb, 14 + sizeof(struct ipv6hdr) + offsetof(struct udphdr, dest),
		       &key.port, 2);
  } else {
      return -1; // TC_NEXT
  }

  __u8 *forbidden = bpf_map_lookup_elem(&k_map_flt, &key);
  if (forbidden == NULL) {
    return -1; // TC_NEXT
  }
  return 2; // TC_DROP
}

// This program only uses non-gpl_only helpers. So we can use our normal license.
char __license[] SEC("license") = "Apache-2.0";
