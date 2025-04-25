// Copyright 2025 SCION Association
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include "bpf_helpers.h"

// This tells our bpf program which port goes to the AF_PACKET socket.
// 
// This is a very small array; e.g. length 1. So it is just a plain sequence
// of allowed port numbers. Those must be in network byte order.
//
// Since AF_PACKET ports receive cloned traffic, we can just drop everything
// we don't want and the regular networking stack will get it.
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
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32); // Plain int. Index into the array.
  __type(value, __u16); // A port number.
  __uint(max_entries, 1);
} sock_map_flt SEC(".maps");

// This is a very simple socket filter: it looks at the packet's protocol and
// dest port. If it is UDP and if the port is found in sock_map_filt, then the
// packet is accepted. Else, dropped. The userland code just adds allowed ports
// to the map.
SEC("socket")
int bpf_port_filter(struct __sk_buff *skb)
{
  __u8 proto;
  bpf_skb_load_bytes(skb, 14 + offsetof(struct iphdr, protocol), &proto, 1);
  if (proto != IPPROTO_UDP) {
      return 0;
  }
  __u16 portNbo;
  bpf_skb_load_bytes(skb, 14 + sizeof(struct iphdr) + offsetof(struct udphdr, dest), &portNbo, 2);

  __u32 index = 0;
  __u16 *allowedPort = bpf_map_lookup_elem(&sock_map_flt, &index);
  if (allowedPort == NULL || *allowedPort != portNbo) {
    return 0;
  }
  return skb->len;
}

char __license[] SEC("license") = "Dual MIT/GPL";
