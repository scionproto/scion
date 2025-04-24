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
#include "bpf_helpers.h"

struct {
  __uint(type, BPF_MAP_TYPE_SOCKHASH);
  __type(key, __u64);
  __type(value, __u32);
  __uint(max_entries, 1);
} sock_map_rx SEC(".maps");


// SOCK_HASH maps are meant to process TCP/UDP traffic. The program is only ever
// invoked for packets that match one of the ports in the map. This means that
// in our case the program has no decision to make at all: we just wanted was to
// avoid receiveing the other packets. It is possible that calling the redirect
// function isn't even necessary.
//
// This works because our socket isn't itself bound to any port; it can never
// receive udp traffic via the regular networking stack. If we are lucky, the
// packets that don't pass the filter aren't cloned at all so we don't pay for
// the copy and they're just delivered the regular way.
//
// The packets that we want, though, there's a good chance that they are cloned
// and the original are processed until it's found that there's no port
// listening for them. Dear cow, it's not just the swiss chocolate industry that's
// counting on you.

SEC("sk_skb/verdict")
int bpf_port_verdict(struct __sk_buff *skb)
{
  __u64 key = (__u64) skb->local_port;

  bpf_sk_redirect_hash(skb, &sock_map_rx, &key, BPF_F_INGRESS);

  return SK_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
