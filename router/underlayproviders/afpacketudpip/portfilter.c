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
} sock_map_rx SEC(".maps");


// This is strange usage of the sk_redirect_hash concept. We only put one socket
// in the map: the one that the map is attached to. As a result (fingers
// crossed), only traffic destined for that socket is ever seem by this program,
// which means that all we have to do is to let is through. The goal is simply
// to prevent an af_packet socket from processing all incoming traffic. If that
// works, it is likely that calling the redirect function isn't even necessary.
//
// This would work only because what we filter is af_packet traffic; cloned by
// alloc_skb. the original traffic is not delivered here at all, it goes to the
// regular networking stack. If we are lucky, the packets that don't pass the
// filter aren't cloned at all so we don't pay for the copy. The packets that we
// want, though, there's a good chance that they are cloned and the original
// keeps being processed until it's found that there's no port listening for
// them.

SEC("sk_skb")
int bpf_port_verdict(struct __sk_buff *skb)
{
  __u64 key = (__u64) skb->local_port;

  bpf_sk_redirect_hash(skb, &sock_map_rx, &key, BPF_F_INGRESS);

  return SK_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
