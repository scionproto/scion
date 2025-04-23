

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
// crossed), only traffic destined for that socket is ever seem by this program.
// Which means that all we have to do is to let is through. The goal is simply
// to prevent an af_packet socket from processing all incoming traffic. If that
// works, it is likely that calling the redirect function isn't even necessary.
SEC("sk_skb")
int bpf_port_verdict(struct __sk_buff *skb)
{
  __u64 key = (__u64) skb->local_port;

  bpf_sk_redirect_hash(skb, &sock_map_rx, &key, BPF_F_INGRESS);

  return SK_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
