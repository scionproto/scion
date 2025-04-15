

//go:build ignore

#include <linux/bpf.h>
#include "bpf_helpers.h"

struct {
        __uint(type, BPF_MAP_TYPE_SOCKMAP);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, __u64);
} sock_map_rx SEC(".maps");

// Copyright Red Hat
SEC("sk_skb/verdict")
int bpf_prog_verdict(struct __sk_buff *skb)
{
        __u32 lport = skb->local_port;
        __u32 idx = 0;

        if (lport == 50000)
                return bpf_sk_redirect_map(skb, &sock_map_rx, idx, BPF_F_INGRESS);

        return SK_PASS;
}


char __license[] SEC("license") = "Dual MIT/GPL";

