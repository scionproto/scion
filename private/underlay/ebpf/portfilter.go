// Copyright 2025 SCION Association
//
// SPDX-License-Identifier: Apache-2.0

//go:build (386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64 || wasm) && linux

package ebpf

import (
	"github.com/cilium/ebpf"
)

// LoadSockfilterSpec returns the eBPF collection spec for the sockfilter XDP program.
// This is used by AF_XDP to load the XDP program and attach it to a network interface.
func LoadSockfilterSpec() (*ebpf.CollectionSpec, error) {
	return loadSockfilter()
}

// DropReasonNames mirrors the DROP_REASON_* constants in sockfilter.c. The order
// MUST match the C side; userspace reads drop_counters[i] and labels the value
// with DropReasonNames[i].
var DropReasonNames = [...]string{
	"eth_malformed",
	"ip_malformed",
	"udp_malformed",
	"fragment",
}
