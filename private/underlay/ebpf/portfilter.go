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
