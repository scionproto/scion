// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025 SCION Association

package ebpf_test

import (
	"net"
	"testing"

	"github.com/gopacket/gopacket/afpacket"
	"github.com/scionproto/scion/private/underlay/ebpf"
	"github.com/stretchr/testify/assert"
)

func TestRawSocket(t *testing.T) {
	// Interface #1 is lo0. Open the next one. We don't really care what it is
	// for this test.
	intf, err := net.InterfaceByIndex(2)
	assert.NoError(t, err)

	afpHandle, err := afpacket.NewTPacket(
		afpacket.OptInterface(intf.Name),
		afpacket.OptFrameSize(4096))

	assert.NoError(t, err)

	filter, err := ebpf.BpfSockFilter(50000)
	assert.NoError(t, err)

	// Attach the program to the raw socket.
	err = afpHandle.SetEBPF(int32(filter))
	assert.NoError(t, err)
}
