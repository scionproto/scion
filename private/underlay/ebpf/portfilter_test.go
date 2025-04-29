// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025 SCION Association

package ebpf_test

import (
	"net"
	"os/exec"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/scionproto/scion/private/underlay/ebpf"
	"github.com/stretchr/testify/assert"
)

func makeVethPair(t *testing.T) {
	// The pair
	cmd := exec.Command("ip", "link", "add", "vetha", "type", "veth", "peer", "name", "vethb")
	assert.NoError(t, cmd.Err)
	err := cmd.Run()
	assert.NoError(t, err)

	// Setup etha
	cmd = exec.Command("ip", "addr", "add", "169.254.123.1/24", "broadcast", "169.254.123.255",
		"dev", "vetha", "scope", "link")
	assert.NoError(t, cmd.Err)
	err = cmd.Run()
	assert.NoError(t, err)

	// Setup ethb
	cmd = exec.Command("ip", "addr", "add", "169.254.132.2/24", "broadcast", "169.254.123.255",
		"dev", "vethb", "scope", "link")
	assert.NoError(t, cmd.Err)
	err = cmd.Run()
	assert.NoError(t, err)

	// Fit for duty
	cmd = exec.Command("ip", "link", "set", "vetha", "up")
	assert.NoError(t, cmd.Err)
	err = cmd.Run()
	assert.NoError(t, err)

	cmd = exec.Command("ip", "link", "set", "vethb", "up")
	assert.NoError(t, cmd.Err)
	err = cmd.Run()
	assert.NoError(t, err)
}

func TestRawSocket(t *testing.T) {

	makeVethPair(t)

	// Make two raw sockets. One attached to each end of the veth.
	// On both sides, the filter lets only port 50000 through.

	// Side A
	afpHandleA, err := afpacket.NewTPacket(
		afpacket.OptInterface("vetha"),
		afpacket.OptFrameSize(4096))
	assert.NoError(t, err)
	filterA, err := ebpf.BpfSockFilter(50000)
	assert.NoError(t, err)
	err = afpHandleA.SetEBPF(int32(filterA))
	assert.NoError(t, err)
	rawAddrA, err := net.ResolveUDPAddr("udp4", "169.254.123.1:50000")
	assert.NoError(t, err)

	// packetChanA := gopacket.NewPacketSource(afpHandleA, layers.LinkTypeEthernet).Packets()
	// Side B
	afpHandleB, err := afpacket.NewTPacket(
		afpacket.OptInterface("vethB"),
		afpacket.OptFrameSize(4096))
	assert.NoError(t, err)
	filterB, err := ebpf.BpfSockFilter(50000)
	assert.NoError(t, err)
	err = afpHandleB.SetEBPF(int32(filterB))
	assert.NoError(t, err)
	rawAddrB, err := net.ResolveUDPAddr("udp4", "169.254.123.2:50000")
	assert.NoError(t, err)
	packetChanB := gopacket.NewPacketSource(afpHandleA, layers.LinkTypeEthernet).Packets()

	// Open two ordinary udp sockets. Those listen to port 50001. The filter does not apply, so they
	// should receive that traffic.
	ipAddrA, err := net.ResolveUDPAddr("udp4", "169.254.123.1:50001")
	assert.NoError(t, err)
	connA, err := net.ListenUDP("udp4", ipAddrA)
	assert.NoError(t, err)

	ipAddrB, err := net.ResolveUDPAddr("udp4", "169.254.123.2:50001")
	assert.NoError(t, err)
	connB, err := net.ListenUDP("udp4", ipAddrB)
	assert.NoError(t, err)

	// Now, check what we can and cannot receive and where.
	buf := make([]byte, 256)

	// Via normal sockets to port 50001
	_, err = connA.WriteTo([]byte("hello"), ipAddrB)
	assert.NoError(t, err)
	connB.SetReadDeadline(time.Now().Add(time.Second))
	_, _, err = connB.ReadFrom(buf)
	assert.NoError(t, err)
	assert.Equal(t, string(buf), "hello")

	// The raw socket shouldn't have gotten anything.
	_, ok := <-packetChanB
	assert.False(t, ok)

	// Via raw sockets to port 5000
	pkt := mkPacket(rawAddrA, rawAddrB)
	err = afpHandleA.WritePacketData(pkt)
	assert.NoError(t, err)
	_, ok = <-packetChanB
	assert.True(t, ok)

	// The regular socket can't possibly get that:
	connB.SetReadDeadline(time.Now().Add(time.Second))
	_, _, err = connB.ReadFrom(buf)
	assert.Error(t, err)
}

var pktOptions = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}

func mkPacket(
	src, dst *net.UDPAddr,
) []byte {

	ethernet, ip, udp := Underlay(src, dst)
	sb := gopacket.NewSerializeBuffer()
	payload := []byte("hello")
	err := gopacket.SerializeLayers(sb, pktOptions, ethernet, ip, udp, gopacket.Payload(payload))
	if err != nil {
		panic(err)
	}
	return sb.Bytes()
}

func Underlay(src, dst *net.UDPAddr) (*layers.Ethernet, *layers.IPv4, *layers.UDP) {
	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x1, 0x1},
		DstMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x2, 0x2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    src.IP,
		DstIP:    dst.IP,
		Protocol: layers.IPProtocolUDP,
		Flags:    layers.IPv4DontFragment,
	}
	udp := &layers.UDP{
		SrcPort: src.Port,
		DstPort: dst.Port,
	}
	_ = udp.SetNetworkLayerForChecksum(ip)

	return ethernet, ip, udp
}
