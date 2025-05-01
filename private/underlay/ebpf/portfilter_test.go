// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025 SCION Association

package ebpf_test

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/scionproto/scion/private/underlay/ebpf"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

// Deletes the vethA/B pair if we were the ones to create them.
func delVethPair() {
	linkA, err := netlink.LinkByName("vethA")
	if err == nil {
		err = netlink.LinkDel(linkA)
		if err != nil {
			fmt.Printf("failed to del link: %v\n", err)
		}
	}
}

// call this only once we succesfully created the interface pair...we would not
// want to remove a pre-existing one after failing to ruin it.
func enableCleanup() {
	sigChan := make(chan os.Signal, 2)
	// That doesn't seem to work. Even with the "supports-graceful-termination tag,
	// we still don't get a SIGINT or a SIGTERM; we still get nuked.
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		delVethPair()
		os.Exit(1)
	}()
}

// This requires capability
func makeVethPair(t *testing.T) {
	// Interface pair
	macA, _ := net.ParseMAC("00:12:34:56:78:01")
	macB, _ := net.ParseMAC("00:12:34:56:78:02")
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:         "vethA",
			HardwareAddr: macA,
			TxQLen:       1000,
			MTU:          4096,
			NumTxQueues:  1,
			NumRxQueues:  1,
		},
		PeerName:         "vethB",
		PeerHardwareAddr: macB,
	}
	err := netlink.LinkAdd(veth)
	require.NoError(t, err)
	enableCleanup()

	linkA, err := netlink.LinkByName("vethA")
	require.NoError(t, err)
	linkB, err := netlink.LinkByName("vethB")
	require.NoError(t, err)

	// IP Addresses
	var addressA = &net.IPNet{IP: net.IPv4(169, 254, 123, 1), Mask: net.CIDRMask(24, 32)}
	var addressB = &net.IPNet{IP: net.IPv4(169, 254, 123, 2), Mask: net.CIDRMask(24, 32)}
	err = netlink.AddrAdd(linkA, &netlink.Addr{IPNet: addressA})
	require.NoError(t, err)
	err = netlink.AddrAdd(linkB, &netlink.Addr{IPNet: addressB})
	require.NoError(t, err)

	// Fit for duty
	err = netlink.LinkSetUp(linkA)
	require.NoError(t, err)
	err = netlink.LinkSetUp(linkB)
	require.NoError(t, err)
}

// This requires capabilities CAP_NET_ADMIN, CAP_NET_RAW and CAP_BPF
func TestRawSocket(t *testing.T) {

	makeVethPair(t)
	defer delVethPair()

	// Make two raw sockets. One attached to each end of the veth.
	// On both sides, the filter lets only port 50000 through.

	// Side A
	afpHandleA, err := afpacket.NewTPacket(
		afpacket.OptInterface("vethA"),
		afpacket.OptFrameSize(4096))
	require.NoError(t, err)
	filterA, err := ebpf.BpfSockFilter(50000)
	require.NoError(t, err)
	err = afpHandleA.SetEBPF(int32(filterA))
	require.NoError(t, err)
	rawAddrA, err := net.ResolveUDPAddr("udp4", "169.254.123.1:50000")
	require.NoError(t, err)

	// Side B
	afpHandleB, err := afpacket.NewTPacket(
		afpacket.OptInterface("vethB"),
		afpacket.OptFrameSize(4096))
	require.NoError(t, err)
	filterB, err := ebpf.BpfSockFilter(50000)
	require.NoError(t, err)
	err = afpHandleB.SetEBPF(int32(filterB))
	require.NoError(t, err)
	rawAddrB, err := net.ResolveUDPAddr("udp4", "169.254.123.2:50000")
	require.NoError(t, err)
	packetChanB := gopacket.NewPacketSource(afpHandleB, layers.LinkTypeEthernet).Packets()

	// Open two ordinary udp sockets. Those listen to port 50001. The filter does not apply, so they
	// should receive that traffic.
	ipAddrA, err := net.ResolveUDPAddr("udp4", "169.254.123.1:50001")
	require.NoError(t, err)
	connA, err := net.ListenUDP("udp4", ipAddrA)
	require.NoError(t, err)

	ipAddrB, err := net.ResolveUDPAddr("udp4", "169.254.123.2:50001")
	require.NoError(t, err)
	connB, err := net.ListenUDP("udp4", ipAddrB)
	require.NoError(t, err)

	// Now, check what we can and cannot receive and where.
	buf := make([]byte, 256)

	// Via normal sockets to port 50001
	_, err = connA.WriteTo([]byte("hello"), ipAddrB)
	require.NoError(t, err)
	connB.SetReadDeadline(time.Now().Add(time.Second))
	_, _, err = connB.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, string(buf[:5]), "hello")

	// The raw socket shouldn't have gotten anything.
	afterCh := time.After(1 * time.Second)
	select {
	case <-packetChanB:
		t.Fatal("Received on raw socket\n")
	case <-afterCh:
	}

	// Via raw sockets to port 50000
	pkt := mkPacket(rawAddrA, rawAddrB)
	err = afpHandleA.WritePacketData(pkt)
	require.NoError(t, err)
	afterCh = time.After(1 * time.Second)
	select {
	case <-packetChanB:
	case <-afterCh:
		t.Fatal("Never received on raw socket\n")
	}

	// The regular socket can't possibly get that:
	connB.SetReadDeadline(time.Now().Add(time.Second))
	_, _, err = connB.ReadFrom(buf)
	require.Error(t, err)
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
		SrcPort: layers.UDPPort(src.Port),
		DstPort: layers.UDPPort(dst.Port),
	}
	_ = udp.SetNetworkLayerForChecksum(ip)

	return ethernet, ip, udp
}
