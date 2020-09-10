// Copyright 2020 Anapaya Systems
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

package cases

import (
	"hash"
	"net"
	"path/filepath"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/integration/braccept_v2/runner"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
)

// ExternalBFD sends an unbootstrapped BFD message to an external interface
// and expects a bootstrapped BFD message on the same interface.
func ExternalBFD(artifactsDir string, mac hash.Hash) runner.Case {
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef},
		DstMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x13},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.IP{192, 168, 13, 3},
		DstIP:    net.IP{192, 168, 13, 2},
		Protocol: layers.IPProtocolUDP,
		Flags:    layers.IPv4DontFragment,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(40000),
		DstPort: layers.UDPPort(50000),
	}
	udp.SetNetworkLayerForChecksum(ip)
	scionL := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      common.L4BFD,
		PathType:     slayers.PathTypeEmpty,
		Path:         &scion.Decoded{},
	}
	bfd := &layers.BFD{
		Version:               1,
		State:                 layers.BFDStateDown,
		DetectMultiplier:      3,
		MyDiscriminator:       12345,
		YourDiscriminator:     0,
		DesiredMinTxInterval:  1000000,
		RequiredMinRxInterval: 25000,
	}

	// Prepare input packet
	input := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(input, options, ethernet, ip, udp, scionL, bfd)
	if err != nil {
		panic(err)
	}

	// Prepare want packet
	want := gopacket.NewSerializeBuffer()
	ethernet.SrcMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x13}
	ethernet.DstMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef}
	ip.SrcIP = net.IP{192, 168, 13, 2}
	ip.DstIP = net.IP{192, 168, 13, 3}
	udp.SrcPort, udp.DstPort = udp.DstPort, udp.SrcPort
	bfd.State = layers.BFDStateInit
	bfd.YourDiscriminator = 12345
	bfd.DesiredMinTxInterval = 1000

	err = gopacket.SerializeLayers(want, options, ethernet, ip, udp, scionL, bfd)
	if err != nil {
		panic(err)
	}

	return runner.Case{
		Name:              "ExternalBFD",
		WriteTo:           "veth_131_host",
		ReadFrom:          "veth_131_host",
		Input:             input.Bytes(),
		Want:              want.Bytes(),
		StoreDir:          filepath.Join(artifactsDir, "ExternalBFD"),
		IgnoreNonMatching: true,
	}
}

// InternalBFD sends an unbootstrapped BFD message to an internal interface
// and expects a bootstrapped BFD message on the same interface.
func InternalBFD(artifactsDir string, mac hash.Hash) runner.Case {
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef},
		DstMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x01},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.IP{192, 168, 0, 13},
		DstIP:    net.IP{192, 168, 0, 11},
		Protocol: layers.IPProtocolUDP,
		Flags:    layers.IPv4DontFragment,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(30003),
		DstPort: layers.UDPPort(30001),
	}
	udp.SetNetworkLayerForChecksum(ip)
	scionL := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      common.L4BFD,
		PathType:     slayers.PathTypeEmpty,
		Path:         &scion.Decoded{},
	}
	bfd := &layers.BFD{
		Version:               1,
		State:                 layers.BFDStateDown,
		DetectMultiplier:      3,
		MyDiscriminator:       12345,
		YourDiscriminator:     0,
		DesiredMinTxInterval:  1000000,
		RequiredMinRxInterval: 25000,
	}

	// Prepare input packet
	input := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(input, options, ethernet, ip, udp, scionL, bfd)
	if err != nil {
		panic(err)
	}

	// Prepare want packet
	want := gopacket.NewSerializeBuffer()
	ethernet.SrcMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x01}
	ethernet.DstMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef}
	ip.SrcIP = net.IP{192, 168, 0, 11}
	ip.DstIP = net.IP{192, 168, 0, 13}
	udp.SrcPort, udp.DstPort = udp.DstPort, udp.SrcPort
	bfd.State = layers.BFDStateInit
	bfd.YourDiscriminator = 12345
	bfd.DesiredMinTxInterval = 1000

	err = gopacket.SerializeLayers(want, options, ethernet, ip, udp, scionL, bfd)
	if err != nil {
		panic(err)
	}

	return runner.Case{
		Name:              "InternalBFD",
		WriteTo:           "veth_int_host",
		ReadFrom:          "veth_int_host",
		Input:             input.Bytes(),
		Want:              want.Bytes(),
		StoreDir:          filepath.Join(artifactsDir, "InternalBFD"),
		IgnoreNonMatching: true,
	}
}
