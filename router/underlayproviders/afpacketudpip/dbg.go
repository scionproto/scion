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

package afpacketudpip

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/scionproto/scion/pkg/log"
)

func DissectAndShow(data []byte, ctx string) {
	// Even the below check has a cost. Careful where you use this function.
	if !zap.L().Core().Enabled(zapcore.Level(log.DebugLevel)) {
		return
	}
	outcome := dissect(data)

	var b strings.Builder

	b.WriteString(ctx)
	b.WriteString(": [\n")
	for _, k := range []string{
		"ethernet", "ARP", "ipv4", "ipv6", "network", "UDP", "icmp6", "transport", "payload"} {
		if v := outcome[k]; v != "" {
			b.WriteString(k)
			b.WriteString(": [")
			b.WriteString(v)
			b.WriteString("]\n")
		}
	}
	b.WriteString("]\n")
	log.Debug(b.String())
}

func dissect(data []byte) map[string]string {
	var ethLayer layers.Ethernet
	var arpLayer layers.ARP
	var icmp6Layer layers.ICMPv6
	var ipv4Layer layers.IPv4
	var ipv6Layer layers.IPv6
	var udpLayer layers.UDP

	outcome := make(map[string]string)

	// Now we need to figure out the real length of the headers and the src addr.
	if err := ethLayer.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		outcome["ethernet"] = fmt.Sprintf("Undecodable. Err: %v. bytes: %v", err, data[0:14])
		return outcome
	}
	data = ethLayer.LayerPayload() // chop off the eth header
	outcome["ethernet"] = EthString(&ethLayer)
	switch ethLayer.EthernetType {
	case layers.EthernetTypeIPv4:
		if err := ipv4Layer.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			outcome["ipv4"] = fmt.Sprintf("Undecodable. Err: %v. bytes: %v", err, data[0:20])
			return outcome
		}
		data = ipv4Layer.LayerPayload() // chop off the ip header
		outcome["ipv4"] = IPv4String(&ipv4Layer)
		if ipv4Layer.Protocol != layers.IPProtocolUDP {
			outcome["transport"] = fmt.Sprintf("Uknown. Proto: %d", ipv4Layer.Protocol)
			return outcome
		}
	case layers.EthernetTypeIPv6:
		if err := ipv6Layer.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			outcome["ipv6"] = fmt.Sprintf("Undecodable. Err: %v. bytes: %v", err, data[0:40])
			return outcome
		}
		outcome["ipv6"] = IPv6String(&ipv6Layer)
		data = ipv6Layer.LayerPayload() // chop off the ip header
		if ipv6Layer.NextHeader == layers.IPProtocolICMPv6 {
			if err := icmp6Layer.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
				outcome["ipcm6"] = fmt.Sprintf("Undecodabe. Err: %v. bytes: %v", err, data[0:16])
				return outcome
			}
			outcome["icmp6"] = ICMP6String(&icmp6Layer)
			return outcome
		} else if ipv6Layer.NextHeader != layers.IPProtocolUDP {
			outcome["transport"] = fmt.Sprintf("Unknown. Proto: %d", ipv4Layer.Protocol)
			return outcome
		}
	case layers.EthernetTypeARP:
		if err := arpLayer.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			outcome["ARP"] = fmt.Sprintf("Undecodable. err: %v. bytes: %v", err, data[0:20])
			return outcome
		}
		outcome["ARP"] = ARPString(&arpLayer)
		return outcome
	default:
		outcome["network"] = fmt.Sprintf("Unknown. Type: %d", ethLayer.EthernetType)
		return outcome
	}
	if err := udpLayer.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		outcome["UDP"] = fmt.Sprintf("Undecodable. err: %v. bytes: %v", err, data[0:8])
		return outcome
	}
	data = udpLayer.LayerPayload() // chop off the udp header. The rest is SCION.
	outcome["UDP"] = UDPString(&udpLayer)

	outcome["payload"] = fmt.Sprintf("%d bytes", len(data))
	return outcome
}

// Gopacket layers don't have pretty String methods
func EthString(l *layers.Ethernet) string {
	return fmt.Sprintf("{Src: %s, Dst: %s, Type: %s}", l.SrcMAC, l.DstMAC, l.EthernetType)
}

func ARPString(l *layers.ARP) string {
	srcIP, _ := netip.AddrFromSlice(l.SourceProtAddress)
	targIP, _ := netip.AddrFromSlice(l.DstProtAddress)

	return fmt.Sprintf(
		"Operation: %v, SenderMAC: %s, SenderIP: %s, TargetMAC: %s, TargetIP: %s",
		l.Operation, net.HardwareAddr(l.SourceHwAddress), srcIP,
		net.HardwareAddr(l.DstHwAddress), targIP,
	)
}

func IPv4String(l *layers.IPv4) string {
	return fmt.Sprintf(
		"{Src: %s, Dst: %s, Protocol: %s, Length: %d}",
		l.SrcIP, l.DstIP, l.Protocol, l.Length,
	)
}

func IPv6String(l *layers.IPv6) string {
	return fmt.Sprintf(
		"{Src: %s, Dst: %s, NextHdr: %s, Length: %d}",
		l.SrcIP, l.DstIP, l.NextHeader, l.Length,
	)
}

func ICMP6String(l *layers.ICMPv6) string {
	data := l.LayerPayload()

	switch l.TypeCode.Type() {
	case layers.ICMPv6TypeNeighborSolicitation:
		var query layers.ICMPv6NeighborSolicitation
		if err := query.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			return fmt.Sprintf("{TypeCode: (%s), Solitation: <broken>}", l.TypeCode)
		}
		return fmt.Sprintf("{TypeCode: (%s), Solicitation: %s}", l.TypeCode, NDPSolString(&query))

	case layers.ICMPv6TypeNeighborAdvertisement:
		var response layers.ICMPv6NeighborAdvertisement
		if err := response.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			return fmt.Sprintf("{TypeCode: (%s), Advertisement: <broken>}", l.TypeCode)
		}
		return fmt.Sprintf(
			"{TypeCode: (%s), Advertisement: %s}",
			l.TypeCode, NDPAdvString(&response),
		)

	default:
		return fmt.Sprintf("{TypeCode: (%s)}", l.TypeCode)
	}
}

func NDPSolString(l *layers.ICMPv6NeighborSolicitation) string {
	var srcMAC net.HardwareAddr

	for _, opt := range l.Options {
		if opt.Type == layers.ICMPv6OptSourceAddress {
			if len(opt.Data) == 6 {
				srcMAC = net.HardwareAddr(opt.Data)
			}
		}
	}
	return fmt.Sprintf("{TargetAddress: %s, opt.SourceMAC: %s}", l.TargetAddress, srcMAC)
}

func NDPAdvString(l *layers.ICMPv6NeighborAdvertisement) string {
	var targetMAC net.HardwareAddr

	for _, opt := range l.Options {
		if opt.Type == layers.ICMPv6OptTargetAddress {
			if len(opt.Data) == 6 {
				targetMAC = net.HardwareAddr(opt.Data)
			}
		}
	}
	return fmt.Sprintf("{TargetAddress: %s, opt.TargetMAC: %s}", l.TargetAddress, targetMAC)
}

func UDPString(l *layers.UDP) string {
	return fmt.Sprintf("{SrcPort: %s, DstPort: %s, Length: %d}", l.SrcPort, l.DstPort, l.Length)
}
