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

package main

import (
	"net"

	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
)

type jsonConfig struct {
	Ethernet struct {
		SrcMAC, DstMAC string
		EthernetType   uint16
	} `json:"ethernet"`
	IPv4 struct {
		SrcIP, DstIP string
		TOS          uint8
		TTL          *uint8
	} `json:"ipv4"`
	UDP struct {
		SrcPort, DstPort uint16
	} `json:"udp"`
	SCION struct {
		TrafficClass uint8
		FlowID       uint32
	} `json:"scion"`
}

func parseEthernet(cfg *jsonConfig) (*layers.Ethernet, error) {
	src, err := net.ParseMAC(cfg.Ethernet.SrcMAC)
	if err != nil {
		return nil, serrors.Wrap("parsing SrcMAC", err)
	}
	dst, err := net.ParseMAC(cfg.Ethernet.DstMAC)
	if err != nil {
		return nil, serrors.Wrap("parsing DstMAC", err)
	}
	return &layers.Ethernet{
		SrcMAC:       src,
		DstMAC:       dst,
		EthernetType: layers.EthernetType(cfg.Ethernet.EthernetType),
	}, nil
}

func parseIPv4(cfg *jsonConfig) *layers.IPv4 {
	src := net.ParseIP(cfg.IPv4.SrcIP)
	dst := net.ParseIP(cfg.IPv4.DstIP)
	var ttl uint8 = 64
	if cfgTTL := cfg.IPv4.TTL; cfgTTL != nil {
		ttl = *cfgTTL
	}
	return &layers.IPv4{
		Version:  4,
		IHL:      5,
		TOS:      cfg.IPv4.TOS,
		Flags:    layers.IPv4DontFragment,
		Protocol: layers.IPProtocolUDP,
		TTL:      ttl,
		SrcIP:    src,
		DstIP:    dst,
	}
}

func parseUDP(cfg *jsonConfig) *layers.UDP {
	return &layers.UDP{
		SrcPort: layers.UDPPort(cfg.UDP.SrcPort),
		DstPort: layers.UDPPort(cfg.UDP.DstPort),
	}
}

func parseSCION(cfg *jsonConfig) *slayers.SCION {
	return &slayers.SCION{
		Version:      0,
		TrafficClass: cfg.SCION.TrafficClass,
		FlowID:       cfg.SCION.FlowID,
		NextHdr:      slayers.L4UDP,
	}
}
