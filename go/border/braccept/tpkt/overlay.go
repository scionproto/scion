// Copyright 2018 ETH Zurich
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

package tpkt

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var _ LayerBuilder = (*OverlayIP4UDP)(nil)
var _ LayerMatcher = (*OverlayIP4UDP)(nil)

// OverlayIP4UDP implementes the IPv4/UDP overlay
type OverlayIP4UDP struct {
	SrcAddr string
	SrcPort uint16
	DstAddr string
	DstPort uint16
}

func GenOverlayIP4UDP(SrcAddr string, SrcPort uint16, DstAddr string,
	DstPort uint16) *OverlayIP4UDP {

	return &OverlayIP4UDP{SrcAddr, SrcPort, DstAddr, DstPort}
}

func (o *OverlayIP4UDP) Build() ([]gopacket.SerializableLayer, error) {
	srcIP := net.ParseIP(o.SrcAddr)
	dstIP := net.ParseIP(o.DstAddr)
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	var l []gopacket.SerializableLayer
	l = append(l, ip)
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(o.SrcPort),
		DstPort: layers.UDPPort(o.DstPort),
	}
	l = append(l, udp)
	udp.SetNetworkLayerForChecksum(ip)
	return l, nil
}

func (o *OverlayIP4UDP) Match(l []gopacket.Layer, lc *LayerCache) ([]gopacket.Layer, error) {
	overlayLayers, err := o.Build()
	if err != nil {
		return nil, err
	}
	for i := range overlayLayers {
		if err := compareLayer(l[i], overlayLayers[i]); err != nil {
			return l[i:], err
		}
	}
	return l[len(overlayLayers):], nil
}

func compareLayer(act gopacket.Layer, exp gopacket.SerializableLayer) error {
	if exp.LayerType() != act.LayerType() {
		return fmt.Errorf("Wrong Layer Type, expected %s, actuaact %s",
			exp.LayerType(), act.LayerType())
	}
	switch exp.LayerType() {
	case layers.LayerTypeIPv4:
		return compareIP4Layer(act.(*layers.IPv4), exp.(*layers.IPv4))
	case layers.LayerTypeIPv6:
		return compareIP6Layer(act.(*layers.IPv6), exp.(*layers.IPv6))
	case layers.LayerTypeUDP:
		return compareUDPLayer(act.(*layers.UDP), exp.(*layers.UDP))
	}
	return fmt.Errorf("Unknown layer %s", exp.LayerType())
}

func compareIP4Layer(act, exp *layers.IPv4) error {
	return compareIPLayer(act.SrcIP, act.DstIP, exp.SrcIP, exp.DstIP)
}

func compareIP6Layer(act, exp *layers.IPv6) error {
	return compareIPLayer(act.SrcIP, act.DstIP, exp.SrcIP, exp.DstIP)
}

func compareIPLayer(actSrcIP, actDstIP, expSrcIP, expDstIP net.IP) error {
	if !actSrcIP.Equal(expSrcIP) {
		return fmt.Errorf("Wrong Source IP, expected %s, actual %s", expSrcIP, actSrcIP)
	}
	if !actDstIP.Equal(expDstIP) {
		return fmt.Errorf("Wrong Destination IP, expected %s, actual %s", expDstIP, actDstIP)
	}
	return nil
}

func compareUDPLayer(act, exp *layers.UDP) error {
	if act.SrcPort != exp.SrcPort {
		return fmt.Errorf("Wrong UDP Source Port, expected %s, actual %s",
			exp.SrcPort, act.SrcPort)
	}
	if act.DstPort != exp.DstPort {
		return fmt.Errorf("Wrong UDP Destination Port, expected %s, actual %s",
			exp.DstPort, act.DstPort)
	}
	return nil
}
