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

// Package tpkt contains interfaces, types, and methods that i) allow the creation of potentially
// malformed SCION packets and ii) enable comparison between expected and received SCION packets.
//
// We cannot always use the hpkt package here, since it disallows some forms of malformed packets,
// e.g., by autogenerating the common header from other input.
package tpkt

import (
	"bytes"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/lib/util"
)

// LayerBuilder is used to generate layers to build the packet that will be sent
// to the border router.
type LayerBuilder interface {
	Build() ([]gopacket.SerializableLayer, error)
}

// LayerMatcher is used to compare layers of the received packet against the expected packet.
type LayerMatcher interface {
	Match([]gopacket.Layer, *LayerCache) ([]gopacket.Layer, error)
}

// ExpPkt defines the expected packet from the border router
type ExpPkt struct {
	Dev    string
	Layers []LayerMatcher
}

// Match compares a received pkt versus an expected packet.
func (p *ExpPkt) Match(pkt gopacket.Packet) error {
	var err error
	layerCache := &LayerCache{}
	// Skip first Layer, Ethernet
	pktLayers := pkt.Layers()[1:]
	for _, l := range p.Layers {
		if pktLayers, err = l.Match(pktLayers, layerCache); err != nil {
			return err
		}
	}
	if len(pktLayers) > 0 {
		return fmt.Errorf("Received packet contains extra data")
	}
	return nil
}

// LayerCache contains references to already processes/parsed layers.
// The main use case is upper layer needing to reference data from lower layers,
// ie. UDP/TCP checksum, authentication of parts of the SCION header, etc.
type LayerCache struct {
	scion *ScionLayer
}

// Pkt defines the packet to send to the border router
type Pkt struct {
	Dev    string
	Layers []LayerBuilder
}

// Pack generates the raw bytes from all the layers that compose a packet.
func (p *Pkt) Pack(dstMac net.HardwareAddr) (common.RawBytes, error) {
	var ethType layers.EthernetType
	switch p.Layers[0].(type) {
	case *OverlayIP4UDP:
		ethType = layers.EthernetTypeIPv4
	default:
		return nil, fmt.Errorf("Fail to build the packet, overlay missing.")
	}
	lbs := make([]LayerBuilder, len(p.Layers)+1)
	lbs[0] = newEthernet(dstMac, ethType)
	copy(lbs[1:], p.Layers)
	return serializeLayers(lbs)
}

func serializeLayers(lbs []LayerBuilder) (common.RawBytes, error) {
	var l []gopacket.SerializableLayer
	for _, lb := range lbs {
		layers, err := lb.Build()
		if err != nil {
			return nil, err
		}
		l = append(l, layers...)
	}
	pkt := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(pkt, options, l...); err != nil {
		return nil, err
	}
	return common.RawBytes(pkt.Bytes()), nil
}

var _ LayerBuilder = (*GenCmnHdr)(nil)

type ethernet struct {
	layers.Ethernet
}

func newEthernet(dstMac net.HardwareAddr, ethType layers.EthernetType) *ethernet {
	// The src MAC does not need to be valid
	srcMac, _ := net.ParseMAC("00:00:de:ad:be:ef")
	return &ethernet{layers.Ethernet{
		DstMAC:       dstMac,
		SrcMAC:       srcMac,
		EthernetType: ethType,
	}}
}

func (l *ethernet) Build() ([]gopacket.SerializableLayer, error) {
	return []gopacket.SerializableLayer{l}, nil
}

var _ LayerBuilder = (*GenCmnHdr)(nil)
var _ LayerMatcher = (*GenCmnHdr)(nil)

// GenCmnHdr is a special SCION layer that auto generates the common header values.
type GenCmnHdr struct {
	ScionLayer
}

func NewGenCmnHdr(srcIA, srcHost, dstIA, dstHost string, path *ScnPath,
	nh common.L4ProtocolType) *GenCmnHdr {

	p := &GenCmnHdr{}
	p.CmnHdr.NextHdr = nh
	addrHdr := NewAddrHdr(srcIA, srcHost, dstIA, dstHost)
	if addrHdr != nil {
		p.AddrHdr = *addrHdr
	}
	if path != nil {
		p.Path = *path
	}
	return p
}

func (l *GenCmnHdr) Build() ([]gopacket.SerializableLayer, error) {
	return []gopacket.SerializableLayer{l}, nil
}

func (l *GenCmnHdr) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	l.setCmnHdr()
	l.CmnHdr.TotalLen += uint16(len(b.Bytes()))
	return l.ScionLayer.SerializeTo(b, opts)
}

func (l *GenCmnHdr) Match(pktLayers []gopacket.Layer, lc *LayerCache) ([]gopacket.Layer, error) {
	l.setCmnHdr()
	scn, ok := pktLayers[0].(*ScionLayer)
	if !ok {
		return nil, fmt.Errorf("Wrong layer\nExpected %v\nActual   %v",
			LayerTypeScion, pktLayers[0].LayerType())
	}
	l.CmnHdr.TotalLen += uint16(len(scn.Payload))
	return l.ScionLayer.Match(pktLayers, lc)
}

func (l *GenCmnHdr) setCmnHdr() {
	addrHdrLen := l.AddrHdr.Len()
	hdrLen := spkt.CmnHdrLen + addrHdrLen + l.Path.Len()
	pathOff := spkt.CmnHdrLen + addrHdrLen
	// Auto generate common header values, NextHdr is already set
	l.CmnHdr.Ver = spkt.SCIONVersion
	l.CmnHdr.DstType = l.AddrHdr.DstHost.Type()
	l.CmnHdr.SrcType = l.AddrHdr.SrcHost.Type()
	l.CmnHdr.HdrLen = uint8(hdrLen / common.LineLen)
	l.CmnHdr.TotalLen = uint16(hdrLen)
	if l.Path.Segs != nil {
		l.CmnHdr.CurrInfoF = uint8((pathOff + l.Path.InfOff) / common.LineLen)
		l.CmnHdr.CurrHopF = uint8((pathOff + l.Path.HopOff) / common.LineLen)
	}
}

var _ LayerBuilder = (*UDP)(nil)
var _ LayerMatcher = (*UDP)(nil)

// UDP is a wrapper that implements LayerBuilder and LayerMatcher interfaces
type UDP struct {
	layers.UDP
}

func NewUDP(src, dst uint16, lb LayerBuilder) *UDP {
	udp := &UDP{}
	var pld common.RawBytes
	if lb != nil {
		pld, _ = serializeLayers([]LayerBuilder{lb})
	}
	udp.UDP = layers.UDP{
		SrcPort: layers.UDPPort(src),
		DstPort: layers.UDPPort(dst),
		Length:  uint16(l4.UDPLen + len(pld)),
	}
	udp.Payload = pld
	return udp
}

func (l *UDP) Build() ([]gopacket.SerializableLayer, error) {
	return []gopacket.SerializableLayer{l}, nil
}

func (l *UDP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Disable checksum generation, requires IPv4/IPv6 pseudo-header
	opts.ComputeChecksums = false
	return l.UDP.SerializeTo(b, opts)
}

func (l *UDP) Match(pktLayers []gopacket.Layer, lc *LayerCache) ([]gopacket.Layer, error) {
	udp := pktLayers[0].(*layers.UDP)
	if udp == nil {
		return nil, fmt.Errorf("Wrong layer\nExpected %v\nActual   %v",
			layers.LayerTypeUDP, pktLayers[0].LayerType())
	}
	// Verify that the checksum is valid using the received packet SCION and UDP header,
	// and the expected Payload
	csum := util.Checksum(lc.scion.RawAddrHdr(), []uint8{0, uint8(common.L4UDP)},
		udp.Contents, l.Payload)
	l.Checksum = csum ^ udp.Checksum
	if l.SrcPort != udp.SrcPort || l.DstPort != udp.DstPort || l.Length != udp.Length ||
		csum != 0 {
		return nil, fmt.Errorf("UDP layer mismatch\nExpected %s\nActual   %s",
			gopacket.LayerString(&l.UDP), gopacket.LayerString(udp))
	}
	return pktLayers[1:], nil
}

var _ LayerBuilder = (*Payload)(nil)
var _ LayerMatcher = (*Payload)(nil)

// Payload is a wrapper that implements LayerBuilder and LayerMatcher interfaces
type Payload struct {
	gopacket.Payload
}

func NewPld(pld []byte) *Payload {
	return &Payload{pld}
}

func (l *Payload) Build() ([]gopacket.SerializableLayer, error) {
	return []gopacket.SerializableLayer{l}, nil
}

func (l *Payload) Match(pktLayers []gopacket.Layer, lc *LayerCache) ([]gopacket.Layer, error) {
	pld := pktLayers[0].(*gopacket.Payload)
	if !bytes.Equal(l.Payload, *pld) {
		return nil, fmt.Errorf("Payload does not match")
	}
	return nil, nil
}
