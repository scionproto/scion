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

package snet

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path/onehop"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/spath"
)

// Payload is the payload of the message, use the different payload type to
// instantiate it.
type Payload interface {
	toLayers(scn *slayers.SCION) []gopacket.SerializableLayer
}

// UDPPayload is a simple UDP payload.
type UDPPayload struct {
	SrcPort, DstPort uint16
	Payload          []byte
}

func (m UDPPayload) toLayers(scn *slayers.SCION) []gopacket.SerializableLayer {
	scn.NextHdr = common.L4UDP
	udp := slayers.UDP{
		UDP: layers.UDP{
			SrcPort: layers.UDPPort(m.SrcPort),
			DstPort: layers.UDPPort(m.DstPort),
		},
	}
	udp.SetNetworkLayerForChecksum(scn)
	return []gopacket.SerializableLayer{&udp, gopacket.Payload(m.Payload)}
}

// SCMPPayload is the interface that all SCMP payloads must implement. It can be
// used to quickly check facts about an SCMP message.
type SCMPPayload interface {
	Payload
	// Type returns the type of the SCMP message as defined in slayers.
	Type() slayers.SCMPType
	// Code returns the code of the SCMP message as defined in slayers.
	Code() slayers.SCMPCode
}

// SCMPExternalInterfaceDown is the message that indicates that an interface is
// down.
type SCMPExternalInterfaceDown struct {
	IA        addr.IA
	Interface uint64
	Payload   []byte
}

func (m SCMPExternalInterfaceDown) toLayers(scn *slayers.SCION) []gopacket.SerializableLayer {
	return toLayers(m, scn,
		&slayers.SCMPExternalInterfaceDown{
			IA:   m.IA,
			IfID: m.Interface,
		},
		m.Payload,
	)
}

// Type returns the SCMP type.
func (SCMPExternalInterfaceDown) Type() slayers.SCMPType {
	return slayers.SCMPTypeExternalInterfaceDown
}

// Code returns the SCMP code.
func (SCMPExternalInterfaceDown) Code() slayers.SCMPCode { return 0 }

// SCMPInternalConnectivityDown is the message that an internal interface is
// down.
type SCMPInternalConnectivityDown struct {
	IA              addr.IA
	Ingress, Egress uint64
	Payload         []byte
}

func (m SCMPInternalConnectivityDown) toLayers(scn *slayers.SCION) []gopacket.SerializableLayer {
	return toLayers(m, scn,
		&slayers.SCMPInternalConnectivityDown{
			IA:      m.IA,
			Ingress: m.Ingress,
			Egress:  m.Egress,
		},
		m.Payload,
	)
}

// Type returns the SCMP type.
func (SCMPInternalConnectivityDown) Type() slayers.SCMPType {
	return slayers.SCMPTypeInternalConnectivityDown
}

// Code returns the SCMP code.
func (SCMPInternalConnectivityDown) Code() slayers.SCMPCode { return 0 }

// SCMPEchoRequest is the SCMP echo request payload.
type SCMPEchoRequest struct {
	Identifier uint16
	SeqNumber  uint16
	Payload    []byte
}

func (m SCMPEchoRequest) toLayers(scn *slayers.SCION) []gopacket.SerializableLayer {
	return toLayers(m, scn,
		&slayers.SCMPEcho{
			Identifier: m.Identifier,
			SeqNumber:  m.SeqNumber,
		},
		m.Payload,
	)
}

// Type returns the SCMP type.
func (SCMPEchoRequest) Type() slayers.SCMPType { return slayers.SCMPTypeEchoRequest }

// Code returns the SCMP code.
func (SCMPEchoRequest) Code() slayers.SCMPCode { return 0 }

// SCMPEchoReply is the SCMP echo reply payload.
type SCMPEchoReply struct {
	Identifier uint16
	SeqNumber  uint16
	Payload    []byte
}

func (m SCMPEchoReply) toLayers(scn *slayers.SCION) []gopacket.SerializableLayer {
	return toLayers(m, scn,
		&slayers.SCMPEcho{
			Identifier: m.Identifier,
			SeqNumber:  m.SeqNumber,
		},
		m.Payload,
	)
}

// Type returns the SCMP type.
func (SCMPEchoReply) Type() slayers.SCMPType { return slayers.SCMPTypeEchoReply }

// Code returns the SCMP code.
func (SCMPEchoReply) Code() slayers.SCMPCode { return 0 }

// SCMPTracerouteRequest is the SCMP traceroute request payload.
type SCMPTracerouteRequest struct {
	Identifier uint16
	Sequence   uint16
}

func (m SCMPTracerouteRequest) toLayers(scn *slayers.SCION) []gopacket.SerializableLayer {
	return toLayers(m, scn,
		&slayers.SCMPTraceroute{
			Identifier: m.Identifier,
			Sequence:   m.Sequence,
		},
		nil,
	)
}

// Type returns the SCMP type.
func (SCMPTracerouteRequest) Type() slayers.SCMPType { return slayers.SCMPTypeTracerouteRequest }

// Code returns the SCMP code.
func (SCMPTracerouteRequest) Code() slayers.SCMPCode { return 0 }

// SCMPTracerouteReply is the SCMP traceroute reply payload.
type SCMPTracerouteReply struct {
	Identifier uint16
	Sequence   uint16
	IA         addr.IA
	Interface  uint64
}

func (m SCMPTracerouteReply) toLayers(scn *slayers.SCION) []gopacket.SerializableLayer {
	return toLayers(m, scn,
		&slayers.SCMPTraceroute{
			Identifier: m.Identifier,
			Sequence:   m.Sequence,
			IA:         m.IA,
			Interface:  m.Interface,
		},
		nil,
	)
}

// Type returns the SCMP type.
func (SCMPTracerouteReply) Type() slayers.SCMPType { return slayers.SCMPTypeTracerouteReply }

// Code returns the SCMP code.
func (SCMPTracerouteReply) Code() slayers.SCMPCode { return 0 }

func toLayers(scmpPld SCMPPayload,
	scn *slayers.SCION, details gopacket.SerializableLayer,
	payload []byte) []gopacket.SerializableLayer {

	scn.NextHdr = common.L4SCMP
	scmp := &slayers.SCMP{TypeCode: slayers.CreateSCMPTypeCode(scmpPld.Type(), scmpPld.Code())}
	scmp.SetNetworkLayerForChecksum(scn)
	l := []gopacket.SerializableLayer{
		scmp,
		details,
	}
	if payload != nil {
		l = append(l, gopacket.Payload(payload))
	}
	return l
}

// Packet describes a SCION packet.
type Packet struct {
	Bytes
	PacketInfo
}

// Decode decodes the Bytes buffer into PacketInfo.
func (p *Packet) Decode() error {
	var (
		scionLayer   slayers.SCION
		udpLayer     slayers.UDP
		scmpLayer    slayers.SCMP
		payloadLayer gopacket.Payload
	)
	parser := gopacket.NewDecodingLayerParser(
		slayers.LayerTypeSCION, &scionLayer, &udpLayer, &scmpLayer, &payloadLayer,
	)
	decoded := make([]gopacket.LayerType, 3)
	// Only return the error if it is not caused by the unregistered SCMP layers.
	if err := parser.DecodeLayers(p.Bytes, &decoded); err != nil {
		if _, ok := err.(gopacket.UnsupportedLayerType); !ok {
			return err
		}
		if len(decoded) == 0 || decoded[len(decoded)-1] != slayers.LayerTypeSCMP {
			return err
		}
	}
	if len(decoded) < 2 {
		return serrors.New("L4 not decoded")
	}
	l4 := decoded[1]
	if l4 != slayers.LayerTypeSCMP && l4 != slayers.LayerTypeSCIONUDP {
		return serrors.New("unknown L4 layer decoded", "type", l4)
	}
	dstAddr, err := scionLayer.DstAddr()
	if err != nil {
		return serrors.WrapStr("extracting destination address", err)
	}
	dstHost, err := netAddrToHostAddr(dstAddr)
	if err != nil {
		return serrors.WrapStr("converting dst address to HostAddr", err)
	}
	srcAddr, err := scionLayer.SrcAddr()
	if err != nil {
		return serrors.WrapStr("extracting source address", err)
	}
	srcHost, err := netAddrToHostAddr(srcAddr)
	if err != nil {
		return serrors.WrapStr("converting src address to HostAddr", err)
	}
	p.Destination = SCIONAddress{IA: scionLayer.DstIA, Host: dstHost}
	p.Source = SCIONAddress{IA: scionLayer.SrcIA, Host: srcHost}
	// A path of length 4 is an empty path, because it only contains the mandatory
	// minimal header. Applications model empty paths via nil, so we return nil here.
	if l := scionLayer.Path.Len(); l > 4 {
		pathCopy := make([]byte, scionLayer.Path.Len())
		if err := scionLayer.Path.SerializeTo(pathCopy); err != nil {
			return serrors.WrapStr("extracting path", err)
		}
		p.Path = spath.NewV2(pathCopy, scionLayer.PathType == slayers.PathTypeOneHop)
	} else {
		p.Path = nil
	}
	switch l4 {
	case slayers.LayerTypeSCIONUDP:
		p.PayloadV2 = UDPPayload{
			SrcPort: uint16(udpLayer.SrcPort),
			DstPort: uint16(udpLayer.DstPort),
			Payload: payloadLayer.Payload(),
		}
	case slayers.LayerTypeSCMP:
		gpkt := gopacket.NewPacket(scmpLayer.Payload, scmpLayer.NextLayerType(),
			gopacket.DecodeOptions{})
		layers := gpkt.Layers()
		if len(layers) == 0 || len(layers) > 2 {
			return serrors.New("invalid number of SCMP layers", "count", len(layers))
		}

		layer := layers[0]
		switch scmpLayer.TypeCode.Type() {
		case slayers.SCMPTypeExternalInterfaceDown:
			v, ok := layer.(*slayers.SCMPExternalInterfaceDown)
			if !ok {
				return serrors.New("invalid SCMP packet",
					"scmp.type", scmpLayer.TypeCode,
					"payload.type", common.TypeOf(layer))
			}
			p.PayloadV2 = SCMPExternalInterfaceDown{
				IA:        v.IA,
				Interface: v.IfID,
				Payload:   v.Payload,
			}
		case slayers.SCMPTypeInternalConnectivityDown:
			v, ok := layer.(*slayers.SCMPInternalConnectivityDown)
			if !ok {
				return serrors.New("invalid SCMP packet",
					"scmp.type", scmpLayer.TypeCode,
					"payload.type", common.TypeOf(layer))
			}
			p.PayloadV2 = SCMPInternalConnectivityDown{
				IA:      v.IA,
				Ingress: v.Ingress,
				Egress:  v.Egress,
				Payload: v.Payload,
			}
		case slayers.SCMPTypeEchoRequest:
			v, ok := layer.(*slayers.SCMPEcho)
			if !ok {
				return serrors.New("invalid SCMP packet",
					"scmp.type", scmpLayer.TypeCode,
					"payload.type", common.TypeOf(layer))
			}
			p.PayloadV2 = SCMPEchoRequest{
				Identifier: v.Identifier,
				SeqNumber:  v.SeqNumber,
				Payload:    v.Payload,
			}
		case slayers.SCMPTypeEchoReply:
			v, ok := layer.(*slayers.SCMPEcho)
			if !ok {
				return serrors.New("invalid SCMP packet",
					"scmp.type", scmpLayer.TypeCode,
					"payload.type", common.TypeOf(layer))
			}
			p.PayloadV2 = SCMPEchoReply{
				Identifier: v.Identifier,
				SeqNumber:  v.SeqNumber,
				Payload:    v.Payload,
			}
		case slayers.SCMPTypeTracerouteRequest:
			v, ok := layer.(*slayers.SCMPTraceroute)
			if !ok {
				return serrors.New("invalid SCMP packet",
					"scmp.type", scmpLayer.TypeCode,
					"payload.type", common.TypeOf(layer))
			}
			p.PayloadV2 = SCMPTracerouteRequest{
				Identifier: v.Identifier,
				Sequence:   v.Sequence,
			}
		case slayers.SCMPTypeTracerouteReply:
			v, ok := layer.(*slayers.SCMPTraceroute)
			if !ok {
				return serrors.New("invalid SCMP packet",
					"scmp.type", scmpLayer.TypeCode,
					"payload.type", common.TypeOf(layer))
			}
			p.PayloadV2 = SCMPTracerouteReply{
				Identifier: v.Identifier,
				Sequence:   v.Sequence,
				IA:         v.IA,
				Interface:  v.Interface,
			}
		default:
			return serrors.New("unhandled SCMP type", "type", scmpLayer.TypeCode)
		}
	}
	return nil
}

// Serialize serializes the PacketInfo into the raw buffer of the packet.
func (p *Packet) Serialize() error {
	p.Prepare()
	if p.Path != nil && !p.Path.IsHeaderV2() {
		return serrors.New("Serialize only works for v2")
	}
	if p.PayloadV2 == nil {
		return serrors.New("no payload set")
	}
	var packetLayers []gopacket.SerializableLayer

	var scionLayer slayers.SCION
	// XXX(scrye): Set version 2 for debugging, although this is not part of the spec. This
	// should be removed once the migration to the new SCION header is finished.
	scionLayer.Version = 2
	// XXX(scrye): Do not set TrafficClass, to keep things simple while we
	// transition to HeaderV2. These should be added once the transition is
	// complete.

	// TODO(lukedirtwalker): Currently just set a pseudo value for the flow ID
	// until we have a better idea of how to set this correctly.
	scionLayer.FlowID = 1
	scionLayer.DstIA = p.Destination.IA
	scionLayer.SrcIA = p.Source.IA
	netDstAddr, err := hostAddrToNetAddr(p.Destination.Host)
	if err != nil {
		return serrors.WrapStr("converting destination addr.HostAddr to net.Addr", err,
			"address", p.Destination.Host)
	}
	if err := scionLayer.SetDstAddr(netDstAddr); err != nil {
		return serrors.WrapStr("setting destination address", err)
	}
	netSrcAddr, err := hostAddrToNetAddr(p.Source.Host)
	if err != nil {
		return serrors.WrapStr("converting source addr.HostAddr to net.Addr", err,
			"address", p.Source.Host)
	}
	if err := scionLayer.SetSrcAddr(netSrcAddr); err != nil {
		return serrors.WrapStr("settting source address", err)
	}
	scionLayer.PathType = slayers.PathTypeSCION

	switch {
	case p.Path == nil:
		// Default nil paths to an empty SCION path
		decodedPath := scion.Decoded{
			Base: scion.Base{
				PathMeta: scion.MetaHdr{},
			},
		}
		scionLayer.Path = &decodedPath
	case p.Path.IsOHP():
		var path onehop.Path
		if err := path.DecodeFromBytes(p.Path.Raw); err != nil {
			return serrors.WrapStr("decoding path", err)
		}
		scionLayer.PathType = slayers.PathTypeOneHop
		scionLayer.Path = &path
	default:
		// Use decoded for simplicity, easier to work with when debugging with delve.
		var decodedPath scion.Decoded
		if err := decodedPath.DecodeFromBytes(p.Path.Raw); err != nil {
			return serrors.WrapStr("decoding path", err)
		}
		scionLayer.Path = &decodedPath
	}
	packetLayers = append(packetLayers, &scionLayer)
	packetLayers = append(packetLayers, p.PayloadV2.toLayers(&scionLayer)...)

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buffer, options, packetLayers...); err != nil {
		return err
	}
	copy(p.Bytes, buffer.Bytes())
	p.Bytes = p.Bytes[:len(buffer.Bytes())]
	return nil
}

// PacketInfo contains the data needed to construct a SCION packet.
//
// This is a high-level structure, and can only be used to create valid
// packets. The documentation for each field specifies cases where
// serialization might fail due to some violation of SCION protocol rules.
type PacketInfo struct {
	// Destination contains the destination address.
	Destination SCIONAddress
	// Source contains the source address. If it is an SVC address, packet
	// serialization will return an error.
	Source SCIONAddress
	// Path contains a SCION forwarding path. The field must be nil or an empty
	// path if the source and destination are inside the same AS.
	//
	// If the source and destination are in different ASes but the path is
	// nil or empty, an error is returned during serialization.
	Path *spath.Path
	// PayloadV2 is the Payload of the message.
	PayloadV2 Payload

	// Deprecated V1 fields:

	// Extensions contains SCION HBH and E2E extensions. When received from a
	// RawSCIONConn, extensions are present in the order they were found in the packet.
	//
	// When writing to a RawSCIONConn, the serializer will attempt
	// to reorder the extensions, depending on their type, in the correct
	// order. If the number of extensions is over the limit allowed by SCION,
	// serialization will fail. Whenever multiple orders are valid, the stable
	// sorting is preferred. The extensions are sorted in place, so callers
	// should expect the order to change after a write.
	//
	// The SCMP HBH extension needs to be manually included by calling code,
	// even when the L4Header and Payload demand one (as is the case, for
	// example, for a SCMP::General::RecordPathRequest packet).
	Extensions []common.Extension
	// L4Header contains L4 header information.
	L4Header l4.L4Header
	Payload  common.Payload
}

func netAddrToHostAddr(a net.Addr) (addr.HostAddr, error) {
	switch aImpl := a.(type) {
	case *net.IPAddr:
		return addr.HostFromIP(aImpl.IP), nil
	case addr.HostSVC:
		return aImpl, nil
	default:
		return nil, serrors.New("address not supported", "a", a)
	}
}

func hostAddrToNetAddr(a addr.HostAddr) (net.Addr, error) {
	switch aImpl := a.(type) {
	case addr.HostSVC:
		return aImpl, nil
	case addr.HostIPv4, addr.HostIPv6:
		return &net.IPAddr{IP: aImpl.IP()}, nil
	default:
		return nil, serrors.New("address not supported", "a", a)
	}
}
