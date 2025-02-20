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
	"math/rand/v2"

	"github.com/gopacket/gopacket"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
)

// Payload is the payload of the message, use the different payload type to
// instantiate it.
type Payload interface {
	toLayers(scn *slayers.SCION) []gopacket.SerializableLayer
	length() int
}

// UDPPayload is a simple UDP payload.
type UDPPayload struct {
	SrcPort, DstPort uint16
	Payload          []byte
}

func (m UDPPayload) toLayers(scn *slayers.SCION) []gopacket.SerializableLayer {
	scn.NextHdr = slayers.L4UDP
	udp := slayers.UDP{
		SrcPort: m.SrcPort,
		DstPort: m.DstPort,
	}
	udp.SetNetworkLayerForChecksum(scn)
	return []gopacket.SerializableLayer{&udp, gopacket.Payload(m.Payload)}
}

func (m UDPPayload) length() int {
	return 8 + len(m.Payload)
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

// SCMPDestinationUnreachable is the message that a destination is not
// reachable.
type SCMPDestinationUnreachable struct {
	code    slayers.SCMPCode
	Payload []byte
}

func (m SCMPDestinationUnreachable) toLayers(scn *slayers.SCION) []gopacket.SerializableLayer {
	return toLayers(m, scn, &slayers.SCMPDestinationUnreachable{}, m.Payload)
}

// Type returns the SCMP type.
func (SCMPDestinationUnreachable) Type() slayers.SCMPType {
	return slayers.SCMPTypeDestinationUnreachable
}

// Code returns the SCMP code.
func (m SCMPDestinationUnreachable) Code() slayers.SCMPCode { return m.code }

func (m SCMPDestinationUnreachable) length() int {
	return 8 + len(m.Payload)
}

// SCMPPacketTooBig indicates that a packet was too big.
type SCMPPacketTooBig struct {
	MTU     uint16
	Payload []byte
}

func (m SCMPPacketTooBig) toLayers(scn *slayers.SCION) []gopacket.SerializableLayer {
	return toLayers(m, scn, &slayers.SCMPPacketTooBig{MTU: m.MTU}, m.Payload)
}

// Type returns the SCMP type.
func (SCMPPacketTooBig) Type() slayers.SCMPType {
	return slayers.SCMPTypePacketTooBig
}

// Code returns the SCMP code.
func (SCMPPacketTooBig) Code() slayers.SCMPCode { return 0 }

func (m SCMPPacketTooBig) length() int {
	return 8 + len(m.Payload)
}

// SCMPParameterProblem is the SCMP parameter problem message.
type SCMPParameterProblem struct {
	code    slayers.SCMPCode
	Pointer uint16
	Payload []byte
}

func (m SCMPParameterProblem) toLayers(scn *slayers.SCION) []gopacket.SerializableLayer {
	return toLayers(m, scn, &slayers.SCMPParameterProblem{
		Pointer: m.Pointer,
	}, m.Payload)
}

// Type returns the SCMP type.
func (SCMPParameterProblem) Type() slayers.SCMPType {
	return slayers.SCMPTypeParameterProblem
}

// Code returns the SCMP code.
func (m SCMPParameterProblem) Code() slayers.SCMPCode { return m.code }

func (m SCMPParameterProblem) length() int {
	return 8 + len(m.Payload)
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

func (m SCMPExternalInterfaceDown) length() int {
	return 20 + len(m.Payload)
}

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

func (m SCMPInternalConnectivityDown) length() int {
	return 28 + len(m.Payload)
}

const (
	// SCMPIdentifierStart and SCMPIdentiferEnd define the range for Identifiers
	// that should be used for SCMPEchoRequest and SCMPTracerouteRequest,
	// in preparation for a dispatcher-less snet.
	// This range corresponds to the port range used for SCION/UDP by the
	// dispatcher. Using the same range for Identifiers in SCMP requests will
	// allow a router to dispatch SCMP requests based on the Identifier,
	// without risk of interfering with unaware endpoints.
	//
	// WARNING: transitional, this will be removed in the dispatcher-less snet.
	SCMPIdentifierStart = 32768
	SCMPIdentifierEnd   = 65535
)

// RandomSCMPIdentifier returns a random SCMP identifier in the range
// [SCMPIdentifierStart, SCMPIdentifierEnd].
//
// WARNING: This is a transitional helper function, which will be removed
// in the dispatcher-less snet; then, the underlay port must be used as identifier.
func RandomSCMPIdentifer() uint16 {
	id := SCMPIdentifierStart + rand.Int32N(SCMPIdentifierEnd-SCMPIdentifierStart+1)
	return uint16(id)
}

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

func (m SCMPEchoRequest) length() int {
	return 8 + len(m.Payload)
}

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

func (m SCMPEchoReply) length() int {
	return 8 + len(m.Payload)
}

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

func (m SCMPTracerouteRequest) length() int {
	return 24
}

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

func (m SCMPTracerouteReply) length() int {
	return 24
}

func toLayers(scmpPld SCMPPayload,
	scn *slayers.SCION, details gopacket.SerializableLayer,
	payload []byte) []gopacket.SerializableLayer {

	scn.NextHdr = slayers.L4SCMP
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

// RawPath is the unprocessed path that is read from a received SCION packet
//
// Packets that are received on the SCIONPacketConn contain a struct of this
// type in the Path field.
type RawPath struct {
	PathType path.Type
	Raw      []byte
}

// SetPath is a dummy method to implement the DataplanePath interface.
// Consumers of SCIONPacketConn need to extract the path and handle it appropriately.
func (r RawPath) SetPath(s *slayers.SCION) error {
	return serrors.New("snet.RawPath does not support SetPath")
}

// Packet describes a SCION packet.
type Packet struct {
	Bytes
	PacketInfo
}

// Decode decodes the Bytes buffer into PacketInfo.
func (p *Packet) Decode() error {
	var (
		scionLayer slayers.SCION
		hbhLayer   slayers.HopByHopExtnSkipper
		e2eLayer   slayers.EndToEndExtnSkipper
		udpLayer   slayers.UDP
		scmpLayer  slayers.SCMP
	)
	parser := gopacket.NewDecodingLayerParser(
		slayers.LayerTypeSCION, &scionLayer, &hbhLayer, &e2eLayer, &udpLayer, &scmpLayer,
	)
	parser.IgnoreUnsupported = true
	decoded := make([]gopacket.LayerType, 0, 4)
	if err := parser.DecodeLayers(p.Bytes, &decoded); err != nil {
		return err
	}
	if len(decoded) < 2 {
		return serrors.New("L4 not decoded")
	}
	l4 := decoded[len(decoded)-1]
	if l4 != slayers.LayerTypeSCMP && l4 != slayers.LayerTypeSCIONUDP {
		return serrors.New("unknown L4 layer decoded", "type", l4)
	}
	dstAddr, err := scionLayer.DstAddr()
	if err != nil {
		return serrors.Wrap("extracting destination address", err)
	}
	srcAddr, err := scionLayer.SrcAddr()
	if err != nil {
		return serrors.Wrap("extracting source address", err)
	}
	p.Destination = SCIONAddress{IA: scionLayer.DstIA, Host: dstAddr}
	p.Source = SCIONAddress{IA: scionLayer.SrcIA, Host: srcAddr}

	rpath := RawPath{
		PathType: scionLayer.Path.Type(),
	}
	if l := scionLayer.Path.Len(); l != 0 {
		rpath.Raw = make([]byte, l)
		if err := scionLayer.Path.SerializeTo(rpath.Raw); err != nil {
			return serrors.Wrap("extracting path", err)
		}
	}
	p.Path = rpath

	switch l4 {
	case slayers.LayerTypeSCIONUDP:
		p.Payload = UDPPayload{
			SrcPort: udpLayer.SrcPort,
			DstPort: udpLayer.DstPort,
			Payload: udpLayer.Payload,
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
		case slayers.SCMPTypeDestinationUnreachable:
			v, ok := layer.(*slayers.SCMPDestinationUnreachable)
			if !ok {
				return serrors.New("invalid SCMP packet",
					"scmp.type", scmpLayer.TypeCode,
					"payload.type", common.TypeOf(layer))
			}
			p.Payload = SCMPDestinationUnreachable{
				code:    scmpLayer.TypeCode.Code(),
				Payload: v.Payload,
			}
		case slayers.SCMPTypePacketTooBig:
			v, ok := layer.(*slayers.SCMPPacketTooBig)
			if !ok {
				return serrors.New("invalid SCMP packet",
					"scmp.type", scmpLayer.TypeCode,
					"payload.type", common.TypeOf(layer))
			}
			p.Payload = SCMPPacketTooBig{
				MTU:     v.MTU,
				Payload: v.Payload,
			}
		case slayers.SCMPTypeParameterProblem:
			v, ok := layer.(*slayers.SCMPParameterProblem)
			if !ok {
				return serrors.New("invalid SCMP packet",
					"scmp.type", scmpLayer.TypeCode,
					"payload.type", common.TypeOf(layer))
			}
			p.Payload = SCMPParameterProblem{
				code:    scmpLayer.TypeCode.Code(),
				Pointer: v.Pointer,
				Payload: v.Payload,
			}
		case slayers.SCMPTypeExternalInterfaceDown:
			v, ok := layer.(*slayers.SCMPExternalInterfaceDown)
			if !ok {
				return serrors.New("invalid SCMP packet",
					"scmp.type", scmpLayer.TypeCode,
					"payload.type", common.TypeOf(layer))
			}
			p.Payload = SCMPExternalInterfaceDown{
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
			p.Payload = SCMPInternalConnectivityDown{
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
			p.Payload = SCMPEchoRequest{
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
			p.Payload = SCMPEchoReply{
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
			p.Payload = SCMPTracerouteRequest{
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
			p.Payload = SCMPTracerouteReply{
				Identifier: v.Identifier,
				Sequence:   v.Sequence,
				IA:         v.IA,
				Interface:  v.Interface,
			}
		default:
			return serrors.New("unhandled SCMP type", "type", scmpLayer.TypeCode, "src", p.Source)
		}
	}
	return nil
}

// Serialize serializes the PacketInfo into the raw buffer of the packet.
func (p *Packet) Serialize() error {
	p.Prepare()
	if p.Payload == nil {
		return serrors.New("no payload set")
	}
	if p.Path == nil {
		return serrors.New("no path set")
	}
	var packetLayers []gopacket.SerializableLayer

	var scionLayer slayers.SCION
	scionLayer.Version = 0
	// XXX(scrye): Do not set TrafficClass, to keep things simple while we
	// transition to HeaderV2. These should be added once the transition is
	// complete.

	// TODO(lukedirtwalker): Currently just set a pseudo value for the flow ID
	// until we have a better idea of how to set this correctly.
	scionLayer.FlowID = 1
	scionLayer.DstIA = p.Destination.IA
	scionLayer.SrcIA = p.Source.IA
	if err := scionLayer.SetDstAddr(p.Destination.Host); err != nil {
		return serrors.Wrap("setting destination address", err)
	}
	if err := scionLayer.SetSrcAddr(p.Source.Host); err != nil {
		return serrors.Wrap("setting source address", err)
	}

	// XXX(roosd): Currently, this does not take the extension headers
	// into consideration.
	scionLayer.PayloadLen = uint16(p.Payload.length())

	// At this point all the fields in the SCION header apart from the path
	// and path type must be set already.
	if err := p.Path.SetPath(&scionLayer); err != nil {
		return serrors.Wrap("setting path", err)
	}

	packetLayers = append(packetLayers, &scionLayer)
	packetLayers = append(packetLayers, p.Payload.toLayers(&scionLayer)...)

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buffer, options, packetLayers...); err != nil {
		return err
	}
	copy(p.Bytes, buffer.Bytes())
	if len(buffer.Bytes()) > cap(p.Bytes) {
		return serrors.New("packet size is bigger than max possible value ")
	}

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
	// Path contains a SCION forwarding path. This field must not be nil.
	Path DataplanePath
	// Payload is the Payload of the message.
	Payload Payload
}
