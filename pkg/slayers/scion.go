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

package slayers

import (
	"encoding/binary"
	"net"

	"github.com/google/gopacket"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
	"github.com/scionproto/scion/pkg/slayers/path/epic"
	"github.com/scionproto/scion/pkg/slayers/path/onehop"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

const (
	// LineLen is the length of a SCION header line in bytes.
	LineLen = 4
	// CmnHdrLen is the length of the SCION common header in bytes.
	CmnHdrLen = 12
	// MaxHdrLen is the maximum allowed length of a SCION header in bytes.
	MaxHdrLen = 1020
	// SCIONVersion is the currently supported version of the SCION header format. Different
	// versions are not guaranteed to be compatible to each other.
	SCIONVersion = 0
)

func init() {
	empty.RegisterPath()
	scion.RegisterPath()
	onehop.RegisterPath()
	epic.RegisterPath()
}

// AddrType indicates the type of a host address in the SCION header.
// The AddrType consists of a sub-type and length part, both two bits wide.
// The four possible lengths are 4B (0), 8B (1), 12B (2), or 16B (3) bytes.
// There are four possible sub-types per address length.
type AddrType uint8

// AddrType constants
const (
	T4Ip  AddrType = 0b0000 // T=0, L=0
	T4Svc          = 0b0100 // T=1, L=0
	T16Ip          = 0b0011 // T=0, L=3
)

// Length returns the length of this AddrType value.
func (tl AddrType) Length() int {
	return LineLen * (1 + (int(tl) & 0x3))
}

// BaseLayer is a convenience struct which implements the LayerData and
// LayerPayload functions of the Layer interface.
// Copy-pasted from gopacket/layers (we avoid importing this due its massive size)
type BaseLayer struct {
	// Contents is the set of bytes that make up this layer.  IE: for an
	// Ethernet packet, this would be the set of bytes making up the
	// Ethernet frame.
	Contents []byte
	// Payload is the set of bytes contained by (but not part of) this
	// Layer.  Again, to take Ethernet as an example, this would be the
	// set of bytes encapsulated by the Ethernet protocol.
	Payload []byte
}

// LayerContents returns the bytes of the packet layer.
func (b *BaseLayer) LayerContents() []byte { return b.Contents }

// LayerPayload returns the bytes contained within the packet layer.
func (b *BaseLayer) LayerPayload() []byte { return b.Payload }

// SCION is the header of a SCION packet.
type SCION struct {
	BaseLayer
	// Common Header fields

	// Version is version of the SCION Header. Currently, only 0 is supported.
	Version uint8
	// TrafficClass denotes the traffic class. Its value in a received packet or fragment might be
	// different from the value sent by the packet’s source. The current use of the Traffic Class
	// field for Differentiated Services and Explicit Congestion Notification is specified in
	// RFC2474 and RFC3168
	TrafficClass uint8
	// FlowID is a 20-bit field used by a source to label sequences of packets to be treated in the
	// network as a single flow. It is mandatory to be set.
	FlowID uint32
	// NextHdr  encodes the type of the first header after the SCION header. This can be either a
	// SCION extension or a layer-4 protocol such as TCP or UDP. Values of this field respect and
	// extend IANA’s assigned internet protocol numbers.
	NextHdr L4ProtocolType
	// HdrLen is the length of the SCION header in multiples of 4 bytes. The SCION header length is
	// computed as HdrLen * 4 bytes. The 8 bits of the HdrLen field limit the SCION header to a
	// maximum of 255 * 4 == 1020 bytes.
	HdrLen uint8
	// PayloadLen is the length of the payload in bytes. The payload includes extension headers and
	// the L4 payload. This field is 16 bits long, supporting a maximum payload size of 64KB.
	PayloadLen uint16
	// PathType specifies the type of path in this SCION header.
	PathType path.Type
	// DstAddrType (4 bit) is the type/length of the destination address.
	DstAddrType AddrType
	// SrcAddrType (4 bit) is the type/length of the source address.
	SrcAddrType AddrType

	// Address header fields.

	// DstIA is the destination ISD-AS.
	DstIA addr.IA
	// SrcIA is the source ISD-AS.
	SrcIA addr.IA
	// RawDstAddr is the destination address.
	RawDstAddr []byte
	// RawSrcAddr is the source address.
	RawSrcAddr []byte

	// Path is the path contained in the SCION header. It depends on the PathType field.
	Path path.Path

	pathPool    []path.Path
	pathPoolRaw path.Path
}

func (s *SCION) LayerType() gopacket.LayerType {
	return LayerTypeSCION
}

func (s *SCION) CanDecode() gopacket.LayerClass {
	return LayerClassSCION
}

func (s *SCION) NextLayerType() gopacket.LayerType {
	return scionNextLayerType(s.NextHdr)
}

func (s *SCION) LayerPayload() []byte {
	return s.Payload
}

func (s *SCION) NetworkFlow() gopacket.Flow {
	// TODO(shitz): Investigate how we can use gopacket.Flow.
	return gopacket.Flow{}
}

func (s *SCION) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	scnLen := CmnHdrLen + s.AddrHdrLen() + s.Path.Len()
	if scnLen > MaxHdrLen {
		return serrors.New("header length exceeds maximum",
			"max", MaxHdrLen, "actual", scnLen)
	}
	if scnLen%LineLen != 0 {
		return serrors.New("header length is not an integer multiple of line length",
			"actual", scnLen)
	}
	buf, err := b.PrependBytes(scnLen)
	if err != nil {
		return err
	}
	if opts.FixLengths {
		s.HdrLen = uint8(scnLen / LineLen)
		s.PayloadLen = uint16(len(b.Bytes()) - scnLen)
	}
	// Serialize common header.
	firstLine := uint32(s.Version&0xF)<<28 | uint32(s.TrafficClass)<<20 | s.FlowID&0xFFFFF
	binary.BigEndian.PutUint32(buf[:4], firstLine)
	buf[4] = uint8(s.NextHdr)
	buf[5] = s.HdrLen
	binary.BigEndian.PutUint16(buf[6:8], s.PayloadLen)
	buf[8] = uint8(s.PathType)
	buf[9] = uint8(s.DstAddrType&0x7)<<4 | uint8(s.SrcAddrType&0x7)
	binary.BigEndian.PutUint16(buf[10:12], 0)

	// Serialize address header.
	if err := s.SerializeAddrHdr(buf[CmnHdrLen:]); err != nil {
		return err
	}
	offset := CmnHdrLen + s.AddrHdrLen()

	// Serialize path header.
	return s.Path.SerializeTo(buf[offset:])
}

// DecodeFromBytes decodes the SCION layer. DecodeFromBytes resets the internal state of this layer
// to the state defined by the passed-in bytes. Slices in the SCION layer reference the passed-in
// data, so care should be taken to copy it first should later modification of data be required
// before the SCION layer is discarded.
func (s *SCION) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// Decode common header.
	if len(data) < CmnHdrLen {
		df.SetTruncated()
		return serrors.New("packet is shorter than the common header length",
			"min", CmnHdrLen, "actual", len(data))
	}
	firstLine := binary.BigEndian.Uint32(data[:4])
	s.Version = uint8(firstLine >> 28)
	s.TrafficClass = uint8((firstLine >> 20) & 0xFF)
	s.FlowID = firstLine & 0xFFFFF
	s.NextHdr = L4ProtocolType(data[4])
	s.HdrLen = data[5]
	s.PayloadLen = binary.BigEndian.Uint16(data[6:8])
	s.PathType = path.Type(data[8])
	s.DstAddrType = AddrType(data[9] >> 4 & 0x7)
	s.SrcAddrType = AddrType(data[9] & 0x7)

	// Decode address header.
	if err := s.DecodeAddrHdr(data[CmnHdrLen:]); err != nil {
		df.SetTruncated()
		return err
	}
	addrHdrLen := s.AddrHdrLen()
	offset := CmnHdrLen + addrHdrLen

	// Decode path header.
	var err error
	hdrBytes := int(s.HdrLen) * LineLen
	pathLen := hdrBytes - CmnHdrLen - addrHdrLen
	if pathLen < 0 {
		return serrors.New("invalid header, negative pathLen",
			"hdrBytes", hdrBytes, "addrHdrLen", addrHdrLen, "CmdHdrLen", CmnHdrLen)
	}
	if minLen := offset + pathLen; len(data) < minLen {
		df.SetTruncated()
		return serrors.New("provided buffer is too small", "expected", minLen, "actual", len(data))
	}

	s.Path, err = s.getPath(s.PathType)
	if err != nil {
		return err
	}

	err = s.Path.DecodeFromBytes(data[offset : offset+pathLen])
	if err != nil {
		return err
	}
	s.Contents = data[:hdrBytes]
	s.Payload = data[hdrBytes:]

	return nil
}

// RecyclePaths enables recycling of paths used for DecodeFromBytes. This is
// only useful if the layer itself is reused.
// When this is enabled, the Path instance may be overwritten in
// DecodeFromBytes. No references to Path should be kept in use between
// invocations of DecodeFromBytes.
func (s *SCION) RecyclePaths() {
	if s.pathPool == nil {
		s.pathPool = []path.Path{
			empty.PathType:  empty.Path{},
			onehop.PathType: &onehop.Path{},
			scion.PathType:  &scion.Raw{},
			epic.PathType:   &epic.Path{},
		}
		s.pathPoolRaw = path.NewRawPath()
	}
}

// getPath returns a new or recycled path for pathType
func (s *SCION) getPath(pathType path.Type) (path.Path, error) {
	if s.pathPool == nil {
		return path.NewPath(pathType)
	}
	if int(pathType) < len(s.pathPool) {
		return s.pathPool[pathType], nil
	}
	return s.pathPoolRaw, nil
}

func decodeSCION(data []byte, pb gopacket.PacketBuilder) error {
	scn := &SCION{}
	err := scn.DecodeFromBytes(data, pb)
	if err != nil {
		return err
	}
	pb.AddLayer(scn)
	pb.SetNetworkLayer(scn)
	return pb.NextDecoder(scionNextLayerType(scn.NextHdr))
}

// scionNextLayerType returns the layer type for the given protocol identifier
// in a SCION base header.
func scionNextLayerType(t L4ProtocolType) gopacket.LayerType {
	switch t {
	case HopByHopClass:
		return LayerTypeHopByHopExtn
	case End2EndClass:
		return LayerTypeEndToEndExtn
	default:
		return scionNextLayerTypeL4(t)
	}
}

// scionNextLayerTypeAfterHBH returns the layer type for the given protocol
// identifier in a SCION hop-by-hop extension, excluding (repeated) hop-by-hop
// extensions.
func scionNextLayerTypeAfterHBH(t L4ProtocolType) gopacket.LayerType {
	switch t {
	case HopByHopClass:
		return gopacket.LayerTypeDecodeFailure
	case End2EndClass:
		return LayerTypeEndToEndExtn
	default:
		return scionNextLayerTypeL4(t)
	}
}

// scionNextLayerTypeAfterE2E returns the layer type for the given protocol
// identifier, in a SCION end-to-end extension, excluding (repeated or
// misordered) hop-by-hop extensions or (repeated) end-to-end extensions.
func scionNextLayerTypeAfterE2E(t L4ProtocolType) gopacket.LayerType {
	switch t {
	case HopByHopClass:
		return gopacket.LayerTypeDecodeFailure
	case End2EndClass:
		return gopacket.LayerTypeDecodeFailure
	default:
		return scionNextLayerTypeL4(t)
	}
}

// scionNextLayerTypeL4 returns the layer type for the given layer-4 protocol identifier.
// Does not handle extension header classes.
func scionNextLayerTypeL4(t L4ProtocolType) gopacket.LayerType {
	switch t {
	case L4UDP:
		return LayerTypeSCIONUDP
	case L4SCMP:
		return LayerTypeSCMP
	case L4BFD:
		return layerTypeBFD
	default:
		return gopacket.LayerTypePayload
	}
}

// DstAddr parses the destination address into a net.Addr. The returned net.Addr references data
// from the underlaying layer data. Changing the net.Addr object might lead to inconsistent layer
// information and thus should be treated read-only. Instead, SetDstAddr should be used to update
// the destination address.
func (s *SCION) DstAddr() (net.Addr, error) {
	return parseAddr(s.DstAddrType, s.RawDstAddr)
}

// SrcAddr parses the source address into a net.Addr. The returned net.Addr references data from the
// underlaying layer data. Changing the net.Addr object might lead to inconsistent layer information
// and thus should be treated read-only. Instead, SetDstAddr should be used to update the source
// address.
func (s *SCION) SrcAddr() (net.Addr, error) {
	return parseAddr(s.SrcAddrType, s.RawSrcAddr)
}

// SetDstAddr sets the destination address and updates the DstAddrType field accordingly.
// SetDstAddr takes ownership of dst and callers should not write to it after calling SetDstAddr.
// Changes to dst might leave the layer in an inconsistent state.
func (s *SCION) SetDstAddr(dst net.Addr) error {
	var err error
	s.DstAddrType, s.RawDstAddr, err = packAddr(dst)
	return err
}

// SetSrcAddr sets the source address and updates the DstAddrType field accordingly.
// SetSrcAddr takes ownership of src and callers should not write to it after calling SetSrcAddr.
// Changes to src might leave the layer in an inconsistent state.
func (s *SCION) SetSrcAddr(src net.Addr) error {
	var err error
	s.SrcAddrType, s.RawSrcAddr, err = packAddr(src)
	return err
}

func parseAddr(addrType AddrType, raw []byte) (net.Addr, error) {
	switch addrType {
	case T4Ip:
		return &net.IPAddr{IP: net.IP(raw)}, nil
	case T4Svc:
		return addr.HostSVC(binary.BigEndian.Uint16(raw[:addr.HostLenSVC])), nil
	case T16Ip:
		return &net.IPAddr{IP: net.IP(raw)}, nil
	}
	return nil, serrors.New("unsupported address type/length combination",
		"type", addrType, "len", addrType.Length())
}

func packAddr(hostAddr net.Addr) (AddrType, []byte, error) {
	switch a := hostAddr.(type) {
	case *net.IPAddr:
		if ip := a.IP.To4(); ip != nil {
			return T4Ip, ip, nil
		}
		return T16Ip, a.IP, nil
	case addr.HostSVC:
		return T4Svc, a.PackWithPad(2), nil
	}
	return 0, nil, serrors.New("unsupported address", "addr", hostAddr)
}

// AddrHdrLen returns the length of the address header (destination and source ISD-AS-Host triples)
// in bytes.
func (s *SCION) AddrHdrLen() int {
	return 2*addr.IABytes + s.DstAddrType.Length() + s.SrcAddrType.Length()
}

// SerializeAddrHdr serializes destination and source ISD-AS-Host address triples into the provided
// buffer. The caller must ensure that the correct address types and lengths are set in the SCION
// layer, otherwise the results of this method are undefined.
func (s *SCION) SerializeAddrHdr(buf []byte) error {
	if len(buf) < s.AddrHdrLen() {
		return serrors.New("provided buffer is too small", "expected", s.AddrHdrLen(),
			"actual", len(buf))
	}
	dstAddrBytes := s.DstAddrType.Length()
	srcAddrBytes := s.SrcAddrType.Length()
	offset := 0
	binary.BigEndian.PutUint64(buf[offset:], uint64(s.DstIA))
	offset += addr.IABytes
	binary.BigEndian.PutUint64(buf[offset:], uint64(s.SrcIA))
	offset += addr.IABytes
	copy(buf[offset:offset+dstAddrBytes], s.RawDstAddr)
	offset += dstAddrBytes
	copy(buf[offset:offset+srcAddrBytes], s.RawSrcAddr)

	return nil
}

// DecodeAddrHdr decodes the destination and source ISD-AS-Host address triples from the provided
// buffer. The caller must ensure that the correct address types and lengths are set in the SCION
// layer, otherwise the results of this method are undefined.
func (s *SCION) DecodeAddrHdr(data []byte) error {
	if len(data) < s.AddrHdrLen() {
		return serrors.New("provided buffer is too small", "expected", s.AddrHdrLen(),
			"actual", len(data))
	}
	offset := 0
	s.DstIA = addr.IA(binary.BigEndian.Uint64(data[offset:]))
	offset += addr.IABytes
	s.SrcIA = addr.IA(binary.BigEndian.Uint64(data[offset:]))
	offset += addr.IABytes
	dstAddrBytes := s.DstAddrType.Length()
	srcAddrBytes := s.SrcAddrType.Length()
	s.RawDstAddr = data[offset : offset+dstAddrBytes]
	offset += dstAddrBytes
	s.RawSrcAddr = data[offset : offset+srcAddrBytes]

	return nil
}

// computeChecksum computes the checksum with the SCION pseudo header.
func (s *SCION) computeChecksum(upperLayer []byte, protocol uint8) (uint16, error) {
	if s == nil {
		return 0, serrors.New("SCION header missing")
	}
	csum, err := s.pseudoHeaderChecksum(len(upperLayer), protocol)
	if err != nil {
		return 0, err
	}
	csum = s.upperLayerChecksum(upperLayer, csum)
	folded := s.foldChecksum(csum)
	return folded, nil
}

func (s *SCION) pseudoHeaderChecksum(length int, protocol uint8) (uint32, error) {
	if len(s.RawDstAddr) == 0 {
		return 0, serrors.New("destination address missing")
	}
	if len(s.RawSrcAddr) == 0 {
		return 0, serrors.New("source address missing")
	}
	var csum uint32
	var srcIA, dstIA [8]byte
	binary.BigEndian.PutUint64(srcIA[:], uint64(s.SrcIA))
	binary.BigEndian.PutUint64(dstIA[:], uint64(s.DstIA))
	for i := 0; i < 8; i += 2 {
		csum += uint32(srcIA[i]) << 8
		csum += uint32(srcIA[i+1])
		csum += uint32(dstIA[i]) << 8
		csum += uint32(dstIA[i+1])
	}
	// Address length is guaranteed to be a multiple of 2 by the protocol.
	for i := 0; i < len(s.RawSrcAddr); i += 2 {
		csum += uint32(s.RawSrcAddr[i]) << 8
		csum += uint32(s.RawSrcAddr[i+1])
	}
	for i := 0; i < len(s.RawDstAddr); i += 2 {
		csum += uint32(s.RawDstAddr[i]) << 8
		csum += uint32(s.RawDstAddr[i+1])
	}
	l := uint32(length)
	csum += (l >> 16) + (l & 0xffff)
	csum += uint32(protocol)
	return csum, nil
}

func (s *SCION) upperLayerChecksum(upperLayer []byte, csum uint32) uint32 {
	// Compute safe boundary to ensure we do not access out of bounds.
	// Odd lengths are handled at the end.
	safeBoundary := len(upperLayer) - 1
	for i := 0; i < safeBoundary; i += 2 {
		csum += uint32(upperLayer[i]) << 8
		csum += uint32(upperLayer[i+1])
	}
	if len(upperLayer)%2 == 1 {
		csum += uint32(upperLayer[safeBoundary]) << 8
	}
	return csum
}

func (s *SCION) foldChecksum(csum uint32) uint16 {
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum)
}
