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
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers/path/empty"
	"github.com/scionproto/scion/go/lib/slayers/path/onehop"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
)

const (
	// LineLen is the length of a SCION header line in bytes.
	LineLen = 4
	// CmnHdrLen is the length of the SCION common header in bytes.
	CmnHdrLen = 12
	// SCIONVersion is the currently supported version of the SCION header format. Different
	// versions are not guaranteed to be compatible to each other.
	SCIONVersion = 0
)

// PathType indicates the type of the path contained in the SCION header.
type PathType uint8

func (t PathType) String() string {
	switch t {
	case PathTypeEmpty:
		return "Empty (0)"
	case PathTypeSCION:
		return "SCION (1)"
	case PathTypeOneHop:
		return "OneHop (2)"
	case PathTypeEPIC:
		return "EPIC (3)"
	case PathTypeCOLIBRI:
		return "COLIBRI (4)"
	}
	return fmt.Sprintf("UNKNOWN (%d)", t)
}

// PathType constants
const (
	PathTypeEmpty PathType = iota
	PathTypeSCION
	PathTypeOneHop
	PathTypeEPIC
	PathTypeCOLIBRI
)

// AddrLen indicates the length of a host address in the SCION header. The four possible lengths are
// 4, 8, 12, or 16 bytes.
type AddrLen uint8

// AddrLen constants
const (
	AddrLen4 AddrLen = iota
	AddrLen8
	AddrLen12
	AddrLen16
)

// AddrType indicates the type of a host address of a given length in the SCION header. There are
// four possible types per address length.
type AddrType uint8

// AddrType constants
const (
	T4Ip AddrType = iota
	T4Svc
)

// AddrLen16 types
const (
	T16Ip AddrType = iota
)

// Path is the path contained in the SCION header.
type Path interface {
	// SerializeTo serializes the path into the provided buffer.
	SerializeTo(b []byte) error
	// DecodesFromBytes decodes the path from the provided buffer.
	DecodeFromBytes(b []byte) error
	// Reverse reverses a path such that it can be used in the reversed direction.
	//
	// XXX(shitz): This method should possibly be moved to a higher-level path manipulation package.
	Reverse() error
	// Len returns the length of a path in bytes.
	Len() int
}

// SCION is the header of a SCION packet.
type SCION struct {
	layers.BaseLayer
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
	NextHdr common.L4ProtocolType
	// HdrLen is the length of the SCION header in multiples of 4 bytes. The SCION header length is
	// computed as HdrLen * 4 bytes. The 8 bits of the HdrLen field limit the SCION header to a
	// maximum of 1024 bytes.
	HdrLen uint8
	// PayloadLen is the length of the payload in bytes. The payload includes extension headers and
	// the L4 payload. This field is 16 bits long, supporting a maximum payload size of 64KB.
	PayloadLen uint16
	// PathType specifies the type of path in this SCION header.
	PathType PathType
	// DstAddrType (2 bit) is the type of the destination address.
	DstAddrType AddrType
	// DstAddrLen (2 bit) is the length of the destination address. Supported address length are 4B
	// (0), 8B (1), 12B (2), and 16B (3).
	DstAddrLen AddrLen
	// SrcAddrType (2 bit) is the type of the source address.
	SrcAddrType AddrType
	// SrcAddrLen (2 bit) is the length of the source address. Supported address length are 4B (0),
	// 8B (1), 12B (2), and 16B (3).
	SrcAddrLen AddrLen

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
	Path Path
}

func (s *SCION) LayerType() gopacket.LayerType {
	return LayerTypeSCION
}

func (s *SCION) CanDecode() gopacket.LayerClass {
	return LayerTypeSCION
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
	buf, err := b.PrependBytes(scnLen)
	if err != nil {
		return err
	}
	if opts.FixLengths {
		s.HdrLen = uint8(scnLen / LineLen)
		s.PayloadLen = uint16(len(b.Bytes()) - int(scnLen))
	}
	// Serialize common header.
	firstLine := uint32(s.Version&0xF)<<28 | uint32(s.TrafficClass)<<20 | s.FlowID&0xFFFFF
	binary.BigEndian.PutUint32(buf[:4], firstLine)
	buf[4] = uint8(s.NextHdr)
	buf[5] = s.HdrLen
	binary.BigEndian.PutUint16(buf[6:8], s.PayloadLen)
	buf[8] = uint8(s.PathType)
	buf[9] = uint8(s.DstAddrType&0x3)<<6 | uint8(s.DstAddrLen&0x3)<<4 |
		uint8(s.SrcAddrType&0x3)<<2 | uint8(s.SrcAddrLen&0x3)
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
	s.NextHdr = common.L4ProtocolType(data[4])
	s.HdrLen = data[5]
	s.PayloadLen = binary.BigEndian.Uint16(data[6:8])
	s.PathType = PathType(data[8])
	s.DstAddrType = AddrType(data[9] >> 6)
	s.DstAddrLen = AddrLen(data[9] >> 4 & 0x3)
	s.SrcAddrType = AddrType(data[9] >> 2 & 0x3)
	s.SrcAddrLen = AddrLen(data[9] & 0x3)

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

	switch s.PathType {
	case PathTypeEmpty:
		if _, ok := s.Path.(empty.Path); ok {
			break
		}
		s.Path = empty.Path{}
		if pathLen != 0 {
			return serrors.New("invalid header, non-empty empty path", "hdrBytes", hdrBytes,
				"addrHdrLen", addrHdrLen, "CmdHdrLen", CmnHdrLen, "pathLen", pathLen)
		}
	case PathTypeSCION:
		// Only allocate a SCION path if necessary. This reduces memory allocation and GC overhead
		// considerably (3x improvement for DecodeFromBytes performance)
		if _, ok := s.Path.(*scion.Raw); ok {
			break
		}
		s.Path = &scion.Raw{}
	case PathTypeOneHop:
		if _, ok := s.Path.(*onehop.Path); ok {
			break
		}
		s.Path = &onehop.Path{}
	case PathTypeEPIC, PathTypeCOLIBRI:
		return serrors.New("unsupported path type", "type", s.PathType.String())
	default:
		return serrors.New("unknown path type", "type", s.PathType.String())
	}

	if minLen := offset + pathLen; len(data) < minLen {
		df.SetTruncated()
		return serrors.New("provided buffer is too small", "expected", minLen, "actual", len(data))
	}
	err = s.Path.DecodeFromBytes(data[offset : offset+pathLen])
	if err != nil {
		return err
	}
	s.Contents = data[:hdrBytes]
	s.Payload = data[hdrBytes:]

	return nil
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

func scionNextLayerType(t common.L4ProtocolType) gopacket.LayerType {
	switch t {
	case common.L4UDP:
		return LayerTypeSCIONUDP
	case common.L4SCMP:
		return LayerTypeSCMP
	case common.L4BFD:
		return layers.LayerTypeBFD
	case common.HopByHopClass:
		return LayerTypeHopByHopExtn
	case common.End2EndClass:
		return LayerTypeEndToEndExtn
	default:
		return gopacket.LayerTypePayload
	}
}

// DstAddr parses the destination address into a net.Addr. The returned net.Addr references data
// from the underlaying layer data. Changing the net.Addr object might lead to inconsistent layer
// information and thus should be treated read-only. Instead, SetDstAddr should be used to update
// the destination address.
func (s *SCION) DstAddr() (net.Addr, error) {
	return parseAddr(s.DstAddrType, s.DstAddrLen, s.RawDstAddr)
}

// SrcAddr parses the source address into a net.Addr. The returned net.Addr references data from the
// underlaying layer data. Changing the net.Addr object might lead to inconsistent layer information
// and thus should be treated read-only. Instead, SetDstAddr should be used to update the source
// address.
func (s *SCION) SrcAddr() (net.Addr, error) {
	return parseAddr(s.SrcAddrType, s.SrcAddrLen, s.RawSrcAddr)
}

// SetDstAddr sets the destination address and updates the DstAddrLen/Type fields accordingly.
// SetDstAddr takes ownership of dst and callers should not write to it after calling SetDstAddr.
// Changes to dst might leave the layer in an inconsistent state.
func (s *SCION) SetDstAddr(dst net.Addr) error {
	var err error
	s.DstAddrLen, s.DstAddrType, s.RawDstAddr, err = packAddr(dst)
	return err
}

// SetSrcAddr sets the source address and updates the DstAddrLen/Type fields accordingly.
// SetSrcAddr takes ownership of src and callers should not write to it after calling SetSrcAddr.
// Changes to src might leave the layer in an inconsistent state.
func (s *SCION) SetSrcAddr(src net.Addr) error {
	var err error
	s.SrcAddrLen, s.SrcAddrType, s.RawSrcAddr, err = packAddr(src)
	return err
}

func parseAddr(addrType AddrType, addrLen AddrLen, raw []byte) (net.Addr, error) {
	switch addrLen {
	case AddrLen4:
		switch addrType {
		case T4Ip:
			return &net.IPAddr{IP: net.IP(raw)}, nil
		case T4Svc:
			return addr.HostSVC(binary.BigEndian.Uint16(raw[:addr.HostLenSVC])), nil
		}
	case AddrLen16:
		switch addrType {
		case T16Ip:
			return &net.IPAddr{IP: net.IP(raw)}, nil
		}
	}
	return nil, serrors.New("unsupported address type/length combination",
		"type", addrType, "len", addrLen)
}

func packAddr(hostAddr net.Addr) (AddrLen, AddrType, []byte, error) {
	switch a := hostAddr.(type) {
	case *net.IPAddr:
		if ip := a.IP.To4(); ip != nil {
			return AddrLen4, T4Ip, ip, nil
		}
		return AddrLen16, T16Ip, a.IP, nil
	case addr.HostSVC:
		return AddrLen4, T4Svc, a.PackWithPad(2), nil
	}
	return 0, 0, nil, serrors.New("unsupported address", "addr", hostAddr)
}

// AddrHdrLen returns the length of the address header (destination and source ISD-AS-Host triples)
// in bytes.
func (s *SCION) AddrHdrLen() int {
	return 2*addr.IABytes + addrBytes(s.DstAddrLen) + addrBytes(s.SrcAddrLen)
}

// SerializeAddrHdr serializes destination and source ISD-AS-Host address triples into the provided
// buffer. The caller must ensure that the correct address types and lengths are set in the SCION
// layer, otherwise the results of this method are undefined.
func (s *SCION) SerializeAddrHdr(buf []byte) error {
	if len(buf) < s.AddrHdrLen() {
		return serrors.New("provided buffer is too small", "expected", s.AddrHdrLen(),
			"actual", len(buf))
	}
	dstAddrBytes := addrBytes(s.DstAddrLen)
	srcAddrBytes := addrBytes(s.SrcAddrLen)
	offset := 0
	s.DstIA.Write(buf[offset:])
	offset += addr.IABytes
	s.SrcIA.Write(buf[offset:])
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
	s.DstIA = addr.IAFromRaw(data[offset:])
	offset += addr.IABytes
	s.SrcIA = addr.IAFromRaw(data[offset:])
	offset += addr.IABytes
	dstAddrBytes := addrBytes(s.DstAddrLen)
	srcAddrBytes := addrBytes(s.SrcAddrLen)
	s.RawDstAddr = data[offset : offset+dstAddrBytes]
	offset += dstAddrBytes
	s.RawSrcAddr = data[offset : offset+srcAddrBytes]

	return nil
}

func addrBytes(addrLen AddrLen) int {
	return (int(addrLen) + 1) * LineLen
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
	s.SrcIA.Write(srcIA[:])
	s.DstIA.Write(dstIA[:])
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
