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
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

var _ LayerBuilder = (*SCMP)(nil)
var _ LayerMatcher = (*SCMP)(nil)

// This type alias is to avoid name clash with Payload field in layers.BaseLayer
type scmpPld = scmp.Payload

type SCMP struct {
	layers.BaseLayer
	scmp.Hdr
	*scmpPld
	scn    *ScionLayer
	layers []LayerBuilder
	info   scmp.Info
	l4Type common.L4ProtocolType
}

var LayerTypeSCMP = gopacket.RegisterLayerType(
	newScnLayerID(),
	gopacket.LayerTypeMetadata{
		Name:    "SCMP",
		Decoder: gopacket.DecodeFunc(decodeSCMP),
	},
)

// NewSCMP creates a new SCMP builder and matcher.
// We need the scion layer to be able to calculate the checksum when serializing and we need
// the pktQuotes to also precaculate the checksum and total length when matching the packet.
func NewSCMP(c scmp.Class, t scmp.Type, ts time.Time, scn *ScionLayer, pktQuotes []LayerBuilder,
	info scmp.Info, l4Type common.L4ProtocolType) *SCMP {

	s := &SCMP{}
	s.Class = c
	s.Type = t
	s.Checksum = common.RawBytes{0, 0}
	if !ts.IsZero() {
		s.SetTime(ts)
	}
	s.scn = scn
	s.layers = pktQuotes
	s.info = info
	s.l4Type = l4Type
	return s
}

func (l *SCMP) Build() ([]gopacket.SerializableLayer, error) {
	return []gopacket.SerializableLayer{l}, nil
}

func (s *SCMP) LayerType() gopacket.LayerType {
	return LayerTypeSCMP
}

func (s *SCMP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	if err := s.generatePayload(); err != nil {
		return err
	}
	if opts.FixLengths {
		s.TotalLen = uint16(scmp.HdrLen + s.scmpPld.Len())
	}
	buf, err := b.PrependBytes(int(s.TotalLen))
	if err != nil {
		return err
	}
	if _, err := s.WritePld(buf[scmp.HdrLen:]); err != nil {
		return err
	}
	rawAddrHdr := make(common.RawBytes, s.scn.AddrHdr.Len())
	s.scn.AddrHdr.Write(rawAddrHdr)
	s.Checksum, err = l4.CalcCSum(&s.Hdr, rawAddrHdr, buf[scmp.HdrLen:])
	if err != nil {
		return err
	}
	if err := s.Hdr.Write(buf); err != nil {
		return err
	}
	return nil
}

func (s *SCMP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < scmp.HdrLen {
		df.SetTruncated()
		return fmt.Errorf("Invalid SCMP header. Length %d less than %d",
			len(data), scmp.HdrLen)
	}
	h, err := scmp.HdrFromRaw(data)
	if err != nil {
		return err
	}
	if int(h.TotalLen) > len(data) {
		df.SetTruncated()
		h.TotalLen = uint16(len(data))
	}
	s.Hdr = *h
	p, err := scmp.PldFromRaw(data[scmp.HdrLen:], scmp.ClassType{Class: s.Class, Type: s.Type})
	if err != nil {
		return err
	}
	s.scmpPld = p
	s.Contents = data[:s.TotalLen]
	return nil
}

func (s *SCMP) String() string {
	var str []string
	str = append(str, fmt.Sprintf("%s", &s.Hdr))
	if s.Meta != nil {
		str = append(str, fmt.Sprintf("Meta={ %s }", s.Meta))
	}
	if s.Info != nil {
		str = append(str, fmt.Sprintf("Info={ %s }", s.Info))
	}
	var cmn *spkt.CmnHdr
	if len(s.CmnHdr) > 0 {
		var err error
		if cmn, err = spkt.CmnHdrFromRaw(s.CmnHdr); err != nil {
			str = append(str, fmt.Sprintf("CmnHdr=%s", s.CmnHdr))
		} else {
			str = append(str, fmt.Sprintf("CmnHdr={ %s }", cmn))
		}
	}
	if len(s.AddrHdr) > 0 && cmn != nil {
		if addr, err := ParseRawAddrHdr(s.AddrHdr, cmn.SrcType, cmn.DstType); err != nil {
			str = append(str, fmt.Sprintf("AddrHdr=%s", s.AddrHdr))
		} else {
			str = append(str, fmt.Sprintf("AddrHdr={ %s }", addr))
		}
	}
	if len(s.PathHdr) > 0 {
		path := &ScnPath{}
		if err := path.Parse(s.PathHdr); err != nil {
			str = append(str, fmt.Sprintf("PathHdr=%s", s.PathHdr))
		} else {
			str = append(str, fmt.Sprintf("PathHdr={ %s }", path))
		}
	}
	if len(s.ExtHdrs) > 0 {
		str = append(str, fmt.Sprintf("ExtHdrs=%s", s.ExtHdrs))
	}
	if len(s.L4Hdr) > 0 {
		switch s.Meta.L4Proto {
		case common.L4UDP:
			if udp, err := l4.UDPFromRaw(s.L4Hdr); err != nil {
				str = append(str, fmt.Sprintf("L4Hdr=%s", s.L4Hdr))
			} else {
				str = append(str, fmt.Sprintf("L4Hdr={ %s }", udp))
			}
		case common.L4SCMP:
			if hdr, err := scmp.HdrFromRaw(s.L4Hdr); err != nil {
				str = append(str, fmt.Sprintf("L4Hdr=%s", s.L4Hdr))
			} else {
				str = append(str, fmt.Sprintf("L4Hdr={ %s }", hdr))
			}
		default:
			str = append(str, fmt.Sprintf("L4Hdr=%s", s.L4Hdr))
		}
	}
	return strings.Join(str, " ")
}

func (s *SCMP) Match(pktLayers []gopacket.Layer, lc *LayerCache) ([]gopacket.Layer, error) {
	pktScmp, ok := pktLayers[0].(*SCMP)
	if !ok {
		return nil, fmt.Errorf("Wrong layer\nExpected %v\nActual   %v",
			LayerTypeSCMP, pktLayers[0].LayerType())
	}
	if err := s.generatePayload(); err != nil {
		return nil, err
	}
	s.TotalLen = uint16(scmp.HdrLen + s.scmpPld.Len())
	// Generate expected checksum with the received packet SCION/SCMP header, and the expected
	// Payload as input
	rawPld := make(common.RawBytes, s.scmpPld.Len())
	if _, err := s.WritePld(rawPld); err != nil {
		return nil, err
	}
	csum := util.Checksum(lc.scion.RawAddrHdr(), []uint8{0, uint8(common.L4SCMP)}, pktScmp.Contents)
	if csum != 0 {
		return nil, fmt.Errorf("SCMP checksum failure\nExpected %x\nActual   %s",
			csum, pktScmp.Checksum)
	}
	s.Checksum = pktScmp.Checksum
	if err := s.compareHdr(pktScmp, lc); err != nil {
		return nil, err
	}
	if err := s.comparePld(pktScmp, lc); err != nil {
		return nil, err
	}
	return pktLayers[1:], nil
}

func (s *SCMP) compareHdr(o *SCMP, lc *LayerCache) error {
	timeFormat := "2006-01-02 15:04:05"
	actTS := o.Time()
	if s.Timestamp == 0 {
		// The timestamp of the expected packet was not specified, likely because it is not know
		// at the time of the test definition, ie. the BR generates this packet.
		now := time.Now()
		// XXX allow up to 2 seconds time difference
		min := now.Add(-2 * time.Second)
		if actTS.After(now) || actTS.Before(min) {
			return fmt.Errorf("SCMP timestamp check failed\nExpected between (%s, %s)\nActual   %s",
				min.Format(timeFormat), now.Format(timeFormat), actTS.Format(timeFormat))
		}
	} else if s.Timestamp != o.Timestamp {
		return fmt.Errorf("SCMP timestamp check failed\nExpected %s\nActual   %s",
			s.Time().Format(timeFormat), actTS.Format(timeFormat))
	}
	if s.Class != o.Class || s.Type != o.Type || s.TotalLen != o.TotalLen {
		return fmt.Errorf("SCMP header mismatch\nExpected %s\nActual   %s",
			&s.Hdr, &o.Hdr)
	}
	return nil
}

func (s *SCMP) comparePld(o *SCMP, lc *LayerCache) error {
	if *s.Meta != *o.Meta {
		return fmt.Errorf("SCMP Meta mismatch\nExpected %s\nActual   %s", s.Meta, o.Meta)
	}
	start := scmp.HdrLen + scmp.MetaLen
	end := start + int(s.Meta.InfoLen)*common.LineLen
	infoRaw := make(common.RawBytes, s.scmpPld.Info.Len())
	s.scmpPld.Info.Write(infoRaw)
	if !bytes.Equal(infoRaw, o.Contents[start:end]) {
		return fmt.Errorf("SCMP Info mismatch\nExpected %s\nActual   %s", s.Info, o.Info)
	}
	if !bytes.Equal(s.scmpPld.CmnHdr, o.scmpPld.CmnHdr) {
		return fmt.Errorf("SCMP CmnHdr quote mismatch\nExpected %s\nActual   %s",
			s.scmpPld.CmnHdr, o.scmpPld.CmnHdr)
	}
	if !bytes.Equal(s.scmpPld.AddrHdr, o.scmpPld.AddrHdr) {
		return fmt.Errorf("SCMP AddrHdr quote mismatch\nExpected %s\nActual   %s",
			s.scmpPld.AddrHdr, o.scmpPld.AddrHdr)
	}
	if !bytes.Equal(s.scmpPld.PathHdr, o.scmpPld.PathHdr) {
		return fmt.Errorf("SCMP PathHdr quote mismatch\nExpected %s\nActual   %s",
			s.scmpPld.PathHdr, o.scmpPld.PathHdr)
	}
	if !bytes.Equal(s.scmpPld.ExtHdrs, o.scmpPld.ExtHdrs) {
		return fmt.Errorf("SCMP ExtHdrs quote mismatch\nExpected %s\nActual   %s",
			s.scmpPld.ExtHdrs, o.scmpPld.ExtHdrs)
	}
	if !bytes.Equal(s.scmpPld.L4Hdr, o.scmpPld.L4Hdr) {
		return fmt.Errorf("SCMP L4Hdr quote mismatch\nExpected %s\nActual   %s",
			s.scmpPld.L4Hdr, o.scmpPld.L4Hdr)
	}
	return nil
}

func (s *SCMP) generatePayload() error {
	if s.scmpPld != nil {
		return nil
	}
	raw, err := serializeLayers(s.layers)
	if err != nil {
		return err
	}
	// Build and parse the packet sent, which will be used to generate the expected quotes
	pkt := gopacket.NewPacket(raw, LayerTypeScion, gopacket.NoCopy)
	scn := pkt.Layer(LayerTypeScion).(*ScionLayer)
	if scn == nil {
		return fmt.Errorf("Failed to generate expected SCMP quotes (SCION layer parsing)")
	}
	qr := &quoteRaw{scion: scn}
	switch s.l4Type {
	case common.L4SCMP:
		qr.l4 = pkt.Layer(LayerTypeSCMP).(*SCMP)
	default:
		qr.l4 = pkt.TransportLayer()
		if qr.l4 == nil {
			// Failed to decode supported transport layer, so retrieve payload
			qr.l4 = pkt.ApplicationLayer()
		}
	}
	// Convert from test relative offset to index offsets
	// Cannot do it on the constructor because we need the segments for the conversion
	pathOff := spkt.CmnHdrLen + scn.AddrHdr.Len()
	switch ipo := s.info.(type) {
	case *scmp.InfoPathOffsets:
		ipo.InfoF, ipo.HopF = convertOffsets(ipo.InfoF, ipo.HopF, pathOff, scn.Path.Segs)
	case *scmp.InfoRevocation:
		ipo.InfoF, ipo.HopF = convertOffsets(ipo.InfoF, ipo.HopF, pathOff, scn.Path.Segs)
	}
	ct := scmp.ClassType{Class: s.Class, Type: s.Type}
	pld := scmp.PldFromQuotes(ct, s.info, s.l4Type, qr.getRaw)
	s.scmpPld = pld
	return nil
}

func convertOffsets(infoF, hopF uint8, pathOff int, segs Segments) (uint8, uint8) {
	infOff, hopOff := indexToOffsets(infoF, hopF, segs)
	return uint8((pathOff + infOff) / common.LineLen), uint8((pathOff + hopOff) / common.LineLen)
}

func decodeSCMP(data []byte, p gopacket.PacketBuilder) error {
	s := &SCMP{}
	err := s.DecodeFromBytes(data, p)
	p.AddLayer(s)
	if err != nil {
		return err
	}
	return nil
}

type quoteRaw struct {
	scion *ScionLayer
	l4    gopacket.Layer
}

// getRaw returns slices of the underlying buffer corresponding to part of the
// packet identified by the blk argument. This is used, for example, by SCMP to
// quote parts of the packet in an error response.
func (qr *quoteRaw) getRaw(blk scmp.RawBlock) common.RawBytes {
	scnRaw := qr.scion.Contents
	addrLen := qr.scion.AddrHdr.Len()
	scnPld := qr.scion.Payload
	extLen := len(scnPld) - len(qr.l4.LayerContents()) - len(qr.l4.LayerPayload())
	switch blk {
	case scmp.RawCmnHdr:
		return scnRaw[:spkt.CmnHdrLen]
	case scmp.RawAddrHdr:
		return scnRaw[spkt.CmnHdrLen : spkt.CmnHdrLen+addrLen]
	case scmp.RawPathHdr:
		return scnRaw[spkt.CmnHdrLen+addrLen:]
	case scmp.RawExtHdrs:
		return scnPld[:extLen]
	case scmp.RawL4Hdr:
		if s, ok := qr.l4.(*SCMP); ok {
			return qr.l4.LayerContents()[:scmp.HdrLen+s.Meta.InfoLen*common.LineLen]
		}
		return qr.l4.LayerContents()
	}
	return nil
}

func NewRevocation(infoF, hopF uint8, ifid common.IFIDType, ingress bool,
	sRevInfo *path_mgmt.SignedRevInfo) *scmp.InfoRevocation {

	var rawSRev common.RawBytes
	if sRevInfo != nil {
		var err error
		rawSRev, err = proto.PackRoot(sRevInfo)
		if err != nil {
			panic(err)
		}
	}
	infoPathOffsets := &scmp.InfoPathOffsets{InfoF: infoF, HopF: hopF, IfID: ifid, Ingress: ingress}
	return &scmp.InfoRevocation{InfoPathOffsets: infoPathOffsets, RawSRev: rawSRev}
}
