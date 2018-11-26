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
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/scmp"
	//"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/lib/util"
)

var _ LayerMatcher = (*SCMP)(nil)

type SCMP struct {
	layers.BaseLayer
	scmp.Hdr
	scmp.Payload
	lbs    []LayerBuilder
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

func NewSCMP(c scmp.Class, t scmp.Type, lbs []LayerBuilder, info scmp.Info,
	l4Type common.L4ProtocolType) *SCMP {

	s := &SCMP{}
	s.Class = c
	s.Type = t
	s.lbs = lbs
	s.info = info
	s.l4Type = l4Type
	return s
}

func (l *SCMP) LayerType() gopacket.LayerType {
	return LayerTypeSCMP
}

func (l *SCMP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	if opts.FixLengths {
		l.TotalLen = uint16(l.Hdr.L4Len() + scmp.MetaLen + l.Payload.Len())
	}
	buf, err := b.PrependBytes(int(l.TotalLen))
	if err != nil {
		return err
	}
	if err := l.Hdr.Write(buf); err != nil {
		return err
	}
	if _, err := l.Payload.WritePld(buf[scmp.HdrLen:]); err != nil {
		return err
	}
	return nil
}

func (l *SCMP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
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
	l.Hdr = *h
	p, err := scmp.PldFromRaw(data[scmp.HdrLen:], scmp.ClassType{Class: l.Class, Type: l.Type})
	if err != nil {
		return err
	}
	l.Payload = *p
	l.Contents = data[:l.TotalLen]
	return nil
}

func (l *SCMP) String() string {
	var str []string
	str = append(str, fmt.Sprintf("%s", &l.Hdr))
	if l.Meta != nil {
		str = append(str, fmt.Sprintf("Meta={ %s }", l.Meta))
	}
	if l.Info != nil {
		str = append(str, fmt.Sprintf("Info={ %s }", l.Info))
	}
	var cmn *spkt.CmnHdr
	if len(l.CmnHdr) > 0 {
		var err error
		if cmn, err = spkt.CmnHdrFromRaw(l.CmnHdr); err != nil {
			str = append(str, fmt.Sprintf("CmnHdr=%s", l.CmnHdr))
		} else {
			str = append(str, fmt.Sprintf("CmnHdr={ %s }", cmn))
		}
	}
	if len(l.AddrHdr) > 0 && cmn != nil {
		if addr, err := ParseRawAddrHdr(l.AddrHdr, cmn.SrcType, cmn.DstType); err != nil {
			str = append(str, fmt.Sprintf("AddrHdr=%s", l.AddrHdr))
		} else {
			str = append(str, fmt.Sprintf("AddrHdr={ %s }", addr))
		}
	}
	if len(l.PathHdr) > 0 {
		path := &ScnPath{}
		if err := path.Parse(l.PathHdr); err != nil {
			str = append(str, fmt.Sprintf("PathHdr=%s", l.PathHdr))
		} else {
			str = append(str, fmt.Sprintf("PathHdr={ %s }", path))
		}
	}
	if len(l.ExtHdrs) > 0 {
		str = append(str, fmt.Sprintf("ExtHdrs=%s", l.ExtHdrs))
	}
	if len(l.L4Hdr) > 0 {
		switch l.Meta.L4Proto {
		case common.L4UDP:
			if udp, err := l4.UDPFromRaw(l.L4Hdr); err != nil {
				str = append(str, fmt.Sprintf("L4Hdr=%s", l.L4Hdr))
			} else {
				str = append(str, fmt.Sprintf("L4Hdr={ %s }", udp))
			}
		case common.L4SCMP:
			if hdr, err := scmp.HdrFromRaw(l.L4Hdr); err != nil {
				str = append(str, fmt.Sprintf("L4Hdr=%s", l.L4Hdr))
			} else {
				str = append(str, fmt.Sprintf("L4Hdr={ %s }", hdr))
			}
		default:
			str = append(str, fmt.Sprintf("L4Hdr=%s", l.L4Hdr))
		}
	}
	return strings.Join(str, " ")
}

func (l *SCMP) Match(pktLayers []gopacket.Layer, lc *LayerCache) ([]gopacket.Layer, error) {
	s, ok := pktLayers[0].(*SCMP)
	if !ok {
		return nil, fmt.Errorf("Wrong layer\nExpected %v\nActual   %v",
			LayerTypeSCMP, pktLayers[0].LayerType())
	}
	if err := l.generatePayload(); err != nil {
		return nil, err
	}
	l.TotalLen = uint16(scmp.HdrLen + l.Payload.Len())
	// Generate expected checksum with the received packet SCION/SCMP header, and the expected
	// Payload as input
	csum := util.Checksum(lc.scion.RawAddrHdr(), []uint8{0, uint8(common.L4SCMP)}, s.Contents)
	if csum != 0 {
		return nil, fmt.Errorf("SCMP checksum failure\nExpected %x\nActual   %s", csum, s.Checksum)
	}
	l.Checksum = s.Checksum
	if err := l.compareHdr(s, lc); err != nil {
		return nil, err
	}
	if err := l.comparePld(s, lc); err != nil {
		return nil, err
	}
	return pktLayers[1:], nil
}

func (l *SCMP) compareHdr(s *SCMP, lc *LayerCache) error {
	ts := s.Time()
	now := time.Now()
	if ts.After(now) || ts.Before(now.Add(-1*time.Second)) {
		return fmt.Errorf("SCMP timestamp check failed\nExpected (now -1, now)\nActual   %s", ts)
	}
	// If the received packet SCMP timestamp is within acceptable limits, we set the expected
	// timestamp to the value of the received packet to do quick struct comparison
	l.Timestamp = s.Timestamp
	if l.Class != s.Class || l.Type != s.Type || l.TotalLen != s.TotalLen {
		return fmt.Errorf("SCMP header mismatch\nExpected %s\nActual   %s",
			&l.Hdr, &s.Hdr)
	}
	return nil
}

func (l *SCMP) comparePld(s *SCMP, lc *LayerCache) error {
	if *l.Meta != *s.Meta {
		return fmt.Errorf("SCMP Meta mismatch\nExpected %s\nActual   %s", l.Meta, s.Meta)
	}
	start := scmp.HdrLen + scmp.MetaLen
	end := start + int(l.Meta.InfoLen)*common.LineLen
	infoRaw := make(common.RawBytes, l.Payload.Info.Len())
	l.Payload.Info.Write(infoRaw)
	//if !bytes.Equal(l.Contents[start:end], s.Contents[start:end]) {
	if !bytes.Equal(infoRaw, s.Contents[start:end]) {
		return fmt.Errorf("SCMP Info mismatch\nExpected %s\nActual   %s", l.Info, s.Info)
	}
	if !bytes.Equal(l.Payload.CmnHdr, s.Payload.CmnHdr) {
		return fmt.Errorf("SCMP CmnHdr quote mismatch\nExpected %s\nActual   %s",
			l.Payload.CmnHdr, s.Payload.CmnHdr)
	}
	if !bytes.Equal(l.Payload.AddrHdr, s.Payload.AddrHdr) {
		return fmt.Errorf("SCMP AddrHdr quote mismatch\nExpected %s\nActual   %s",
			l.Payload.AddrHdr, s.Payload.AddrHdr)
	}
	if !bytes.Equal(l.Payload.PathHdr, s.Payload.PathHdr) {
		return fmt.Errorf("SCMP PathHdr quote mismatch\nExpected %s\nActual   %s",
			l.Payload.PathHdr, s.Payload.PathHdr)
	}
	if !bytes.Equal(l.Payload.ExtHdrs, s.Payload.ExtHdrs) {
		return fmt.Errorf("SCMP ExtHdrs quote mismatch\nExpected %s\nActual   %s",
			l.Payload.ExtHdrs, s.Payload.ExtHdrs)
	}
	if !bytes.Equal(l.Payload.L4Hdr, s.Payload.L4Hdr) {
		return fmt.Errorf("SCMP L4Hdr quote mismatch\nExpected %s\nActual   %s",
			l.Payload.L4Hdr, s.Payload.L4Hdr)
	}
	return nil
}

func (l *SCMP) generatePayload() error {
	// It cannot fail, given that is the the packet that was previously sent without error
	raw, _ := serializeLayers(l.lbs)
	// Build and parse the packet sent, which will be used to generate the expected quotes
	pkt := gopacket.NewPacket(raw, LayerTypeScion, gopacket.NoCopy)
	scn := pkt.Layer(LayerTypeScion).(*ScionLayer)
	if scn == nil {
		return fmt.Errorf("Failed to generate expected SCMP quotes (SCION layer parsing)")
	}
	qr := &quoteRaw{scion: scn}
	switch l.l4Type {
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
	if ipo, ok := l.info.(*scmp.InfoPathOffsets); ok {
		infOff, hopOff := indexToOffsets(ipo.InfoF, ipo.HopF, scn.Path.Segs)
		base := spkt.CmnHdrLen + scn.AddrHdr.Len()
		ipo.InfoF = uint8((base + infOff) / common.LineLen)
		ipo.HopF = uint8((base + hopOff) / common.LineLen)
	}
	ct := scmp.ClassType{Class: l.Class, Type: l.Type}
	pld := scmp.PldFromQuotes(ct, l.info, l.l4Type, qr.getRaw)
	l.Payload = *pld
	return nil
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

func NewInfoPathOffsets(infoF, hopF uint8, ifid common.IFIDType, in bool) *scmp.InfoPathOffsets {
	return &scmp.InfoPathOffsets{InfoF: infoF, HopF: hopF, IfID: ifid, Ingress: in}
}
