package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spkt"
)

//
// SCION gopacket layer
//
type ScionLayer struct {
	layers.BaseLayer
	nextHdr common.L4ProtocolType
	CmnHdr  spkt.CmnHdr
	AddrHdr AddrHdr
	Path    ScnPath
}

var LayerTypeScion = gopacket.RegisterLayerType(
	1337,
	gopacket.LayerTypeMetadata{
		"ScionLayerType",
		gopacket.DecodeFunc(decodeScionLayer),
	},
)

func (l *ScionLayer) LayerType() gopacket.LayerType {
	return LayerTypeScion
}

func (l *ScionLayer) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	scnLen := spkt.CmnHdrLen + l.AddrHdr.Len() + l.Path.Segs.Len()
	buf, err := b.PrependBytes(scnLen)
	if err != nil {
		return err
	}
	l.CmnHdr.Write(buf)
	addrLen := l.AddrHdr.Write(buf[spkt.CmnHdrLen:])
	l.Path.Raw = buf[spkt.CmnHdrLen+addrLen:]
	writeScnPath(l.Path.Segs, l.Path.Raw)
	return nil
}

func (l *ScionLayer) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if err := l.CmnHdr.Parse(data); err != nil {
		return err
	}
	offset := spkt.CmnHdrLen
	addrLen, err := l.AddrHdr.Parse(data[offset:], l.CmnHdr.SrcType, l.CmnHdr.DstType)
	if err != nil {
		return err
	}
	offset += addrLen
	hdrLen := l.CmnHdr.HdrLenBytes()
	l.Path.InfOff = int(l.CmnHdr.CurrInfoF) - (offset / common.LineLen)
	l.Path.HopOff = int(l.CmnHdr.CurrHopF) - (offset / common.LineLen)
	l.Path.Raw = data[offset:hdrLen]
	l.BaseLayer = layers.BaseLayer{data[:hdrLen], data[hdrLen:]}
	l.nextHdr = l.CmnHdr.NextHdr
	// TODO Extensions
	return nil
}

func decodeScionLayer(data []byte, p gopacket.PacketBuilder) error {
	scn := &ScionLayer{}
	err := scn.DecodeFromBytes(data, p)
	p.AddLayer(scn)
	if err != nil {
		return err
	}
	return p.NextDecoder(scionNextLayerType(scn.nextHdr))
}

func scionNextLayerType(t common.L4ProtocolType) gopacket.LayerType {
	switch t {
	case common.L4UDP:
		return layers.LayerTypeUDP
	}
	return gopacket.LayerTypePayload
}

func writeScnPath(segs []*SegDef, b []byte) int {
	offset := 0
	for i, _ := range segs {
		offset += writeScnPathSeg(segs[i], b[offset:])
	}
	return offset
}

func writeScnPathSeg(seg *SegDef, b []byte) int {
	// Write Info Field
	seg.inf.Write(b)
	// Write Hop Fields
	prevHop := []byte{}
	nHops := len(seg.hops)
	for j, _ := range seg.hops {
		hopIdx := j
		if !seg.inf.ConsDir {
			// For reverse ConsDir, start from last hop
			hopIdx = nHops - 1 - j
		}
		hop := seg.hops[hopIdx]
		if hop.Mac == nil {
			mac.Reset()
			hop.Mac, err = hop.CalcMac(mac, seg.inf.TsInt, prevHop)
			if err != nil {
				panic(err)
			}
		}
		curOff := spath.InfoFieldLength + hopIdx*spath.HopFieldLength
		hop.Write(b[curOff:])
		prevHop = b[curOff+1 : curOff+spath.HopFieldLength]
	}
	return spath.InfoFieldLength + nHops*spath.HopFieldLength
}
