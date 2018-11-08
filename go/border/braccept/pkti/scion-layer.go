package pkti

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spkt"
)

// ScionLayer is a basic (no extensions support) gopacket SCION layer implementation.
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
	if _, err := l.Path.WriteRaw(); err != nil {
		return err
	}
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
