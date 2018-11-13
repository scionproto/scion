package tpkt

import (
	"bytes"
	"fmt"
	"hash"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/imdario/mergo"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spkt"
)

// Pkt is a base structure used to specify packets.
// It is not meant to be used stand-alone, but as the base for other types implementing
// the required interfaces for a test.
type Pkt struct {
	Dev     string
	Overlay OverlayLayers
	CmnHdr  *spkt.CmnHdr
	AddrHdr *AddrHdr
	Path    *ScnPath
	Exts    []common.Extension
	L4      l4.L4Header
	Pld     common.Payload
}

func (p *Pkt) String() string {
	var str []string
	if a := p.AddrHdr; a != nil {
		str = append(str, fmt.Sprintf("\t%s,[%s] -> %s,[%s]",
			a.SrcIA, a.SrcHost, a.DstIA, a.DstHost))
	}
	if p.Path != nil {
		str = append(str, PrintSegments(p.Path.Segs, "\t", "\n"))
	}
	return strings.Join(str, "\n")
}

func (p *Pkt) GetDev() string {
	return p.Dev
}

// mergeCmnHdr uses mego package to merge structures.
func (p *Pkt) mergeCmnHdr() error {
	// Replace all unset values with the values from auto generated common header from packet info
	cmnHdr := p.genCmnHdr()
	if p.CmnHdr != nil {
		return mergo.Merge(p.CmnHdr, cmnHdr)
	}
	p.CmnHdr = cmnHdr
	return nil
}

// genCmnHdr generates a full common header section from the other fields.
// It is mostly used as default values for fields not set in the packet info test description.
func (p *Pkt) genCmnHdr() *spkt.CmnHdr {
	// Generate Common Header
	addrHdrLen := p.AddrHdr.Len()
	pathOff := spkt.CmnHdrLen + addrHdrLen
	hdrLen := spkt.CmnHdrLen + addrHdrLen + p.Path.Segs.Len()
	totalLen := hdrLen + extnsLength(p.Exts)
	if p.L4 != nil {
		totalLen += p.L4.L4Len()
	}
	if p.Pld != nil {
		totalLen += p.Pld.Len()
	}
	cmnHdr := &spkt.CmnHdr{
		Ver:       spkt.SCIONVersion,
		DstType:   p.AddrHdr.DstHost.Type(),
		SrcType:   p.AddrHdr.SrcHost.Type(),
		TotalLen:  uint16(totalLen),
		HdrLen:    uint8(hdrLen / common.LineLen),
		CurrInfoF: uint8((pathOff + p.Path.InfOff) / common.LineLen),
		CurrHopF:  uint8((pathOff + p.Path.HopOff) / common.LineLen),
	}
	if len(p.Exts) > 0 {
		cmnHdr.NextHdr = p.Exts[0].Class()
	} else if p.L4 != nil {
		cmnHdr.NextHdr = p.L4.L4Type()
	}
	return cmnHdr
}

func (p *Pkt) GetOverlay(dstMac net.HardwareAddr) ([]gopacket.SerializableLayer, error) {
	var ethType layers.EthernetType
	switch p.Overlay.(type) {
	case *OverlayIP4UDP:
		ethType = layers.EthernetTypeIPv4
	}
	// The src MAC does not need to be valid
	srcMac, _ := net.ParseMAC("00:00:de:ad:be:ef")
	eth := &layers.Ethernet{
		DstMAC:       dstMac,
		SrcMAC:       srcMac,
		EthernetType: ethType,
	}
	var l []gopacket.SerializableLayer
	l = append(l, eth)
	l = append(l, p.Overlay.ToLayers()...)
	return l, nil
}

func (p *Pkt) Pack(dstMac net.HardwareAddr, mac hash.Hash) (common.RawBytes, error) {
	pkt := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths: true,
	}
	var pLayers []gopacket.SerializableLayer
	if p.CmnHdr != nil || p.AddrHdr != nil || p.Path != nil {
		scnLayer := &ScionLayer{CmnHdr: *p.CmnHdr, AddrHdr: *p.AddrHdr, Path: *p.Path}
		if p.Path != nil {
			scnLayer.Path.Mac = mac
		}
		pLayers = append(pLayers, scnLayer)
	}
	// TODO Extensions
	if p.L4 != nil {
		pLayers = append(pLayers, l4ToLayer(p.L4))
	}
	if p.Pld != nil {
		pLayers = append(pLayers, pldToLayer(p.Pld))
	}
	if err := gopacket.SerializeLayers(pkt, options, pLayers...); err != nil {
		return nil, err
	}
	overlayLayers, err := p.GetOverlay(dstMac)
	if err != nil {
		return nil, err
	}
	options.ComputeChecksums = true
	// XXX Cannot use SerializeLayers as it clears previously written bytes
	for i := len(overlayLayers) - 1; i >= 0; i-- {
		layer := overlayLayers[i]
		if err := layer.SerializeTo(pkt, options); err != nil {
			return nil, err
		}
	}
	return common.RawBytes(pkt.Bytes()), nil
}

func (p *Pkt) checkScnHdr(b common.RawBytes) (common.RawBytes, error) {
	scnPkt := gopacket.NewPacket(b, LayerTypeScion, gopacket.NoCopy)
	scn := scnPkt.Layer(LayerTypeScion).(*ScionLayer)
	if scn == nil {
		return nil, fmt.Errorf("Could not parse SCION headers")
	}
	if scn.CmnHdr != *p.CmnHdr {
		return nil, fmt.Errorf("Common header mismatch\nExpected %v\nActual   %v",
			p.CmnHdr, &scn.CmnHdr)
	}
	if !p.AddrHdr.Eq(&scn.AddrHdr) {
		return nil, fmt.Errorf("Address header mismatch\nExpected %v\nActual   %v",
			p.AddrHdr, &scn.AddrHdr)
	}
	if err := p.Path.Check(&scn.Path); err != nil {
		return nil, err
	}
	// As we already checked that we have a valid common header, we can use the HdrLen safely
	return b[scn.CmnHdr.HdrLenBytes():], nil
}

func (p *Pkt) checkL4(b common.RawBytes) (common.RawBytes, error) {
	if p.L4 == nil {
		return b, nil
	}
	pldLen := 0
	if p.Pld != nil {
		pldLen = p.Pld.Len()
	}
	switch p.L4.L4Type() {
	case common.L4None:
	case common.L4SCMP:
		pktL4, _ := scmp.HdrFromRaw(b)
		scmp := p.L4.(*scmp.Hdr)
		if scmp.TotalLen == 0 {
			scmp.SetPldLen(pldLen)
		}
		if !scmpEqual(scmp, pktL4) {
			return nil, fmt.Errorf("L4 SCMP header does not match\n Expected: %s\n Actual: %s",
				scmp, pktL4)
		}
		// TODO compare specific SCMP data and payload
	case common.L4UDP:
		pktL4, _ := l4.UDPFromRaw(b)
		udp := p.L4.(*l4.UDP)
		if udp.TotalLen == 0 {
			udp.SetPldLen(pldLen)
		}
		if !udpEqual(udp, pktL4) {
			return nil, fmt.Errorf("L4 UDP header does not match\n Expected: %s\n Actual: %s",
				udp, pktL4)
		}
	}
	return b[p.L4.L4Len():], nil
}

func (p *Pkt) checkPld(b common.RawBytes) (common.RawBytes, error) {
	if p.Pld == nil {
		return b, nil
	}
	expPld := make(common.RawBytes, p.Pld.Len())
	p.Pld.WritePld(expPld)
	if !bytes.Equal(b, expPld) {
		return nil, fmt.Errorf("Payload does not match")
	}
	return b[p.Pld.Len():], nil
}

func l4ToLayer(l l4.L4Header) gopacket.SerializableLayer {
	switch l.L4Type() {
	case common.L4UDP:
		udp, _ := l.(*l4.UDP)
		return &layers.UDP{
			SrcPort: layers.UDPPort(udp.SrcPort),
			DstPort: layers.UDPPort(udp.DstPort),
		}
	}
	return nil
}

func pldToLayer(pld common.Payload) gopacket.SerializableLayer {
	b := make([]byte, pld.Len())
	pld.WritePld(b)
	return gopacket.Payload(b)
}

func extnsLength(extns []common.Extension) int {
	l := 0
	for _, e := range extns {
		l += int(e.Len())
	}
	return l
}

func scmpEqual(a, b *scmp.Hdr) bool {
	// Ignore Checksum and Timestamp
	// TODO Pld/quotes
	return a.Class == b.Class && a.Type == b.Type && a.TotalLen == b.TotalLen
}

func udpEqual(a, b *l4.UDP) bool {
	// Ignore Checksum
	return a.SrcPort == b.SrcPort && a.DstPort == b.DstPort && a.TotalLen == b.TotalLen
}
