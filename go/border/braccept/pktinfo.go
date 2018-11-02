package main

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/imdario/mergo"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/spkt"
)

type PktInfo struct {
	Dev     string
	Overlay OverlayLayers
	CmnHdr  *spkt.CmnHdr
	AddrHdr *AddrHdr
	Path    *ScnPath
	Exts    []common.Extension
	L4      l4.L4Header
	Pld     common.Payload
}

// Generate common header from packet info and replace the values provided by the user.
// Also use any section from the passed packet info if not set .
func (p *PktInfo) Merge(pi *PktInfo) {
	if pi != nil {
		// If not set, use headers from default packet, except the common header
		if p.Overlay == nil {
			p.Overlay = pi.Overlay
		}
		if p.AddrHdr == nil {
			p.AddrHdr = pi.AddrHdr
		}
		if p.Path == nil {
			p.Path = pi.Path
		}
		if p.Exts == nil {
			p.Exts = pi.Exts
		}
		if p.L4 == nil {
			p.L4 = pi.L4
		}
		if p.Pld == nil {
			p.Pld = pi.Pld
		}
	}
	p.mergeCmnHdr()
}

func (pi *PktInfo) mergeCmnHdr() {
	// Replace all unset values with the values from auto generated common header from packet info
	cmnHdr := pi.genCmnHdr()
	if pi.CmnHdr != nil {
		if err := mergo.Merge(pi.CmnHdr, cmnHdr); err != nil {
			panic(err)
		}
	} else {
		pi.CmnHdr = cmnHdr
	}
}

func (pi *PktInfo) genCmnHdr() *spkt.CmnHdr {
	// Generate Common Header
	addrHdrLen := pi.AddrHdr.Len()
	pathOff := spkt.CmnHdrLen + addrHdrLen
	hdrLen := spkt.CmnHdrLen + addrHdrLen + pi.Path.Segs.Len()
	totalLen := hdrLen + extnsLength(pi.Exts)
	if pi.L4 != nil {
		totalLen += pi.L4.L4Len()
	}
	if pi.Pld != nil {
		totalLen += pi.Pld.Len()
	}
	cmnHdr := &spkt.CmnHdr{
		Ver:       spkt.SCIONVersion,
		DstType:   pi.AddrHdr.DstHost.Type(),
		SrcType:   pi.AddrHdr.SrcHost.Type(),
		TotalLen:  uint16(totalLen),
		HdrLen:    uint8(hdrLen / common.LineLen),
		CurrInfoF: uint8((pathOff + pi.Path.InfOff) / common.LineLen),
		CurrHopF:  uint8((pathOff + pi.Path.HopOff) / common.LineLen),
	}
	if len(pi.Exts) > 0 {
		cmnHdr.NextHdr = pi.Exts[0].Class()
	} else if pi.L4 != nil {
		cmnHdr.NextHdr = pi.L4.L4Type()
	}
	return cmnHdr
}

func (pi *PktInfo) GetPktInfo() *PktInfo {
	return pi
}

func (pi *PktInfo) GetDev() string {
	return pi.Dev
}

func (pi *PktInfo) GetOverlay() (l []gopacket.SerializableLayer) {
	srcMac, _ := net.ParseMAC("00:00:de:ad:be:ef") // XXX Irrelevant
	var ethType layers.EthernetType
	switch pi.Overlay.(type) {
	case *OverlayIP4UDP:
		ethType = layers.EthernetTypeIPv4
	}
	eth := &layers.Ethernet{
		DstMAC:       devByName[pi.Dev].mac,
		SrcMAC:       srcMac,
		EthernetType: ethType,
	}
	l = append(l, eth)
	l = append(l, pi.Overlay.ToLayer()...)
	return
}

func (pi *PktInfo) Pack() common.RawBytes {
	pkt := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths: true,
	}
	var pLayers []gopacket.SerializableLayer
	if pi.CmnHdr != nil || pi.AddrHdr != nil || pi.Path != nil {
		scnLayer := &ScionLayer{CmnHdr: *pi.CmnHdr, AddrHdr: *pi.AddrHdr, Path: *pi.Path}
		pLayers = append(pLayers, scnLayer)
	}
	// TODO Extensions
	if pi.L4 != nil {
		pLayers = append(pLayers, l4ToLayer(pi.L4))
	}
	if pi.Pld != nil {
		pLayers = append(pLayers, pldToLayer(pi.Pld))
	}
	if err := gopacket.SerializeLayers(pkt, options, pLayers...); err != nil {
		panic(err)
	}
	overlayLayers := pi.GetOverlay()
	options.ComputeChecksums = true
	// XXX Cannot use SerializeLayers as it clears previously written bytes
	for i := len(overlayLayers) - 1; i >= 0; i-- {
		layer := overlayLayers[i]
		if err := layer.SerializeTo(pkt, options); err != nil {
			panic(err)
		}
	}
	return common.RawBytes(pkt.Bytes())
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

//
// OverlayLayers
//
type OverlayLayers interface {
	ToLayer() []gopacket.SerializableLayer
}

//
// OverlayIP4UDP
//
type OverlayIP4UDP struct {
	srcAddr string
	srcPort uint16
	dstAddr string
	dstPort uint16
}

func (o *OverlayIP4UDP) ToLayer() (l []gopacket.SerializableLayer) {
	srcIP := net.ParseIP(o.srcAddr)
	dstIP := net.ParseIP(o.dstAddr)
	var nl gopacket.NetworkLayer
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	nl = ip
	l = append(l, ip)
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(o.srcPort),
		DstPort: layers.UDPPort(o.dstPort),
	}
	l = append(l, udp)
	udp.SetNetworkLayerForChecksum(nl)
	return l
}
