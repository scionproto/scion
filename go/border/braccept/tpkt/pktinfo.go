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

func (pi *Pkt) String() string {
	var str []string
	if a := pi.AddrHdr; a != nil {
		str = append(str, fmt.Sprintf("\t%s,[%s] -> %s,[%s]",
			a.SrcIA, a.SrcHost, a.DstIA, a.DstHost))
	}
	if pi.Path != nil {
		str = append(str, PrintSegments(pi.Path.Segs, "\t", "\n"))
	}
	return strings.Join(str, "\n")
}

func (pi *Pkt) GetDev() string {
	return pi.Dev
}

// mergeCmnHdr uses mego package to merge structures.
func (pi *Pkt) mergeCmnHdr() error {
	// Replace all unset values with the values from auto generated common header from packet info
	cmnHdr := pi.genCmnHdr()
	if pi.CmnHdr != nil {
		return mergo.Merge(pi.CmnHdr, cmnHdr)
	}
	pi.CmnHdr = cmnHdr
	return nil
}

// genCmnHdr generates a full common header section from the other fields.
// It is mostly used as default values for fields not set in the packet info test description.
func (pi *Pkt) genCmnHdr() *spkt.CmnHdr {
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

func (pi *Pkt) GetOverlay(dstMac net.HardwareAddr) ([]gopacket.SerializableLayer, error) {
	var ethType layers.EthernetType
	switch pi.Overlay.(type) {
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
	l = append(l, pi.Overlay.ToLayers()...)
	return l, nil
}

func (pi *Pkt) Pack(dstMac net.HardwareAddr, mac hash.Hash) (common.RawBytes, error) {
	pkt := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths: true,
	}
	var pLayers []gopacket.SerializableLayer
	if pi.CmnHdr != nil || pi.AddrHdr != nil || pi.Path != nil {
		scnLayer := &ScionLayer{CmnHdr: *pi.CmnHdr, AddrHdr: *pi.AddrHdr, Path: *pi.Path}
		if pi.Path != nil {
			scnLayer.Path.Mac = mac
		}
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
		return nil, err
	}
	overlayLayers, err := pi.GetOverlay(dstMac)
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

func (pi *Pkt) checkScnHdr(b common.RawBytes) (common.RawBytes, error) {
	scnPkt := gopacket.NewPacket(b, LayerTypeScion, gopacket.NoCopy)
	scn := scnPkt.Layer(LayerTypeScion).(*ScionLayer)
	if scn == nil {
		return nil, fmt.Errorf("Could not parse SCION headers")
	}
	if scn.CmnHdr != *pi.CmnHdr {
		return nil, fmt.Errorf("Common header mismatch\nExpected %v\nActual   %v", pi.CmnHdr, scn.CmnHdr)
	}
	if !pi.AddrHdr.Eq(&scn.AddrHdr) {
		return nil, fmt.Errorf("Address header mismatch\nExpected %v\nActual   %v", pi.AddrHdr, scn.AddrHdr)
	}
	if err := pi.Path.Check(&scn.Path); err != nil {
		return nil, err
	}
	// As we already checked that we have a valid common header, we can use the HdrLen safely
	return b[scn.CmnHdr.HdrLenBytes():], nil
}

func (pi *Pkt) checkL4(b common.RawBytes) (common.RawBytes, error) {
	if pi.L4 == nil {
		return b, nil
	}
	switch pi.L4.L4Type() {
	case common.L4None:
	case common.L4SCMP:
		pktL4, _ := scmp.HdrFromRaw(b)
		scmp := pi.L4.(*scmp.Hdr)
		if !scmpEqual(scmp, pktL4) {
			return nil, fmt.Errorf("L4 SCMP header does not match")
		}
		// TODO compare specific SCMP data and payload
	case common.L4UDP:
		pktL4, _ := l4.UDPFromRaw(b)
		udp := pi.L4.(*l4.UDP)
		if !udpEqual(udp, pktL4) {
			return nil, fmt.Errorf("L4 UDP header does not match")
		}
	}
	return b[pi.L4.L4Len():], nil
}

func (pi *Pkt) checkPld(b common.RawBytes) (common.RawBytes, error) {
	if pi.Pld == nil {
		return b, nil
	}
	expPld := make(common.RawBytes, pi.Pld.Len())
	pi.Pld.WritePld(expPld)
	if !bytes.Equal(b, expPld) {
		return nil, fmt.Errorf("Payload does not match")
	}
	return b[pi.Pld.Len():], nil
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
	return a.Class == b.Class && a.Type == b.Type && a.TotalLen == b.TotalLen
}

func udpEqual(a, b *l4.UDP) bool {
	// Ignore Checksum
	return a.SrcPort == b.SrcPort && a.DstPort == b.DstPort && a.TotalLen == b.TotalLen
}
