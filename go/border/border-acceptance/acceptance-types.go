package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/imdario/mergo"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/lib/util"
)

func gOverlay(srcAddr string, srcPort uint16, dstAddr string, dstPort uint16) []SerializableLayer {
	var l []SerializableLayer
	srcIP := net.ParseIP(srcAddr)
	dstIP := net.ParseIP(dstAddr)
	var nl gopacket.NetworkLayer
	if dstIP.To4() != nil {
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
	} else {
		// TODO IPv6
		return nil
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	l = append(l, udp)
	udp.SetNetworkLayerForChecksum(nl)
	return l
}

func gPath(infoF, hopF int, segs []*segDef) *ScnPath {
	p := &ScnPath{}
	for i := 0; i < infoF-1; i++ {
		p.InfOff += 1 + int(segs[i].inf.Hops)
	}
	p.HopOff = p.InfOff + hopF
	p.Segs = segs
	return p
}

type BRTest struct {
	In  *pktInfo
	Out []*pktInfo
}

type SerializableLayer interface {
	gopacket.SerializableLayer
	gopacket.Layer
}

type ScnPath struct {
	spath.Path
	Segs []*segDef
}

func (p *ScnPath) Parse(b []byte) error {
	if len(b) == 0 || len(b)%common.LineLen != 0 {
		return fmt.Errorf("Bad path length, actual=%d", len(b))
	}
	//p.Raw = b
	offset := 0
	for offset < len(b) {
		seg := &segDef{}
		len, err := seg.Parse(b[offset:])
		if err != nil {
			return err
		}
		p.Segs = append(p.Segs, seg)
		offset += len
	}
	return nil
}

type segDef struct {
	inf  spath.InfoField
	hops []spath.HopField
}

func (s *segDef) Parse(b []byte) (int, error) {
	inf, err := spath.InfoFFromRaw(b)
	if err != nil {
		return 0, err
	}
	s.inf = *inf
	segLen := int(spath.InfoFieldLength + inf.Hops*common.LineLen)
	if segLen > len(b) {
		return 0, fmt.Errorf("Buffer is too short, expected=%d, actual=%d", segLen, len(b))
	}
	for offset := spath.InfoFieldLength; offset < segLen; offset += common.LineLen {
		hop, err := spath.HopFFromRaw(b[offset:])
		if err != nil {
			return 0, err
		}
		s.hops = append(s.hops, *hop)
	}
	return segLen, nil
}

func (s *segDef) String() string {
	var str []string
	var cons, short, peer string
	if s.inf.ConsDir {
		cons = "C"
	}
	if s.inf.Shortcut {
		short = "S"
	}
	if s.inf.Peer {
		peer = "P"
	}
	for i, _ := range s.hops {
		var xover, ver string
		if s.hops[i].Xover {
			xover = "X"
		}
		if s.hops[i].VerifyOnly {
			ver = "V"
		}
		str = append(str, fmt.Sprintf("%1s%1s %04d:%04d", xover, ver,
			s.hops[i].ConsIngress, s.hops[i].ConsEgress))
	}
	return fmt.Sprintf("[%1s%1s%1s] %s", cons, short, peer, strings.Join(str, " <-> "))
}

func (s *segDef) segLen() int {
	return spath.InfoFieldLength + spath.HopFieldLength*len(s.hops)
}

func printSegs(segs []*segDef) string {
	var str []string
	for _, s := range segs {
		str = append(str, fmt.Sprintf("\t%s", s))
	}
	return strings.Join(str, "\n")
}

func pathLen(segs []*segDef) int {
	len := 0
	for i, _ := range segs {
		len += segs[i].segLen()
	}
	return len
}

type pktInfo struct {
	Dev     string
	Overlay []SerializableLayer
	CmnHdr  *spkt.CmnHdr
	AddrHdr *AddrHdr
	Path    *ScnPath
	Exts    []common.Extension
	L4      l4.L4Header
	Pld     common.Payload
}

func (pi *pktInfo) mergeCmnHdr() {
	// All the other headers must be already set
	cmnHdr := pi.genCmnHdr()
	if pi.CmnHdr != nil {
		if err := mergo.Merge(pi.CmnHdr, cmnHdr); err != nil {
			panic(err)
		}
	} else {
		pi.CmnHdr = cmnHdr
	}
}

func (pi *pktInfo) genPktSent() {
	// All the other headers must be provided
	pi.mergeCmnHdr()
}

func (pi *pktInfo) genPktExpected(def *pktInfo) {
	// If not set, use headers from default packet, except the common header
	if pi.Overlay == nil {
		pi.Overlay = def.Overlay
	}
	if pi.AddrHdr == nil {
		pi.AddrHdr = def.AddrHdr
	}
	if pi.Path == nil {
		pi.Path = def.Path
	}
	if pi.Exts == nil {
		pi.Exts = def.Exts
	}
	if pi.L4 == nil {
		pi.L4 = def.L4
	}
	if pi.Pld == nil {
		pi.Pld = def.Pld
	}
	pi.mergeCmnHdr()
}

func (pi *pktInfo) genCmnHdr() *spkt.CmnHdr {
	// Generate Common Header
	addrHdrLen := pi.AddrHdr.Len()
	pathOff := (spkt.CmnHdrLen + addrHdrLen) / common.LineLen
	hdrLen := spkt.CmnHdrLen + addrHdrLen + pathLen(pi.Path.Segs)
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
		CurrInfoF: uint8(pathOff + pi.Path.InfOff),
		CurrHopF:  uint8(pathOff + pi.Path.HopOff),
	}
	if len(pi.Exts) > 0 {
		cmnHdr.NextHdr = pi.Exts[0].Class()
	} else if pi.L4 != nil {
		cmnHdr.NextHdr = pi.L4.L4Type()
	}
	return cmnHdr
}

func (pi *pktInfo) build() []byte {
	pkt := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths: true,
	}
	var pLayers []gopacket.SerializableLayer
	pLayers = append(pLayers, genEth(pi.Dev))
	pLayers = append(pLayers, pi.Overlay[0])
	pLayers = append(pLayers, pi.Overlay[1])
	pLayers = append(pLayers, &ScionLayer{CmnHdr: *pi.CmnHdr, AddrHdr: *pi.AddrHdr, Path: *pi.Path})
	// TODO Extensions
	if pi.L4 != nil {
		pLayers = append(pLayers, l4ToLayer(pi.L4))
	}
	if pi.Pld != nil {
		pLayers = append(pLayers, pldToLayer(pi.Pld))
	}
	err = gopacket.SerializeLayers(pkt, options, pLayers[3:]...)
	if err != nil {
		panic(err)
	}
	options.ComputeChecksums = true
	// XXX Cannot use SerializeLayers as it clears previously written bytes
	for i := len(pLayers[0:3]) - 1; i >= 0; i-- {
		layer := pLayers[i]
		err := layer.SerializeTo(pkt, options)
		if err != nil {
			panic(err)
		}
	}
	rawPkt := pkt.Bytes()
	return rawPkt
}

func genEth(dev string) SerializableLayer {
	srcMac, _ := net.ParseMAC("00:00:de:ad:be:ef") // XXX Irrelevant
	return &layers.Ethernet{
		DstMAC:       devByName[dev].mac,
		SrcMAC:       srcMac,
		EthernetType: layers.EthernetTypeIPv4, // TODO based on overlay
	}
}

func l4ToLayer(l l4.L4Header) SerializableLayer {
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

func pldToLayer(pld common.Payload) SerializableLayer {
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
	scnLen := spkt.CmnHdrLen + l.AddrHdr.Len() + pathLen(l.Path.Segs)
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

func writeScnPath(segs []*segDef, b []byte) int {
	offset := 0
	for i, _ := range segs {
		offset += writeScnPathSeg(segs[i], b[offset:])
	}
	return offset
}

func writeScnPathSeg(seg *segDef, b []byte) int {
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

//
// SCION AddrHdr
//
type AddrHdr struct {
	DstIA, SrcIA     addr.IA
	DstHost, SrcHost addr.HostAddr
}

func NewAddrHdr(srcIA, srcHost, dstIA, dstHost string) *AddrHdr {
	dIA, _ := addr.IAFromString(dstIA)
	sIA, _ := addr.IAFromString(srcIA)
	return &AddrHdr{
		DstIA:   dIA,
		SrcIA:   sIA,
		DstHost: addr.HostFromIP(net.ParseIP(dstHost)),
		SrcHost: addr.HostFromIP(net.ParseIP(srcHost)),
	}
}

func ParseFromRaw(b common.RawBytes, srcT, dstT addr.HostAddrType) (*AddrHdr, error) {
	a := &AddrHdr{}
	if _, err := a.Parse(b, srcT, dstT); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *AddrHdr) Parse(b common.RawBytes, srcT, dstT addr.HostAddrType) (int, error) {
	srcLen, err := addr.HostLen(srcT)
	if err != nil {
		return 0, err
	}
	dstLen, err := addr.HostLen(dstT)
	if err != nil {
		return 0, err
	}
	addrLen := ceil(2*addr.IABytes+int(dstLen+srcLen), common.LineLen)
	if addrLen > len(b) {
		return 0, fmt.Errorf("Buffer too short, expected=%d, acutal=%d", addrLen, len(b))
	}
	a.DstIA = addr.IAFromRaw(b)
	a.SrcIA = addr.IAFromRaw(b[addr.IABytes:])
	offset := uint8(2 * addr.IABytes)
	a.DstHost, err = addr.HostFromRaw(b[offset:], dstT)
	if err != nil {
		return 0, err
	}
	offset += dstLen
	a.SrcHost, err = addr.HostFromRaw(b[offset:], srcT)
	if err != nil {
		return 0, err
	}
	return addrLen, nil
}

func ceil(len, mult int) int {
	// mult must be base 2 value
	return (len + mult - 1) &^ (mult - 1)
}

func (a *AddrHdr) Len() int {
	return ceil(2*addr.IABytes+a.DstHost.Size()+a.SrcHost.Size(), common.LineLen)
}

func (a *AddrHdr) Write(b common.RawBytes) int {
	// Address header
	offset := 0
	a.DstIA.Write(b[offset:])
	offset += addr.IABytes
	a.SrcIA.Write(b[offset:])
	offset += addr.IABytes
	// addr.HostAddr.Pack() is zero-copy, use it directly
	offset += copy(b[offset:], a.DstHost.Pack())
	offset += copy(b[offset:], a.SrcHost.Pack())
	// Zero memory padding
	addrPad := util.CalcPadding(offset, common.LineLen)
	zeroPad := b[offset : offset+addrPad]
	for i := range zeroPad {
		zeroPad[i] = 0
	}
	return offset + addrPad
}

func (a *AddrHdr) Eq(o *AddrHdr) bool {
	return a.DstIA.Eq(o.DstIA) && a.SrcIA.Eq(o.SrcIA) &&
		a.DstHost.Eq(o.DstHost) && a.SrcHost.Eq(o.SrcHost)
}

func (a *AddrHdr) String() string {
	return fmt.Sprintf("DstIA: %s, SrcIA: %s, DstHost: %s, SrcHost: %s",
		a.DstIA, a.SrcIA, a.DstHost, a.SrcHost)
}
