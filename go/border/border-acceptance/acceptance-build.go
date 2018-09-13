package main

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spkt"
)

const bufSize = 1500

func buildPkts(test *BRTest) (ifPktInfo, []ifPktInfo) {
	inPkt := ifPktInfo{dev: test.In.Dev, overlay: test.In.Overlay}
	b := make([]byte, bufSize)
	offset := buildScn(test.In, b)
	offset += buildScnPath(test.In.Path, b[offset:])
	// TODO specific Payload
	//inPkt.data = buildOverlay(test.In.Dev, test.In.Overlay, b[:offset])
	inPkt.data = make([]byte, offset)
	copy(inPkt.data, b[:offset])
	outPkts := make([]ifPktInfo, len(test.Out))
	for i, _ := range test.Out {
		p := test.Out[i]
		offset := buildScn(p, b)
		offset += buildScnPath(p.Path, b[offset:])
		// TODO specific Payload
		outPkts[i].dev = p.Dev
		outPkts[i].overlay = p.Overlay
		//outPkts[i].data = buildOverlay(p.Dev, p.Overlay, b[:offset])
		outPkts[i].data = make([]byte, offset)
		copy(outPkts[i].data, b[:offset])
	}
	return inPkt, outPkts
}

func buildScn(info *pktInfo, b []byte) int {
	offset := 0
	dst := addr.HostFromIP(net.ParseIP(info.Addr.DstHost))
	src := addr.HostFromIP(net.ParseIP(info.Addr.SrcHost))
	cmnAddrLen := spkt.CmnHdrLen + spkt.AddrHdrLen(dst, src)
	hdrLen := cmnAddrLen + pathLen(info.Path)
	// Common header
	cmnHdr := &spkt.CmnHdr{
		Ver:       spkt.SCIONVersion,
		DstType:   dst.Type(),
		SrcType:   src.Type(),
		TotalLen:  uint16(hdrLen),
		HdrLen:    uint8(hdrLen) / common.LineLen,
		CurrInfoF: infoIdxToOffset(cmnAddrLen, info.Path, info.InfoF),
		CurrHopF:  hopIdxToOffset(cmnAddrLen, info.HopF),
		NextHdr:   4,
	}
	fmt.Printf("CmnHdr:\n%v\n", cmnHdr)
	cmnHdr.Write(b[offset:])
	offset += spkt.CmnHdrLen
	// Address header
	dstIA, _ := addr.IAFromString(info.Addr.DstIA)
	srcIA, _ := addr.IAFromString(info.Addr.SrcIA)
	addrHdr := &AddrHdr{
		DstIA:   dstIA,
		SrcIA:   srcIA,
		DstHost: dst,
		SrcHost: src,
	}
	fmt.Printf("AddrHdr:\n%v\n", addrHdr)
	offset += addrHdr.Write(b[offset:])
	return offset
}

func buildScnPath(segs []*segDef, b []byte) int {
	// The path is already basically generated in the test description
	offset := 0
	for i, _ := range segs {
		seg := segs[i]
		// Set Info Field
		seg.inf.Hops = uint8(len(seg.hops))
		if seg.inf.TsInt == 0 {
			seg.inf.TsInt = uint32(time.Now().Unix())
		}
		fmt.Printf("InfoField:\n%v\n", seg.inf)
		seg.inf.Write(b[offset:])
		offset += spath.InfoFieldLength
		//prevHop := make([]byte, spath.HopFieldLength)
		prevHop := []byte{}
		for j, _ := range seg.hops {
			hop := seg.hops[j]
			//hop.ExpTime = spath.DefaultHopFExpiry
			mac.Reset()
			hop.Mac, err = hop.CalcMac(mac, seg.inf.TsInt, prevHop)
			if err != nil {
				panic(err)
			}
			fmt.Printf("HopField:\n%v\n", hop)
			hop.Write(b[offset:])
			prevHop = b[offset+1 : offset+spath.HopFieldLength]
			offset += spath.HopFieldLength
		}
	}
	return offset
}

func buildOverlay(dev string, overInfo *overlayInfo, scnHdr []byte) []byte {
	srcMac, _ := net.ParseMAC("00:00:de:ad:be:ef") // XXX Irrelevant
	ethernetLayer := &layers.Ethernet{
		DstMAC:       devByName[dev].mac,
		SrcMAC:       srcMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP(overInfo.SrcAddr),
		DstIP:    net.ParseIP(overInfo.DstAddr),
	}
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(overInfo.SrcPort),
		DstPort: layers.UDPPort(overInfo.DstPort),
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)
	// And create the packet with the layers
	pkt := gopacket.NewSerializeBuffer()
	//pkt := gopacket.NewSerializeBufferExpectedSize(0, bufSize)
	//func NewSerializeBufferExpectedSize(expectedPrependLength, expectedAppendLength int) SerializeBuffer {
	/*
		if err := pkt.Clear(); err != nil {
			panic(err)
		}
	*/
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(pkt, options,
		ethernetLayer, ipLayer, udpLayer, gopacket.Payload(scnHdr))
	if err != nil {
		panic(err)
	}
	fmt.Printf("Created packet:\n%v%v%v\n", gopacket.LayerDump(ethernetLayer),
		gopacket.LayerDump(ipLayer), gopacket.LayerDump(udpLayer))
	rawPkt := pkt.Bytes()
	return rawPkt
}

func segLen(segs *segDef) int {
	return spath.InfoFieldLength + spath.HopFieldLength*len(segs.hops)
}

func pathLen(segs []*segDef) int {
	size := 0
	for i, _ := range segs {
		size += segLen(segs[i])
	}
	return size
}

func infoIdxToOffset(hLen int, segs []*segDef, idx int) uint8 {
	var size int
	for i := 0; i < idx-1; i++ {
		size += segLen(segs[i])
	}
	return uint8((hLen + size) / common.LineLen)
}

// XXX This assumes all HopF are the same length
func hopIdxToOffset(hLen int, idx int) uint8 {
	size := spath.InfoFieldLength
	size += spath.HopFieldLength * (idx - 1)
	return uint8((hLen + size) / common.LineLen)
}
