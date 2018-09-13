package main

import (
	"bytes"
	"fmt"
	"net"
	"reflect"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spath"
)

var (
	cases []reflect.SelectCase
)

func checkRecvPkts(t *BRTest) error {
	timerIdx := len(devList)
	if cases == nil {
		cases = make([]reflect.SelectCase, timerIdx+1)
		for i, ifi := range devList {
			h := ifi.handle
			packetSource := gopacket.NewPacketSource(h, h.LinkType())
			ch := packetSource.Packets()
			cases[i] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ch)}
		}
	}
	timerCh := time.After(timeout)
	cases[timerIdx] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(timerCh)}

	expPkts := make([]*pktInfo, len(t.Out))
	for i, _ := range t.Out {
		expPkts[i] = t.Out[i]
		expPkts[i].genPktExpected(t.In)
	}
	for {
		idx, pktV, ok := reflect.Select(cases)
		if !ok {
			cases[idx].Chan = reflect.ValueOf(nil)
			return fmt.Errorf("Unexpected interface %s/%s closed:\n",
				devList[idx].hostDev, devList[idx].contDev)
		}
		if idx == timerIdx {
			// Timeout receiving packets
			if len(expPkts) > 0 {
				return fmt.Errorf("Timeout receiving packets\n")
			}
			return nil
		}
		// Packet received
		pkt := pktV.Interface().(gopacket.Packet)
		i, err := checkPkt(expPkts, idx, pkt)
		if err != nil {
			if len(expPkts) > 0 {
				fmt.Println(err)
				continue
			}
			// Packet received when no packet is expected
			return err
		}
		expPkts[i] = expPkts[len(expPkts)-1]
		expPkts = expPkts[:len(expPkts)-1]
	}
	return nil
}

func checkPkt(expPkts []*pktInfo, devIdx int, pkt gopacket.Packet) (int, error) {
	for i, _ := range expPkts {
		expPkt := expPkts[i]
		// Check interface
		if expPkt.Dev != devList[devIdx].contDev {
			continue
		}
		var b []byte
		if b, err = checkOverlay(pkt, expPkt.Overlay[0], expPkt.Overlay[1]); err != nil {
			// We could be expecting another packet in this interface
			continue
		}
		var l4Off int
		if l4Off, err = checkScnHdr(b, expPkt); err != nil {
			fmt.Println(err)
			continue
		}
		// TODO Check Extensions
		// Check L4 and Payload
		if err = checkL4Pld(b[l4Off:], expPkt); err != nil {
			continue
		}
		// Expected packet matched!
		return i, nil
	}
	payload := pkt.ApplicationLayer().LayerContents()
	scnPkt := gopacket.NewPacket(payload, LayerTypeScion, gopacket.NoCopy)
	if scn := scnPkt.Layer(LayerTypeScion).(*ScionLayer); scn != nil {
		scn.Path.Parse(scn.Path.Raw)
		scn.Path.Raw = nil
	}
	return 0, fmt.Errorf("Unexpected pkt on interface %s\n%v\n%v\n",
		devList[devIdx].contDev, pkt, scnPkt)
}

// NOTE: We cannot predict all the fields in the overlay header, ie. ID set by the kernel
func checkOverlay(pkt gopacket.Packet, l3Layer, l4Layer gopacket.Layer) ([]byte, error) {
	// Check IPv4 or IPv6 Overlay
	srcIPExp, dstIPExp := getSrcDstIP(l3Layer, l3Layer.LayerType())
	var srcIP, dstIP net.IP
	if l := pkt.Layer(l3Layer.LayerType()); l != nil {
		srcIP, dstIP = getSrcDstIP(l3Layer, l3Layer.LayerType())
	} else {
		return nil, fmt.Errorf("Wrong Overlay Type, layer %s not found", l3Layer.LayerType())
	}
	if !srcIP.Equal(srcIPExp) {
		return nil, fmt.Errorf("Wrong Overlay Source IP, expected %s, actual %s", srcIP, srcIPExp)
	}
	if !dstIP.Equal(dstIPExp) {
		return nil, fmt.Errorf("Wrong Overlay Destination IP, expected %s, actual %s", dstIP, dstIPExp)
	}
	// Check Ports
	// TODO support other L4 overlay protocols
	var pktSrcPort, pktDstPort layers.UDPPort
	var payload []byte
	if l := pkt.Layer(layers.LayerTypeUDP); l != nil {
		udp, _ := l.(*layers.UDP)
		pktSrcPort = udp.SrcPort
		pktDstPort = udp.DstPort
		payload = udp.LayerPayload()
	} else {
		return nil, fmt.Errorf("Wrong Overlay Type, expected UDP")
	}
	udp, _ := l4Layer.(*layers.UDP)
	if udp.SrcPort != pktSrcPort {
		return nil, fmt.Errorf("Wrong Overlay Source Port, expected %s, actual %s",
			udp.SrcPort, pktSrcPort)
	}
	if udp.DstPort != pktDstPort {
		return nil, fmt.Errorf("Wrong Overlay Destination iP, expected %s, actual %s",
			udp.DstPort, pktDstPort)
	}
	return payload, nil
}

func getSrcDstIP(l gopacket.Layer, t gopacket.LayerType) (net.IP, net.IP) {
	switch t {
	case layers.LayerTypeIPv4:
		ip, _ := l.(*layers.IPv4)
		return ip.SrcIP, ip.DstIP
	case layers.LayerTypeIPv6:
		ip, _ := l.(*layers.IPv6)
		return ip.SrcIP, ip.DstIP
	}
	return nil, nil
}

func checkScnHdr(b []byte, pi *pktInfo) (int, error) {
	scnPkt := gopacket.NewPacket(b, LayerTypeScion, gopacket.NoCopy)
	scn := scnPkt.Layer(LayerTypeScion).(*ScionLayer)
	if scn == nil {
		return 0, fmt.Errorf("Could not parse SCION headers")
	}
	if scn.CmnHdr != *pi.CmnHdr {
		return 0, fmt.Errorf("Common header mismatch\nExpected %v\nActual   %v", pi.CmnHdr, scn.CmnHdr)
	}
	if !pi.AddrHdr.Eq(&scn.AddrHdr) {
		return 0, fmt.Errorf("Address header mismatch\nExpected %v\nActual   %v", pi.AddrHdr, scn.AddrHdr)
	}
	// As we already checked that we have a valid common header, we can use the HdrLen safely
	if err := checkScnPath(&scn.Path, pi.Path); err != nil {
		return 0, err
	}
	return scn.CmnHdr.HdrLenBytes(), nil
}

func checkScnPath(p *ScnPath, exp *ScnPath) error {
	p.Parse(p.Raw)
	if len(p.Segs) != len(exp.Segs) {
		return fmt.Errorf("Numer of segments mismatch, expected=%d, actual=%d",
			len(exp.Segs), len(p.Segs))
	}
	for i, _ := range exp.Segs {
		if err := checkScnPathSeg(exp.Segs[i], p.Segs[i]); err != nil {
			return nil
		}
	}
	return nil
}

func checkScnPathSeg(exp, act *segDef) error {
	if exp.inf != act.inf {
		return fmt.Errorf("Info Field mismatch\nExpected: %s\nActual:   %s\n", exp.inf, act.inf)
	}
	for i, _ := range exp.hops {
		if compareHopF(exp.hops[i], act.hops[i]) {
			return fmt.Errorf("Hop Field mismatch\nExpected: %s\nActual:   %s\n",
				exp.hops[i], act.hops[i])
		}
	}
	return nil
}

func compareHopF(a, o spath.HopField) bool {
	return a.Xover == o.Xover && a.VerifyOnly == o.VerifyOnly && a.ExpTime == o.ExpTime &&
		a.ConsIngress == o.ConsIngress && a.ConsEgress == o.ConsEgress && bytes.Equal(a.Mac, o.Mac)
}

func checkL4Pld(b []byte, pi *pktInfo) error {
	if pi.L4 == nil && pi.Pld == nil && b == nil {
		return nil
	}
	pktPld := b
	switch pi.L4.L4Type() {
	case common.L4None:
	case common.L4SCMP:
		pktL4, _ := scmp.HdrFromRaw(b)
		scmp := pi.L4.(*scmp.Hdr)
		if !scmpEqual(scmp, pktL4) {
			return fmt.Errorf("L4 SCMP header does not match")
		}
		fmt.Printf("DEBUG\n    exp %v\n,    actual %v\n", scmp, pktL4)
		pktPld = b[scmp.L4Len():]
		// TODO compare specific SCMP data and payload
		return nil
	case common.L4UDP:
		//fmt.Printf("DEBUG L4: %x", b)
		pktL4, _ := l4.UDPFromRaw(b)
		udp := pi.L4.(*l4.UDP)
		if !udpEqual(udp, pktL4) {
			fmt.Printf("DEBUG\nExpected %v\nActual   %v\n", udp, pktL4)
			return fmt.Errorf("L4 UDP header does not match")
		}
		pktPld = b[udp.L4Len():]
	}
	if pi.Pld != nil {
		expPld := make([]byte, pi.Pld.Len())
		pi.Pld.WritePld(expPld)
		if !bytes.Equal(pktPld, expPld) {
			return fmt.Errorf("Payload does not match")
		}
	} else if len(pktPld) > 0 {
		return fmt.Errorf("Unexpected payload")
	}
	return nil
}

func udpEqual(a, b *l4.UDP) bool {
	// Ignore Checksum
	return a.SrcPort == b.SrcPort && a.DstPort == b.DstPort && a.TotalLen == b.TotalLen
}

func scmpEqual(a, b *scmp.Hdr) bool {
	// Ignore Checksum and Timestamp
	return a.Class == b.Class && a.Type == b.Type && a.TotalLen == b.TotalLen
}
