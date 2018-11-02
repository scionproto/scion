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

	expPkts := make([]PktMatch, len(t.Out))
	for i, _ := range t.Out {
		expPkts[i] = t.Out[i]
		expPkts[i].Merge(t.In.GetPktInfo())
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

func checkPkt(expPkts []PktMatch, devIdx int, pkt gopacket.Packet) (int, error) {
	for i, _ := range expPkts {
		expPkt := expPkts[i]
		// Check interface
		if expPkt.GetDev() != devList[devIdx].contDev {
			continue
		}
		if err := expPkt.Match(pkt); err != nil {
			fmt.Println(err)
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

func (pi *PktInfo) Match(pkt gopacket.Packet) error {
	var b common.RawBytes

	// Skip first Layer, Ethernet
	l := pkt.Layers()[1:]
	if l, err = pi.checkOverlay(l); err != nil {
		return err
	}
	if b, err = pi.checkScnHdr(l[0].LayerContents()); err != nil {
		return err
	}
	// TODO Check Extensions
	// Check L4 and Payload
	if b, err = pi.checkL4(b); err != nil {
		return err
	}
	if b, err = pi.checkPld(b); err != nil {
		return err
	}
	if len(b) > 0 {
		return fmt.Errorf("Unexpected traling bytes: %v", b)
	}
	// Expected packet matched!
	return nil
}

//
// Check Overlay
//
func (pi *PktInfo) checkOverlay(l []gopacket.Layer) ([]gopacket.Layer, error) {
	overlayLayers := pi.Overlay.ToLayer()
	for i := range overlayLayers {
		if err := compareLayer(l[i], overlayLayers[i]); err != nil {
			return l[i:], err
		}
	}
	return l[len(overlayLayers):], nil
}

func compareLayer(act gopacket.Layer, exp gopacket.SerializableLayer) error {
	if exp.LayerType() != act.LayerType() {
		return fmt.Errorf("Wrong Layer Type, expected %s, actuaact %s",
			exp.LayerType(), act.LayerType())
	}
	switch exp.LayerType() {
	case layers.LayerTypeIPv4:
		return compareIP4Layer(exp.(*layers.IPv4), act.(*layers.IPv4))
	case layers.LayerTypeIPv6:
		return compareIP6Layer(exp.(*layers.IPv6), act.(*layers.IPv6))
	case layers.LayerTypeUDP:
		return compareUDPLayer(exp.(*layers.UDP), act.(*layers.UDP))
	}
	return fmt.Errorf("Unknown layer %s", exp.LayerType())
}

func compareIP4Layer(act, exp *layers.IPv4) error {
	return compareIPLayer(act.SrcIP, act.DstIP, exp.SrcIP, exp.DstIP)
}

func compareIP6Layer(act, exp *layers.IPv6) error {
	return compareIPLayer(act.SrcIP, act.DstIP, exp.SrcIP, exp.DstIP)
}

func compareIPLayer(actSrcIP, actDstIP, expSrcIP, expDstIP net.IP) error {
	if !actSrcIP.Equal(expSrcIP) {
		return fmt.Errorf("Wrong Source IP, expected %s, actual %s", expSrcIP, actSrcIP)
	}
	if !actDstIP.Equal(expDstIP) {
		return fmt.Errorf("Wrong Destination IP, expected %s, actual %s", expDstIP, actDstIP)
	}
	return nil
}

func compareUDPLayer(act, exp *layers.UDP) error {
	if act.SrcPort != exp.SrcPort {
		return fmt.Errorf("Wrong UDP Source Port, expected %s, actual %s",
			exp.SrcPort, act.SrcPort)
	}
	if act.DstPort != exp.DstPort {
		return fmt.Errorf("Wrong UDP Destination Port, expected %s, actual %s",
			exp.DstPort, act.DstPort)
	}
	return nil
}

//
// Check SCION
//
func (pi *PktInfo) checkScnHdr(b common.RawBytes) (common.RawBytes, error) {
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
	if err := pi.checkScnPath(&scn.Path); err != nil {
		return nil, err
	}
	// As we already checked that we have a valid common header, we can use the HdrLen safely
	return b[scn.CmnHdr.HdrLenBytes():], nil
}

func (pi *PktInfo) checkScnPath(p *ScnPath) error {
	p.Parse(p.Raw)
	if len(p.Segs) != len(pi.Path.Segs) {
		return fmt.Errorf("Number of segments mismatch, pi.Pathected=%d, actual=%d",
			len(pi.Path.Segs), len(p.Segs))
	}
	for i, _ := range pi.Path.Segs {
		if err := checkScnPathSeg(pi.Path.Segs[i], p.Segs[i]); err != nil {
			return nil
		}
	}
	return nil
}

func checkScnPathSeg(exp, act *SegDef) error {
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

//
// Check L4
//
func (pi *PktInfo) checkL4(b common.RawBytes) (common.RawBytes, error) {
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

func scmpEqual(a, b *scmp.Hdr) bool {
	// Ignore Checksum and Timestamp
	return a.Class == b.Class && a.Type == b.Type && a.TotalLen == b.TotalLen
}

func udpEqual(a, b *l4.UDP) bool {
	// Ignore Checksum
	return a.SrcPort == b.SrcPort && a.DstPort == b.DstPort && a.TotalLen == b.TotalLen
}

//
// Check Payload
//
func (pi *PktInfo) checkPld(b common.RawBytes) (common.RawBytes, error) {
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
