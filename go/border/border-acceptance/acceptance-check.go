package main

import (
	"bytes"
	"fmt"
	"net"
	"reflect"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func checkRecvPkts(expPkts []ifPktInfo) error {
	timerIdx := len(devList)
	cases := make([]reflect.SelectCase, timerIdx+1)
	for i, ifi := range devList {
		h := ifi.handle
		packetSource := gopacket.NewPacketSource(h, h.LinkType())
		ch := packetSource.Packets()
		cases[i] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ch)}
	}
	//timerCh := time.After(time.Second)
	start := time.Now()
	timerCh := time.After(timeout)
	cases[timerIdx] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(timerCh)}
	for {
		idx, pktV, ok := reflect.Select(cases)
		if !ok {
			cases[idx].Chan = reflect.ValueOf(nil)
			return fmt.Errorf("Unexpected interface %s/%s closed:\n",
				devList[idx].hostDev, devList[idx].contDev)
		}
		if idx == timerIdx {
			if len(expPkts) == 0 {
				// Case when no packet is expected
				return nil
			}
			return fmt.Errorf("Timeout receiving packets\n")
		}
		pkt := pktV.Interface().(gopacket.Packet)
		fmt.Printf("Received packet %v:\n%v", time.Since(start), pkt)

		i, err := checkPkt(expPkts, idx, pkt)
		if err != nil {
			fmt.Printf("%s\n", err)
			continue
		}
		expPkts[i] = expPkts[len(expPkts)-1]
		expPkts = expPkts[:len(expPkts)-1]
		if len(expPkts) == 0 {
			return nil
		}
		// XXX check if any other packets has been received?
		// TODO reset timeout?
	}
}

func checkPkt(expPkts []ifPktInfo, devIdx int, pkt gopacket.Packet) (int, error) {
	for i, _ := range expPkts {
		expPkt := expPkts[i]
		// Check interface
		if expPkt.dev != devList[devIdx].contDev {
			continue
		}
		var payload []byte
		if payload, err = checkOverlay(expPkt.overlay, pkt); err != nil {
			// We could be expecting another packet in this interface
			continue
		}
		fmt.Printf("Valid Packet Overlay\n")
		if !bytes.Equal(payload, expPkt.data) {
			continue
		}
		// Expected packet matched!
		fmt.Printf("Valid SCION Packet\n")
		return i, nil
	}
	return 0, fmt.Errorf("Unexpected pkt on interface %s:\n", devList[devIdx].contDev)
}

func checkOverlay(overInfo *overlayInfo, pkt gopacket.Packet) ([]byte, error) {
	// Check IP
	var pktSrcIP, pktDstIP net.IP
	if l := pkt.Layer(layers.LayerTypeIPv4); l != nil {
		ip, _ := l.(*layers.IPv4)
		pktSrcIP = ip.SrcIP
		pktDstIP = ip.DstIP
	} else if l := pkt.Layer(layers.LayerTypeIPv6); l != nil {
		ip, _ := l.(*layers.IPv6)
		pktSrcIP = ip.SrcIP
		pktDstIP = ip.DstIP
	} else {
		return nil, fmt.Errorf("Wrong Overlay Type, neither IPv4 nor IPv6")
	}
	srcIP := net.ParseIP(overInfo.SrcAddr)
	dstIP := net.ParseIP(overInfo.DstAddr)
	if !srcIP.Equal(pktSrcIP) {
		return nil, fmt.Errorf("Wrong Overlay Source IP, expected %s, actual %s", srcIP, pktSrcIP)
	}
	if !dstIP.Equal(pktDstIP) {
		return nil, fmt.Errorf("Wrong Overlay Destination IP, expected %s, actual %s", dstIP, pktDstIP)
	}
	// Check Ports
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
	srcPort := layers.UDPPort(overInfo.SrcPort)
	dstPort := layers.UDPPort(overInfo.DstPort)
	if srcPort != pktSrcPort {
		return nil, fmt.Errorf("Wrong Overlay Source Port, expected %s, actual %s", srcPort, pktSrcPort)
	}
	if dstPort != pktDstPort {
		return nil, fmt.Errorf("Wrong Overlay Destination iP, expected %s, actual %s", dstPort, pktDstPort)
	}
	return payload, nil
}
