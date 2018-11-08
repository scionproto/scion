package main

import (
	"fmt"
	"reflect"
	"time"

	"github.com/google/gopacket"

	"github.com/scionproto/scion/go/border/braccept/pkti"
)

var (
	cases []reflect.SelectCase
)

// checkRecvPkts compares packets received in any interface against the expected packets
// from the test, checking that they have been received on the expected interface.
func checkRecvPkts(t *BRTest) error {
	timerIdx := len(devList)
	if cases == nil {
		// We just need to setup the dynamic select case once per run
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

	expPkts := make([]pkti.PktMatch, len(t.Out))
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

// checkPkt compare a given packet against all the possible expected packets,
// It return the index of the expected packet matched or an error with a pretty-print
// packet dump of the unmatched packet.
func checkPkt(expPkts []pkti.PktMatch, devIdx int, pkt gopacket.Packet) (int, error) {
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
	scnPkt := gopacket.NewPacket(payload, pkti.LayerTypeScion, gopacket.NoCopy)
	if scn := scnPkt.Layer(pkti.LayerTypeScion).(*pkti.ScionLayer); scn != nil {
		scn.Path.Parse(scn.Path.Raw)
		scn.Path.Raw = nil
	}
	return 0, fmt.Errorf("\nUnexpected pkt on interface %s\n%v\n%v",
		devList[devIdx].contDev, pkt, scnPkt)
}
