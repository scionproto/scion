// Copyright 2019 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/google/gopacket"

	"github.com/scionproto/scion/go/border/braccept/parser"
	"github.com/scionproto/scion/go/border/braccept/shared"
	"github.com/scionproto/scion/go/lib/log"
)

func ExpectedPackets(desc string, to string, pkts ...*DevTaggedLayers) int {
	var errors int
	// Given that the number of interfaces changes depending on the BR configuration,
	// we use a dynamic select/switch case approach, where each interface has an equivalent
	// case entry, and the last one is always the timer channel for the timeout.
	timerIdx := len(shared.DevList)
	timeout, err := time.ParseDuration(to)
	if err != nil {
		panic(err)
	}
	timerCh := time.After(timeout)
	// Add timeout channel as the last select case.
	cases[timerIdx] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(timerCh)}
	// XXX workaround until we use fixed MAC addresses in the containers
	for i := range pkts {
		pkt := pkts[i]
		e := pkt.TaggedLayers[0].(*parser.EthernetTaggedLayer)
		e.SrcMAC = shared.DevByName[pkt.Dev].Mac
	}
	// Serialize all expected packets so that we generate proper length values, checksums, etc.
	expPkts := toGoPackets(pkts...)
	var errStr []string
	for {
		idx, pktV, ok := reflect.Select(cases)
		if !ok {
			panic(fmt.Errorf("Unexpected interface %s/%s closed",
				shared.DevList[idx].HostDev, shared.DevList[idx].ContDev))
		}
		if idx == timerIdx {
			// Timeout receiving packets
			if len(expPkts) > 0 {
				errStr = append(errStr, fmt.Sprintf("Timeout receiving packets"))
			}
			break
		}
		// Packet received
		pkt := pktV.Interface().(gopacket.Packet)
		if _, e := checkPkt(IgnoredPkts, idx, pkt); e == nil {
			// Packet is to be ignored
			continue
		}
		/*
			else {
				pktStr := fmt.Sprintf("%s", pkt)
				ignStr := fmt.Sprintf("%s", IgnoredPkts[0].Pkt)
				fmt.Printf("DEBUG expect ignored:\n%s\n", compareStrings(pktStr, ignStr))
			}
		*/
		i, e := checkPkt(expPkts, idx, pkt)
		if e != nil {
			errStr = append(errStr, fmt.Sprintf("%s", e))
			continue
		}
		// Remove matched packet from expected packets
		expPkts = append(expPkts[:i], expPkts[i+1:]...)
	}
	if len(errStr) > 0 {
		log.Info(fmt.Sprintf("Test %s: %s\n", desc, fail()))
		log.Error(fmt.Sprintf("%s\n\n", strings.Join(errStr, "\n")))
		errors = 1
	} else {
		log.Info(fmt.Sprintf("Test %s: %s\n", desc, pass()))
	}
	return errors
}

/*

	golayers "github.com/google/gopacket/layers"
	"github.com/scionproto/scion/go/border/braccept/layers"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/util"
func verifyIPUDPChecksum(pkt gopacket.Packet) (uint16, uint16) {
	ip4 := pkt.Layer(golayers.LayerTypeIPv4)
	udp := pkt.Layer(golayers.LayerTypeUDP).(*golayers.UDP)
	pseudo := make(common.RawBytes, 20)
	copy(pseudo, ip4.LayerContents()[12:])
	pseudo[8] = 0
	pseudo[9] = byte(common.L4UDP)
	common.Order.PutUint16(pseudo[10:12], uint16(len(ip4.LayerPayload())))
	fmt.Printf("DEBUG IP4UDP udp: %s", gopacket.LayerDump(udp))
	copy(pseudo[12:], udp.LayerContents()[:6])
	return udp.Checksum, util.Checksum(pseudo, udp.LayerPayload())
}

func verifyScionUDPChecksum(pkt gopacket.Packet) (uint16, uint16) {
	scn := pkt.Layer(layers.LayerTypeScion).(*layers.Scion)
	var udp *golayers.UDP
	pktL := pkt.Layers()
	max := len(pktL) - 1
	for i := range pktL {
		l := pktL[max-i]
		if l.LayerType() == golayers.LayerTypeUDP {
			udp = l.(*golayers.UDP)
			break
		}
	}
	scratchPad := make(common.RawBytes, scn.AddrHdr.Len()+2+6)
	scratchPad[0] = 0
	scratchPad[1] = uint8(common.L4UDP)
	fmt.Printf("DEBUG ScionUDP udp: %s", gopacket.LayerDump(udp))
	copy(scratchPad[2:], udp.LayerContents()[:6])
	scn.AddrHdr.Write(scratchPad[8:])
	return udp.Checksum, util.Checksum(scratchPad[:8+scn.AddrHdr.NoPaddedLen()], udp.LayerPayload())
}

func checkIgnoredPkts(expPkts []*DevPkt, devIdx int, pkt gopacket.Packet) (int, error) {
	actCS, expCS := verifyIPUDPChecksum(pkt)
	fmt.Printf("DEBUG IP4UDP act csum: Actual %x, Expected %x\n\n", actCS, expCS)
	actCS, expCS = verifyScionUDPChecksum(pkt)
	fmt.Printf("DEBUG ScionUDP act csum: Actual %x, Expected %x\n\n", actCS, expCS)
	var errStr []string
	dev := shared.DevList[devIdx].ContDev
	for i := range expPkts {
		actCS, expCS = verifyIPUDPChecksum(expPkts[i].Pkt)
		fmt.Printf("DEBUG IP4UDP exp%d csum: Actual %x, Expected %x\n\n", i, actCS, expCS)
		actCS, expCS = verifyScionUDPChecksum(expPkts[i].Pkt)
		fmt.Printf("DEBUG ScionUDP exp%d csum: Actual %x, Expected %x\n\n", i, actCS, expCS)
		if dev != expPkts[i].Dev {
			continue
		}
		if err := ComparePackets(pkt, expPkts[i].Pkt); err != nil {
			errStr = append(errStr, fmt.Sprintf("[ERROR] %s\n", err))
			continue
		}
		// Packet matched!
		return i, nil
	}
	if len(expPkts) == 0 {
		errStr = append(errStr,
			fmt.Sprintf("[ERROR] Packet received when no packet was expected\n"))
	}
	errStr = append(errStr, fmt.Sprintf("Unexpected packet on interface %s:\n\n%v", dev, pkt))
	return -1, fmt.Errorf(strings.Join(errStr, "\n"))
}
*/
// checkPkt compare a given packet against all the possible expected packets,
// It returns the index of the expected packet matched or an error with a pretty-print
// packet dump of the unmatched packet.
func checkPkt(expPkts []*DevPkt, devIdx int, pkt gopacket.Packet) (int, error) {
	var errStr []string
	dev := shared.DevList[devIdx].ContDev
	for i := range expPkts {
		if dev != expPkts[i].Dev {
			continue
		}
		if err := ComparePackets(pkt, expPkts[i].Pkt); err != nil {
			errStr = append(errStr, fmt.Sprintf("[ERROR] %s", err))
			actStr := fmt.Sprintf("%s", pkt)
			expStr := fmt.Sprintf("%s", expPkts[i].Pkt)
			errStr = append(errStr, StringDiffPrettyPrint(actStr, expStr))
			continue
		}
		// Packet matched!
		return i, nil
	}
	if len(expPkts) == 0 {
		errStr = append(errStr,
			fmt.Sprintf("[ERROR] Packet received when no packet was expected\n"))
	}
	errStr = append(errStr, fmt.Sprintf("Unexpected packet on interface %s:\n\n%v", dev, pkt))
	return -1, fmt.Errorf(strings.Join(errStr, "\n"))
}
