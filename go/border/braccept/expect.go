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
	// Serialize all expected packets so that we generate proper length values, checksums, etc.
	expPkts := toGoPackets(pkts...)
	var errStr []string
	for {
		idx, pktV, ok := reflect.Select(cases)
		if !ok {
			panic(fmt.Errorf("Unexpected interface %s/%s closed",
				shared.DevList[idx].Host.Name, shared.DevList[idx].ContDev))
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
