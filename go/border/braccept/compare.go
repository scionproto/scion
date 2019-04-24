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
	"time"

	"github.com/google/gopacket"
	golayers "github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/border/braccept/layers"
	"github.com/scionproto/scion/go/border/braccept/shared"
	"github.com/scionproto/scion/go/lib/infra"
)

func compareLayersHex(act, exp gopacket.Layer) {
	var actStr, expStr string
	if act.LayerPayload() != nil {
		actStr = fmt.Sprintf("%s %x%x", act.LayerType(), act.LayerContents(), act.LayerPayload())
	} else {
		actStr = fmt.Sprintf("%s %x", act.LayerType(), act.LayerContents())
	}
	if exp.LayerPayload() != nil {
		expStr = fmt.Sprintf("%s %x%x", exp.LayerType(), exp.LayerContents(), exp.LayerPayload())
	} else {
		expStr = fmt.Sprintf("%s %x", exp.LayerType(), exp.LayerContents())
	}
	fmt.Printf("[CompareLayersHex]\n%v\n", compareStrings(actStr, expStr))
}

func ComparePackets(act, exp gopacket.Packet) error {
	var err error
	layersAct := act.Layers()
	layersExp := exp.Layers()
	for i := range layersAct {
		switch l := layersAct[i].(type) {
		case *golayers.IPv4:
			err = compareLayersIP4(l, layersExp[i])
		case *golayers.UDP:
			err = compareLayersUDP(l, layersExp[i])
		case *layers.SCMP:
			err = compareLayersSCMP(l, layersExp[i])
		case *gopacket.Payload:
			err = compareLayersPayload(l, layersExp[i])
		default:
			err = compareLayers(l, layersExp[i])
		}
		if err != nil {
			return fmt.Errorf("Layer Mismatch!:\n%s", err)
		}
	}
	return nil
}

func compareLayersIP4(act, exp gopacket.Layer) error {
	actIP4 := act.(*golayers.IPv4)
	expIP4, ok := exp.(*golayers.IPv4)
	if ok {
		if expIP4.Id == 0 {
			// XXX if the expected packet IPv4 ID field is 0, it is ignored.
			// This is useful for packets that are generated in the BR and contain unpredictable
			// data, ie. IPv4 ID
			actIP4.Id = 0
		}
		if expIP4.Checksum == 0 {
			// XXX if the expected packet IPv4 checksum field is 0, it is ignored.
			// This is useful for packets that are generated in the BR and contain unpredictable
			// data, ie. IPv4 ID, thus also IPv4 checksum.
			actIP4.Checksum = 0
		}
	}
	return compareLayers(act, exp)
}

func compareLayersUDP(act, exp gopacket.Layer) error {
	actUDP := act.(*golayers.UDP)
	expUDP, ok := exp.(*golayers.UDP)
	if ok && expUDP.Checksum == 0 {
		// XXX if the expected packet checksum is 0, it is ignored.
		// This is useful for packets that are generated in the BR and contain unpredictable
		// data, ie. Timestamp.
		actUDP.Checksum = 0
	}
	return compareLayers(act, exp)
}

func compareLayersSCMP(act, exp gopacket.Layer) error {
	actSCMP := act.(*layers.SCMP)
	expSCMP, ok := exp.(*layers.SCMP)
	if ok {
		if expSCMP.Timestamp == 0 {
			// The timestamp of the expected packet was not specified, likely because it is not
			// know at the time of the test definition, ie. the BR generates this packet.
			actTS := actSCMP.Time()
			now := time.Now()
			// Allow up to 250ms time drift
			min := now.Add(-250 * time.Millisecond)
			if actTS.Before(now) && actTS.After(min) {
				expSCMP.Timestamp = actSCMP.Timestamp
			}
		}
		if expSCMP.Checksum[0] == 0 && expSCMP.Checksum[1] == 0 {
			// The checksum of the expected packet is 0, ignored it.
			// This is useful for packets that are generated in the BR and contain unpredictable
			// data, ie. Timestamp.
			actSCMP.Checksum[0] = 0
			actSCMP.Checksum[1] = 0
		}
	}
	return compareLayers(act, exp)
}

func compareLayersPayload(act, exp gopacket.Layer) error {
	// Try capnp decap first, otherwise do normal string comparison
	actU, actErr := shared.CtrlCapnpDec(infra.NullSigVerifier, act.LayerContents())
	expU, expErr := shared.CtrlCapnpDec(infra.NullSigVerifier, exp.LayerContents())
	if actErr == nil && expErr == nil {
		// Both are capnp, compare then
		actStr := actU.String()
		expStr := expU.String()
		return compareStrings(actStr, expStr)
	}
	return compareLayers(act, exp)
}

func compareLayers(act, exp gopacket.Layer) error {
	actStr := gopacket.LayerString(act)
	expStr := gopacket.LayerString(exp)
	return compareStrings(actStr, expStr)
}

func compareStrings(act, exp string) error {
	if act == exp {
		return nil
	}
	return fmt.Errorf(StringDiffPrettyPrint(act, exp))
}
