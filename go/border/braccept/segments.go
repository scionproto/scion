// Copyright 2018 ETH Zurich
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
	"hash"
	"regexp"
	"strconv"

	"github.com/scionproto/scion/go/border/braccept/tpkt"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spath"
)

// segment parses a string that defines a SCION path segment.
// The info field should always be the first in the segment, then as many hop fields as needed.
// The info fields syntax matches the following regex:
//   ^\([C_][S_][P_]\) with C (ConsDir), S (Shortcut), P (Peer)
// The hop fields syntax matches the following regex:
//   \[([X_][V_]\.)?(0|[0-9]{3})\.(0|[0-9]{3})\] with X (Xover), V (VerifyOnly),
// and the interfaces are either 0 or a 3 digit int.
// Examples:
//   (_S_)[211.0][X_.151.121][_V.511.0]
//   (C__)[X_.0.141][411.0]
func segment(input string, hashMac hash.Hash, hopIdxs ...int) *tpkt.Segment {
	infoStr := regexp.MustCompile(`^\(...\)`).FindString(input)
	if infoStr == "" {
		panic(fmt.Sprintf("Bad segment syntax: %s", input))
	}
	infoF, err := decodeInfoF(infoStr)
	if err != nil {
		panic(fmt.Sprintf("%s\n%s", infoStr, err))
	}
	var hops []*spath.HopField
	fields := regexp.MustCompile(`\[.*?\]`).FindAllString(input, -1)
	for _, hf := range fields {
		hop, err := decodeHopF(hf)
		if err != nil {
			panic(fmt.Sprintf("%s\n%s", input, err))
		}
		hops = append(hops, hop)
	}
	infoF.Hops = uint8(len(hops))
	if len(hopIdxs) > 0 {
		return tpkt.NewSegment(infoF, hops).Macs(hashMac, hopIdxs...)
	}
	return tpkt.NewSegment(infoF, hops)
}

func decodeInfoF(str string) (*spath.InfoField, error) {
	// Validate InfoField flags syntax
	match, _ := regexp.MatchString(`^\([C_][S_][P_]\)$`, str)
	if !match {
		return nil, fmt.Errorf("Bad Info Field flags syntax: %s", str)
	}
	// Decode and build Info Field
	return &spath.InfoField{
		ConsDir:  str[1] == 'C',
		Shortcut: str[2] == 'S',
		Peer:     str[3] == 'P',
		TsInt:    tsNow32,
		ISD:      1,
	}, nil
}

func decodeHopF(str string) (*spath.HopField, error) {
	// Validate InfoField flags syntax
	match, _ := regexp.MatchString(`^\[([X_][V_]\.)?(0|[0-9]{3})\.(0|[0-9]{3})\]$`, str)
	if !match {
		return nil, fmt.Errorf("Bad Hop Field syntax: %s", str)
	}
	r, _ := regexp.Compile(`0|[1-9]{3,3}`)
	ifids := r.FindAllString(str, 2)
	ingress, err := strconv.ParseUint(ifids[0], 10, 64)
	if err != nil {
		return nil, err
	}
	egress, err := strconv.ParseUint(ifids[1], 10, 64)
	if err != nil {
		return nil, err
	}
	return &spath.HopField{
		Xover:       str[1] == 'X',
		VerifyOnly:  str[1] == 'V' || str[2] == 'V',
		ConsIngress: common.IFIDType(ingress),
		ConsEgress:  common.IFIDType(egress),
	}, nil
}
