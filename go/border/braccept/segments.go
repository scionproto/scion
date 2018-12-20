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

func segment(input string, hashMac hash.Hash, hopIdxs ...int) *tpkt.Segment {
	str := regexp.MustCompile(` +`).ReplaceAllString(input, " ")
	fields := regexp.MustCompile(` `).Split(str, -1)
	infoF, err := decodeInfoF(fields[0])
	if err != nil {
		panic(fmt.Sprintf("%s\n%s", str, err))
	}
	var hops []*spath.HopField
	for _, hf := range fields[1:] {
		hop, err := decodeHopF(hf)
		if err != nil {
			panic(fmt.Sprintf("%s\n%s", str, err))
		}
		hops = append(hops, hop)
	}
	infoF.Hops = uint8(len(hops))
	if len(hopIdxs) > 0 {
		return tpkt.NewSegment(infoF, hops).Macs(hashMac, hopIdxs...)
	}
	return tpkt.NewSegment(infoF, hops)
}

func decodeHopF(str string) (*spath.HopField, error) {
	// Validate InfoField flags syntax
	match, _ := regexp.MatchString(`^((X|V|XV)\.)?(0|[1-9]{3,3})\.(0|[1-9]{3,3})$`, str)
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
		Xover:       str[0] == 'X',
		VerifyOnly:  str[0] == 'V' || str[1] == 'V',
		ConsIngress: common.IFIDType(ingress),
		ConsEgress:  common.IFIDType(egress),
	}, nil
}

func decodeInfoF(str string) (*spath.InfoField, error) {
	// Validate InfoField flags syntax
	match, _ := regexp.MatchString("^[C_][S_][P_]$", str)
	if !match {
		return nil, fmt.Errorf("Bad Info Field flags syntax: %s", str)
	}
	// Decode and build Info Field
	return &spath.InfoField{
		ConsDir:  str[0] == 'C',
		Shortcut: str[1] == 'S',
		Peer:     str[2] == 'P',
		TsInt:    tsNow,
		ISD:      1,
	}, nil
}
