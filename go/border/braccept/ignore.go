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
	"github.com/scionproto/scion/go/border/braccept/parser"
	"github.com/scionproto/scion/go/border/braccept/shared"
)

var IgnoredPkts []*DevPkt

func IgnoredPackets(dtls ...*DevTaggedLayers) {
	// XXX workaround until we use fixed MAC addresses in the containers
	for i := range dtls {
		dtl := dtls[i]
		e := dtl.TaggedLayers[0].(*parser.EthernetTaggedLayer)
		e.SrcMAC = shared.DevByName[dtl.Dev].Mac
	}
	pkts := toGoPackets(dtls...)
	IgnoredPkts = append(IgnoredPkts, pkts...)
}

func ClearIgnoredPackets() {
	IgnoredPkts = IgnoredPkts[:0]
}
