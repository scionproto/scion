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

package parser

import (
	"fmt"

	"github.com/google/gopacket"
	golayers "github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/border/braccept/layers"
)

var _ TaggedLayer = (*UDPTaggedLayer)(nil)

type UDPTaggedLayer struct {
	layers.UDP
	tagged
	options
}

func UDPParser(lines []string) TaggedLayer {
	// default UDP layer values
	udp := &UDPTaggedLayer{}

	//SerializeOptions
	udp.opts.ComputeChecksums = true
	udp.opts.FixLengths = true

	udp.Update(lines)
	return udp
}

func (udp *UDPTaggedLayer) Layer() gopacket.Layer {
	return &udp.UDP
}

func (udp *UDPTaggedLayer) Clone() TaggedLayer {
	clone := *udp
	return &clone
}

func (udp *UDPTaggedLayer) String() string {
	return gopacket.LayerString(&udp.UDP)
}

func (udp *UDPTaggedLayer) Update(lines []string) {
	if udp == nil {
		panic(fmt.Errorf("UDP Tagged Layer is nil!\n"))
	}
	if len(lines) != 1 {
		panic(fmt.Errorf("Bad UDP layer!\n%s\n", lines))
	}
	line := lines[0]
	_, tag, kvStr := decodeLayerLine(line)
	udp.tag = tag

	kvs := getKeyValueMap(kvStr)
	udp.updateFields(kvs)
}

func (udp *UDPTaggedLayer) updateFields(kvs propMap) {
	for k, v := range kvs {
		switch k {
		case "Src":
			udp.SrcPort = golayers.UDPPort(StrToInt(v))
		case "Dst":
			udp.DstPort = golayers.UDPPort(StrToInt(v))
		case "Length":
			udp.Length = uint16(StrToInt(v))
			udp.opts.FixLengths = false
		case "Checksum":
			udp.Checksum = uint16(StrToInt(v))
			udp.opts.ComputeChecksums = false
		default:
			panic(fmt.Errorf("Unknown UDP field: %s", k))
		}
	}
}
