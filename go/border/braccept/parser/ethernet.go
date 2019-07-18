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
	"net"

	"github.com/google/gopacket"
	golayers "github.com/google/gopacket/layers"
)

// Ethernet packet parser
var _ TaggedLayer = (*EthernetTaggedLayer)(nil)

type EthernetTaggedLayer struct {
	golayers.Ethernet
	tagged
	options
}

func EthernetParser(lines []string) TaggedLayer {
	// default Ethernet layer values
	ether := &EthernetTaggedLayer{}

	//SerializeOptions
	ether.opts.ComputeChecksums = true
	ether.opts.FixLengths = true

	ether.Update(lines)
	return ether
}

func (ether *EthernetTaggedLayer) Layer() gopacket.Layer {
	return &ether.Ethernet
}

func (ether *EthernetTaggedLayer) Clone() TaggedLayer {
	clone := *ether
	return &clone
}

func (ether *EthernetTaggedLayer) String() string {
	return gopacket.LayerString(&ether.Ethernet)
}

func (ether *EthernetTaggedLayer) Update(lines []string) {
	if ether == nil {
		panic(fmt.Errorf("Ethernet Tagged Layer is nil!\n"))
	}
	if len(lines) != 1 {
		panic(fmt.Errorf("Bad Ethernet layer!\n%s\n", lines))
	}
	line := lines[0]
	_, tag, kvStr := decodeLayerLine(line)
	ether.tag = tag

	kvs := getKeyValueMap(kvStr)
	ether.updateFields(kvs)
}

func (ether *EthernetTaggedLayer) updateFields(kvs propMap) {
	var err error
	for k, v := range kvs {
		switch k {
		case "SrcMAC":
			ether.SrcMAC, err = net.ParseMAC(v)
		case "DstMAC":
			ether.DstMAC, err = net.ParseMAC(v)
		case "EthernetType":
			var etherMeta []golayers.EnumMetadata
			etherMeta = golayers.EthernetTypeMetadata[:]
			ether.EthernetType = golayers.EthernetType(ParseProto(etherMeta, v))
		default:
			panic(fmt.Errorf("Unknown Ethernet field: %s", k))
		}
		if err != nil {
			panic(err)
		}
	}
}
