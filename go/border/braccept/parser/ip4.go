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
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var _ TaggedLayer = (*IP4TaggedLayer)(nil)

type IP4TaggedLayer struct {
	layers.IPv4
	tagged
	options
}

func IP4Parser(lines []string) TaggedLayer {
	// default IP4 layer values
	ip := &IP4TaggedLayer{}
	ip.Version = 4
	ip.IHL = 5
	ip.TTL = 64

	//SerializeOptions
	ip.opts.ComputeChecksums = true
	ip.opts.FixLengths = true

	ip.Update(lines)
	return ip
}

func (ip *IP4TaggedLayer) Layer() gopacket.Layer {
	return &ip.IPv4
}

func (ip *IP4TaggedLayer) Clone() TaggedLayer {
	clone := *ip
	return &clone
}

func (ip *IP4TaggedLayer) String() string {
	return gopacket.LayerString(&ip.IPv4)
}

func (ip *IP4TaggedLayer) Update(lines []string) {
	if ip == nil {
		panic(fmt.Errorf("IP4 Tagged Layer is nil!\n"))
	}
	if len(lines) != 1 {
		panic(fmt.Errorf("Bad IP4 layer!\n%s\n", lines))
	}
	line := lines[0]
	_, tag, kvStr := decodeLayerLine(line)
	ip.tag = tag

	kvs := getKeyValueMap(kvStr)
	ip.updateFields(kvs)
}

func (ip *IP4TaggedLayer) updateFields(kvs propMap) {
	for k, v := range kvs {
		switch k {
		case "Version":
			ip.Version = uint8(StrToInt(v))
		case "IHL":
			ip.IHL = uint8(StrToInt(v))
		case "Length":
			ip.Length = uint16(StrToInt(v))
			ip.opts.FixLengths = false
		case "Id":
			ip.Id = uint16(StrToInt(v))
		case "Flags":
			ip.updateFlags(v)
		case "TTL":
			ip.TTL = uint8(StrToInt(v))
		case "Checksum":
			ip.Checksum = uint16(HexToInt(v))
			ip.opts.ComputeChecksums = false
		case "NextHdr":
			var ip4Meta []layers.EnumMetadata
			ip4Meta = layers.IPProtocolMetadata[:]
			ip.Protocol = layers.IPProtocol(ParseProto(ip4Meta, v))
		case "Src":
			ip.SrcIP = net.ParseIP(v)
		case "Dst":
			ip.DstIP = net.ParseIP(v)
		case "TOS":
			fallthrough
		case "FragOffset":
			panic(fmt.Errorf("Unsupported IP4 field: %s", k))
		default:
			panic(fmt.Errorf("Unknown IP4 field: %s", k))
		}
	}
}

func (ip *IP4TaggedLayer) updateFlags(flags string) {
	f := strings.Split(flags, ",")
	for i := range f {
		flag := f[i]
		switch flag {
		case "DF":
			ip.Flags |= layers.IPv4DontFragment
		default:
			panic(fmt.Errorf("Error parsing IPv4 flags '%s'", flag))
		}
	}
}
