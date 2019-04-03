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
	"strings"

	"github.com/google/gopacket"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/layers"
)

// HBH packet parser
var _ LayerParser = (*HBHTaggedLayer)(nil)
var _ TaggedLayer = (*HBHTaggedLayer)(nil)

var _ gopacket.Layer = (*HBHTaggedLayer)(nil)

var HBHParser *HBHTaggedLayer

type HBHTaggedLayer struct {
	layers.Extension
	ext common.Extension
	tagged
	options
}

// XXX layers.Extension is missing following method to implement gopacket.Layer
func (hbh *HBHTaggedLayer) LayerType() gopacket.LayerType {
	return layers.LayerTypeHopByHopExtension
}

func (hbh *HBHTaggedLayer) Layer() gopacket.Layer {
	return hbh
}

func (hbh *HBHTaggedLayer) Clone() TaggedLayer {
	clone := *hbh
	return &clone
}

func (hbh *HBHTaggedLayer) String() string {
	return gopacket.LayerString(hbh)
}

func (_hbh *HBHTaggedLayer) ParseLayer(lines []string) TaggedLayer {
	if _hbh != nil {
		panic(fmt.Errorf("ParseLayer needs to be called on a type nil!\n"))
	}
	// default HBH layer values
	hbh := &HBHTaggedLayer{}

	//SerializeOptions
	hbh.opts.FixLengths = true

	hbh.parse(lines)
	return hbh
}

func (hbh *HBHTaggedLayer) Update(lines []string) {
	if hbh == nil {
		panic(fmt.Errorf("HBH Tagged Layer is nil!\n"))
	}
	hbh.parse(lines)
}

func (hbh *HBHTaggedLayer) parse(lines []string) {
	if len(lines) != 2 {
		panic(fmt.Errorf("Bad HBH layer!\n%s\n", strings.Join(lines, "\n")))
	}
	line := lines[0]
	_, tag, kvStr := decodeLayerLine(line)
	hbh.tag = tag
	kvs := getKeyValueMap(kvStr)
	hbh.updateFields(kvs)

	layerType, _, kvStr := decodeLayerLine(lines[1])
	kvs = getKeyValueMap(kvStr)
	var e common.Extension
	switch layerType {
	case "HBH.OHP":
		ohp := &hbh_ohp{}
		ohp.updateFields(kvs)
		e = ohp
	case "HBH.SCMP":
		scmp := &hbh_scmp{}
		scmp.updateFields(kvs)
		e = scmp
	default:
		panic(fmt.Errorf("Unknown HBH layer Type '%s'", layerType))
	}
	var err error
	hbh.Data, err = e.Pack()
	if err != nil {
		panic(err)
	}
}

func (hbh *HBHTaggedLayer) updateFields(kvs propMap) {
	for k, v := range kvs {
		switch k {
		case "NextHdr":
			hbh.NextHeader = parseScionProto(v)
		case "Length":
			hbh.NumLines = uint8(StrToInt(v))
			hbh.opts.FixLengths = false
		case "Type":
			hbh.Type = parseHBHType(v)
		default:
			panic(fmt.Errorf("Unknown HBH field: %s", k))
		}
	}
}

type hbh_ohp struct {
	layers.ExtnOHP
}

func (ohp *hbh_ohp) updateFields(kvs propMap) {
	if kvs != nil {
		panic(fmt.Errorf("Unknown HBH_SCMP fields: %v", kvs))
	}
}

type hbh_scmp struct {
	layers.ExtnSCMP
}

func (scmp *hbh_scmp) updateFields(kvs propMap) {
	for k, v := range kvs {
		switch k {
		case "Flags":
			scmp.updateFlags(v)
		default:
			panic(fmt.Errorf("Unknown HBH_SCMP field: %s", k))
		}
	}
}

func (scmp *hbh_scmp) updateFlags(flags string) {
	f := strings.Split(flags, ",")
	for i := range f {
		flag := f[i]
		switch flag {
		case "Error":
			scmp.Error = true
		case "HBH":
			scmp.HopByHop = true
		default:
			panic(fmt.Errorf("Error parsing IPv4 flags '%s'", flag))
		}
	}
}

func parseHBHType(t string) uint8 {
	var e common.ExtnType
	switch t {
	case "SCMP":
		e = common.ExtnSCMPType
	case "OHP":
		e = common.ExtnOneHopPathType
	case "SIBRA":
		panic(fmt.Errorf("Unsupported HBH Type: %s", t))
	default:
		panic(fmt.Errorf("Unknown HBH Type: %s", t))
	}
	return e.Type
}
