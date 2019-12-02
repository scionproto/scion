// Copyright 2019 ETH Zurich, Anapaya Systems
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

var _ TaggedLayer = (*HBHTaggedLayer)(nil)
var _ gopacket.Layer = (*HBHTaggedLayer)(nil)

type HBHTaggedLayer struct {
	layers.Extension
	tagged
	options
}

func HBHParser(lines []string) TaggedLayer {
	// default HBH layer values
	hbh := &HBHTaggedLayer{}

	//SerializeOptions
	hbh.opts.FixLengths = true

	hbh.Update(lines)
	return hbh
}

func (hbh *HBHTaggedLayer) Layer() gopacket.Layer {
	return hbh
}

func (hbh *HBHTaggedLayer) Clone() TaggedLayer {
	clone := *hbh
	return &clone
}

// XXX layers.Extension is missing following method to implement gopacket.Layer
func (hbh *HBHTaggedLayer) LayerType() gopacket.LayerType {
	return layers.LayerTypeHopByHopExtension
}

/*
func (hbh *HBHTaggedLayer) String() string {
	return gopacket.LayerString(hbh)
}
*/

func (hbh *HBHTaggedLayer) String() string {
	e, err := layers.NewExtnSCMPFromLayer(&hbh.Extension)
	if err != nil {
		return fmt.Sprintf("NextHeader=%s NumLines=%d Type=%s Data=%x", hbh.NextHeader,
			hbh.NumLines, common.ExtnType{Class: common.HopByHopClass, Type: hbh.Type}, hbh.Data)
	}
	return fmt.Sprintf("NextHeader=%s NumLines=%d { %s }", hbh.NextHeader, hbh.NumLines, e)
}

func (hbh *HBHTaggedLayer) Update(lines []string) {
	if hbh == nil {
		panic(fmt.Errorf("HBH Tagged Layer is nil!\n"))
	}
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
	case "HBH.Empty":
		hbh.Data = []byte{}
		return
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
		panic(fmt.Errorf("Unknown HBH_OHP fields: %v", kvs))
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
	case "InvHBH":
		e = common.ExtnType{Class: common.HopByHopClass, Type: 255}
	default:
		panic(fmt.Errorf("Unknown HBH Type: %s", t))
	}
	return e.Type
}
