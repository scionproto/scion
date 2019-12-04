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
	"encoding/hex"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"github.com/google/gopacket"

	"github.com/scionproto/scion/go/border/braccept/layers"
	"github.com/scionproto/scion/go/border/braccept/shared"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spath"
)

var _ TaggedLayer = (*ScionTaggedLayer)(nil)

type ScionTaggedLayer struct {
	layers.Scion
	tagged
	options
	tags scionTags
}

func ScionParser(lines []string) TaggedLayer {
	// default Scion layer values
	scn := &ScionTaggedLayer{}
	scn.tags = newScionTags()

	//SerializeOptions
	scn.opts.FixLengths = true

	for i := range lines {
		line := lines[i]

		layerType, tag, _ := decodeLayerLine(line)
		switch layerType {
		case "IF":
			scn.newIF(tag)
		case "HF":
			scn.newHF(tag)
		}
	}
	scn.Update(lines)
	return scn
}

func (scn *ScionTaggedLayer) Layer() gopacket.Layer {
	return &scn.Scion
}

func (scn *ScionTaggedLayer) Clone() TaggedLayer {
	clone := *scn
	// copy scion path
	path := scn.Path.Clone()
	clone.Path = *path
	// update cloned tags to point to the cloned info/hop fields in the path
	clone.tags = newScionTags()
	for i := range scn.Path.Segs {
		seg := scn.Path.Segs[i]
		tag := scn.tags.getTag(seg.Inf)
		clone.tags.add(tag, clone.Path.Segs[i].Inf)
		for j := range seg.Hops {
			tag := scn.tags.getTag(seg.Hops[j])
			clone.tags.add(tag, clone.Path.Segs[i].Hops[j])
		}
	}
	return &clone
}

func (scn *ScionTaggedLayer) String() string {
	return gopacket.LayerString(&scn.Scion)
}

func (scn *ScionTaggedLayer) Update(lines []string) {
	if scn == nil {
		panic(fmt.Errorf("Scion Tagged Layer is nil!\n"))
	}
	for i := range lines {
		line := lines[i]

		layerType, tag, kvStr := decodeLayerLine(line)
		kvs := getKeyValueMap(kvStr)
		switch layerType {
		case "SCION":
			scn.tag = tag
			scn.updateCommon(kvs)
		case "ADDR":
			scn.updateAddr(kvs)
		case "IF":
			scn.updateIF(tag, kvs)
		case "HF":
			scn.updateHF(tag, kvs)
		default:
			panic(fmt.Errorf("Unknown SCION sub layer type '%s'\n", layerType))
		}
	}
}

// parseScionProto parses a protocol name or number
func parseScionProto(protoName string) common.L4ProtocolType {
	if p, err := strconv.Atoi(protoName); err == nil {
		// It is a number, use it as protocol
		return common.L4ProtocolType(p)
	}
	switch protoName {
	case "UDP":
		return common.L4UDP
	case "SCMP":
		return common.L4SCMP
	case "HBH":
		return common.HopByHopClass
	}
	panic(fmt.Errorf("Scion NextHeader '%s' not found", protoName))
}

func HostAddrTypeFromString(ht string) addr.HostAddrType {
	switch ht {
	case "IPv4":
		return addr.HostTypeIPv4
	case "IPv6":
		return addr.HostTypeIPv6
	case "SVC":
		return addr.HostTypeSVC
	default:
		return addr.HostAddrType(StrToInt(ht))
	}
}

func (scn *ScionTaggedLayer) updateCommon(kvs propMap) {
	for k, v := range kvs {
		switch k {
		case "Ver":
			scn.CmnHdr.Ver = uint8(StrToInt(v))
		case "DstType":
			scn.CmnHdr.DstType = HostAddrTypeFromString(v)
		case "SrcType":
			scn.CmnHdr.SrcType = HostAddrTypeFromString(v)
		case "TotalLen":
			scn.CmnHdr.TotalLen = uint16(StrToInt(v))
			scn.opts.FixLengths = false
		case "HdrLen":
			scn.CmnHdr.HdrLen = uint8(StrToInt(v))
			scn.opts.FixLengths = false
		case "CurrInfoF":
			scn.CmnHdr.CurrInfoF = uint8(StrToInt(v))
		case "CurrHopF":
			scn.CmnHdr.CurrHopF = uint8(StrToInt(v))
		case "NextHdr":
			scn.CmnHdr.NextHdr = parseScionProto(v)
		default:
			panic(fmt.Errorf("Error parsing common hdr fields '%s'", k))
		}
	}
}

func (scn *ScionTaggedLayer) updateAddr(kvs propMap) {
	var err error
	for k, v := range kvs {
		switch k {
		case "DstIA":
			scn.AddrHdr.DstIA, err = addr.IAFromString(v)
			if err != nil {
				panic(err)
			}
		case "SrcIA":
			scn.AddrHdr.SrcIA, err = addr.IAFromString(v)
			if err != nil {
				panic(err)
			}
		case "Dst":
			var dst addr.HostAddr
			dst = addr.HostSVCFromString(v)
			if dst == addr.SvcNone {
				// Try to parse IP address
				dst = addr.HostFromIPStr(v)
				if dst == nil {
					dst = layers.HostBad(HexToBytes(v))
				}
			}
			scn.AddrHdr.DstHost = dst
		case "Src":
			src := addr.HostFromIPStr(v)
			if src == nil {
				src = layers.HostBad(HexToBytes(v))
			}
			scn.AddrHdr.SrcHost = src
		default:
			panic(fmt.Errorf("Error parsing address hdr fields '%s'", k))
		}
	}
}

func (scn *ScionTaggedLayer) newIF(tag string) {
	seg := &layers.Segment{}
	inf := &spath.InfoField{TsInt: shared.TsNow32}
	seg.Inf = inf
	scn.Path.Segs = append(scn.Path.Segs, seg)
	scn.tags.add(tag, inf)
}

func (scn *ScionTaggedLayer) updateIF(tag string, kvs propMap) {
	inf := scn.tags.get(tag).(*spath.InfoField)
	if inf == nil {
		panic(fmt.Errorf("Invalid IF tag '%s'\n", tag))
	}
	updateFieldsIF(inf, kvs)
}

func updateFieldsIF(inf *spath.InfoField, kvs propMap) {
	for k, v := range kvs {
		switch k {
		case "Flags":
			updateFlagsIF(inf, v)
		case "TsInt":
			// Note that users can still pass a normally formatted timestamp
			// with fmt.Sprintf("%d", timeStamp.Unix()).
			inf.TsInt = uint32(StrToInt(v))
		case "ISD":
			inf.ISD = uint16(StrToInt(v))
		case "Hops":
			inf.Hops = uint8(StrToInt(v))
		default:
			panic(fmt.Errorf("Error parsing IF '%s'", k))
		}
	}
}

func updateFlagsIF(inf *spath.InfoField, flags string) {
	f := strings.Split(flags, ",")
	for i := range f {
		flag := f[i]
		switch flag {
		case "ConsDir":
			inf.ConsDir = true
		case "Shortcut":
			inf.Shortcut = true
		case "Peer":
			inf.Peer = true
		default:
			panic(fmt.Errorf("Error parsing IF flags '%s'", flag))
		}
	}
}

// Add Hop Field to the last segment of the path
// Panic if there is no segment
func (scn *ScionTaggedLayer) newHF(tag string) {
	if len(scn.Path.Segs) == 0 {
		panic(fmt.Errorf("No segment for HF '%s'", tag))
	}
	seg := scn.Path.Segs[len(scn.Path.Segs)-1]
	hf := &spath.HopField{}
	hf.Mac = common.RawBytes{0xc0, 0xff, 0xee}
	seg.Hops = append(seg.Hops, hf)
	scn.tags.add(tag, hf)
}

func (scn *ScionTaggedLayer) updateHF(tag string, kvs propMap) {
	hf := scn.tags.get(tag).(*spath.HopField)
	if hf == nil {
		panic(fmt.Errorf("Invalid HF tag '%s'\n", tag))
	}
	updateFieldsHF(hf, kvs)
}

func updateFieldsHF(hf *spath.HopField, kvs propMap) {
	var err error
	for k, v := range kvs {
		switch k {
		case "Flags":
			updateFlagsHF(hf, v)
		case "ExpTime":
			hf.ExpTime = spath.ExpTimeType(StrToInt(v))
		case "ConsIngress":
			hf.ConsIngress = common.IFIDType(StrToInt(v))
		case "ConsEgress":
			hf.ConsEgress = common.IFIDType(StrToInt(v))
		case "Mac":
			hf.Mac, err = hex.DecodeString(v)
		default:
			panic(fmt.Errorf("Error parsing HF '%s'", k))
		}
		if err != nil {
			panic(err)
		}
	}
}

func updateFlagsHF(hf *spath.HopField, flags string) {
	f := strings.Split(flags, ",")
	for i := range f {
		flag := f[i]
		switch flag {
		case "Xover":
			hf.Xover = true
		case "VerifyOnly":
			hf.VerifyOnly = true
		default:
			panic(fmt.Errorf("Error parsing HF flags '%s'", flag))
		}
	}
}

func (scn *ScionTaggedLayer) GenerateMac(hMac hash.Hash, infTag, hfTag, hfMacTag string) {
	// Retrieve each tagged field
	if hMac == nil {
		panic(fmt.Errorf("GenerateMac: Invalid Mac %v", hMac))
	}
	inf := scn.tags.get(infTag).(*spath.InfoField)
	hf := scn.tags.get(hfTag).(*spath.HopField)
	var hfMac *spath.HopField
	buf := make(common.RawBytes, spath.HopFieldLength)
	if hfMacTag != "" {
		hfMac = scn.tags.get(hfMacTag).(*spath.HopField)
		hfMac.Write(buf)
	}
	hMac.Reset()
	/// CalcMac assumes TsInt in network order
	//hf.Mac = hf.CalcMac(hMac, common.Order.PutUint32(inf.TsInt, buf))
	hf.Mac = hf.CalcMac(hMac, inf.TsInt, buf[1:])
}

// Tags is just a map of tag to SCION fields, used for GenerateMac or field update.
type scionTags map[string]interface{}

func newScionTags() scionTags {
	return make(map[string]interface{})
}

func (tags scionTags) add(tag string, v interface{}) {
	if _, ok := tags[tag]; ok {
		panic(fmt.Errorf("Duplicated tag '%s'", tag))
	}
	tags[tag] = v
}

func (tags scionTags) get(tag string) interface{} {
	if tag == "" {
		panic(fmt.Errorf("Invalid empty tag"))
	}
	v, ok := tags[tag]
	if !ok {
		panic(fmt.Errorf("Tag '%s' does not exists", tag))
	}
	return v
}

func (tags scionTags) getTag(v interface{}) string {
	matchedTags := []string{}
	for tag, val := range tags {
		if val == v {
			matchedTags = append(matchedTags, tag)
		}
	}
	if len(matchedTags) == 0 {
		panic(fmt.Errorf("No tag for layer '%v'", v))
	}
	if len(matchedTags) > 1 {
		panic(fmt.Errorf("Invalid! multiple tags found for layer '%v'", v))
	}
	return matchedTags[0]
}
