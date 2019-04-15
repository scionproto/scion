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

// This package is responsible for parsing a packet description, more specifically,
// an ordered list of layers definitions.
//
// In its basic form, each layers is defined by a text line following the following sytnax:
//    TAG: prop1=val1 prop2=val2
//
// where TAG serves two functions:
// 1. It specifies the type of layer.
// 2. It uniquely names a layer.
//
// As an example:
//    IP4: Src=192.168.12.3 Dst=192.168.12.2 NextHdr=UDP
//    UDP_1: Src=40000 Dst=50000 Checksum=0
//
// The above example defines a packet with two layers, IP4 and UDP,
// with tags IP4 and UDP_1 respectively.
// Tags are useful to refer to specific layers in a packet.
//
// The parse is indentation aware, meaning that all layers need to have the same tab indentation
// as the first layer.
//
// It is also possible to define a layer which consists of multiple lines:
//    IP4: Src=192.168.12.3 Dst=192.168.12.2 NextHdr=UDP
//    UDP: Src=40000 Dst=50000 Checksum=0
//    SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=5 SrcType=IPv4 DstType=SVC
//        ADDR: SrcIA=1-ff00:0:2 Src=172.16.2.1 DstIA=1-ff00:0:1 Dst=192.168.0.51
//        IF_1: ISD=1 Hops=3 Flags=Peer
//            HF_1: ConsIngress=261 ConsEgress=0   Flags=Xover
//            HF_2: ConsIngress=211 ConsEgress=151 Flags=Xover
//            HF_3: ConsIngress=0   ConsEgress=621
//    UDP: Src=1111 Dst=2222
//
// From the parsing point of view, everyline with deeper indentation than the layer itself belong
// to the layer, so in the example above, the SCION layer would consist of:
//    SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=5 SrcType=IPv4 DstType=SVC
//        ADDR: SrcIA=1-ff00:0:2 Src=172.16.2.1 DstIA=1-ff00:0:1 Dst=192.168.0.51
//        IF_1: ISD=1 Hops=3 Flags=Peer
//            HF_1: ConsIngress=261 ConsEgress=0   Flags=Xover
//            HF_2: ConsIngress=211 ConsEgress=151 Flags=Xover
//            HF_3: ConsIngress=0   ConsEgress=621
package parser

import (
	"bufio"
	"fmt"
	"hash"
	"regexp"
	"strings"

	"github.com/google/gopacket"
	golayers "github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/border/braccept/layers"
	"github.com/scionproto/scion/go/lib/common"
)

type TaggedLayer interface {
	gopacket.SerializableLayer
	SerializeOptions() gopacket.SerializeOptions
	Tag() string
	Layer() gopacket.Layer
	Clone() TaggedLayer
	Update([]string)
}

type LayerParser func(lines []string) TaggedLayer

var parserMap = map[string]LayerParser{
	"Ethernet":      EthernetParser,
	"IP4":           IP4Parser,
	"UDP":           UDPParser,
	"SCION":         ScionParser,
	"HBH":           HBHParser,
	"SCMP":          SCMPParser,
	"IFStateReq":    IFStateReqParser,
	"IFStateInfo":   IFStateInfoParser,
	"SignedRevInfo": SignedRevInfoParser,
}

type TaggedLayers []TaggedLayer

func (taggedLayers TaggedLayers) CloneAndUpdate(packetString string) TaggedLayers {
	// Clone all tagged layers
	tls := make(TaggedLayers, len(taggedLayers))
	for i := range taggedLayers {
		tls[i] = taggedLayers[i].Clone()
	}
	// Update specific layers
	tls.Update(packetString)
	//fmt.Printf("Updated Packet:\n%s\n", tls)
	return tls
}

func (taggedLayers TaggedLayers) Update(packetString string) {
	pktDef := removeEmptyLines(packetString)
	scanner := bufio.NewScanner(strings.NewReader(pktDef))
	// indent of first layer dictates minimum indent for all layers
	scanner.Scan()
	minIndent := getIndent(scanner.Text())
	for {
		lines := getHeaderLines(scanner, minIndent)
		// No more lines to scan
		if len(lines) == 0 {
			break
		}
		// decode the layer, the first line contains the layer type
		_, layerTag, _ := decodeLayerLine(lines[0])
		taggedLayer := taggedLayers.GetTaggedLayer(layerTag)
		if taggedLayer == nil {
			panic(fmt.Errorf("TaggedLayer not found: %s\n", layerTag))
		}
		taggedLayer.Update(lines)
		//fmt.Printf("Update: %s\n", gopacket.LayerString(taggedLayer.Layer()))
	}
}

func (taggedLayers TaggedLayers) Serialize() common.RawBytes {
	buf := gopacket.NewSerializeBuffer()
	if err := SerializeLayers(buf, taggedLayers...); err != nil {
		panic(err)
	}
	return common.RawBytes(buf.Bytes())
}

func (taggedLayers TaggedLayers) GetTaggedLayer(tag string) TaggedLayer {
	for i := range taggedLayers {
		tl := taggedLayers[i]
		if tl.Tag() == tag {
			return tl
		}
	}
	return nil
}

func (taggedLayers TaggedLayers) SetChecksum(l4Tag, l3Tag string) {
	tl := taggedLayers.GetTaggedLayer(l3Tag)
	var nl gopacket.NetworkLayer
	switch l := tl.Layer().(type) {
	case *golayers.IPv4:
		nl = l
	case *layers.Scion:
		nl = l
	default:
		panic(fmt.Errorf("SetChecksum: Invalid L3 network layer '%s'\n", l3Tag))
	}

	tl = taggedLayers.GetTaggedLayer(l4Tag)
	switch l := tl.Layer().(type) {
	case *layers.UDP:
		if err := l.SetNetworkLayerForChecksum(nl); err != nil {
			panic(err)
		}
	case *layers.SCMP:
		if err := l.SetNetworkLayerForChecksum(nl); err != nil {
			panic(err)
		}
	default:
		panic(fmt.Errorf("SetChecksum: Invalid L4 network layer '%s'\n", l4Tag))
	}
}

func (taggedLayers TaggedLayers) GenerateMac(scnTag string, hMac hash.Hash,
	infTag, hfTag, hfMacTag string) {

	tl := taggedLayers.GetTaggedLayer(scnTag)
	scn, ok := tl.(*ScionTaggedLayer)
	if !ok {
		panic(fmt.Errorf("GenerateMac: Invalid tag '%s'\n", scnTag))
	}
	scn.GenerateMac(hMac, infTag, hfTag, hfMacTag)
}

func (taggedLayers TaggedLayers) String() string {
	var str []string
	for _, tl := range taggedLayers {
		str = append(str, fmt.Sprintf("%s", tl))
	}
	return strings.Join(str, "\n")
}

// SerializeLayers serializes all gopacket.Layers to Bytes.
// We implement our own SerializeLayers (gopacket provides one) to allow for custom
// SerializeOptions per layer
func SerializeLayers(w gopacket.SerializeBuffer, layers ...TaggedLayer) error {
	w.Clear()
	for i := len(layers) - 1; i >= 0; i-- {
		layer := layers[i]
		err := layer.SerializeTo(w, layer.SerializeOptions())
		if err != nil {
			return err
		}
		w.PushLayer(layer.LayerType())
	}
	return nil
}

func ParsePacket(packetString string) TaggedLayers {
	pktDef := removeEmptyLines(packetString)
	scanner := bufio.NewScanner(strings.NewReader(pktDef))
	var tls []TaggedLayer
	// indent of first layer dictates minimum indent for all layers
	scanner.Scan()
	minIndent := getIndent(scanner.Text())
	for {
		lines := getHeaderLines(scanner, minIndent)
		// No more lines to scan
		if len(lines) == 0 {
			break
		}
		// decode the layer, the first line contains the layer type
		layerType, _, _ := decodeLayerLine(lines[0])
		layerParser, ok := parserMap[layerType]
		if !ok {
			panic(fmt.Errorf("Unsupported Layer Type: %s\n", layerType))
		}
		taggedLayer := layerParser(lines)
		//fmt.Printf("%s\n", gopacket.LayerString(taggedLayer.Layer()))
		tls = append(tls, taggedLayer)
	}
	//fmt.Printf("ParsePacket:\n%s\n", tls)
	return tls
}

// decodeLayerLine splits a layer line follwing required syntax into its different components.
func decodeLayerLine(line string) (string, string, string) {
	// For the following tagged layer syntax:
	//  IP4_0: ...
	// the type is IP4, the tag is IP4_0, which should be unique for a packet
	matches := regexp.MustCompile(`^\t*([a-zA-Z0-9.]+)(_[0-9]+)?:(.*)$`).FindStringSubmatch(line)
	if matches == nil {
		panic(fmt.Sprintf("Bad Test syntax: %s", line))
	}
	// return type, tag and key/value pairs
	return matches[1], matches[1] + matches[2], matches[3]
}

// scan all the lines with more indentation than current line,
// as they belong to the same layer
// example:
//  A: a b
//          S1: s t
//      S2: p o
//  B: w q
//
// After grouping them we would have a the following set of lines for A:
//   A: a b
//          S1: s t
//      S2: p o
//
// B has the same indentation so it counts as a different layer
//
func getHeaderLines(scanner *bufio.Scanner, minIndent int) []string {
	l := scanner.Text()
	// We have already deleted empty start/end lines so this means it is the end of the file
	if l == "" {
		return nil
	}
	validateLine(l, minIndent)
	indent := getIndent(l)

	lines := []string{l}
	for scanner.Scan() {
		l = scanner.Text()
		validateLine(l, minIndent)

		// if the lines is on the same indentation or lower, it belongs to a different layer
		if getIndent(l) <= indent {
			break
		}
		lines = append(lines, l)
	}
	return lines
}

func validateLine(line string, minIndent int) {
	// check only tabs are used for indentation
	white_space := regexp.MustCompile(`^\s*`).FindString(line)
	tabs := regexp.MustCompile(`^\t*`).FindString(line)
	if white_space != tabs {
		panic(fmt.Errorf("Bad indentation! only tabs allowed:\n%s\n", line))
	}
	// check line is not just white space
	if regexp.MustCompile(`^\s*$`).FindString(line) != "" {
		panic(fmt.Errorf("Empty lines not allowed:\n"))
	}
	indent := getIndent(line)
	// check for required minimum indentation
	if indent < minIndent {
		panic(fmt.Errorf("Bad indentation! expected at least %d tabs:\n%s\n", minIndent, line))
	}
}

func removeEmptyLines(packetString string) string {
	// remove empty lines at the start
	packetString = regexp.MustCompile(`(?m)\A\s*[\r\n]+`).ReplaceAllString(packetString, "")
	// remove empty lines at the end
	return regexp.MustCompile(`(?m)[\r\n]+\s*\z`).ReplaceAllString(packetString, "")
}

func getIndent(line string) int {
	return len(regexp.MustCompile(`^\t*`).FindString(line))
}
