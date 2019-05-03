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

	"github.com/scionproto/scion/go/border/braccept/shared"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
)

var _ TaggedLayer = (*IFStateReqTaggedLayer)(nil)

type IFStateReqTaggedLayer struct {
	gopacket.Payload
	path_mgmt.IFStateReq
	tagged
	options
}

// IFStateReqParser parses an Interface State Request with the following syntax:
//
// IFStateReq: IfID=121
//
func IFStateReqParser(lines []string) TaggedLayer {
	// default IFStateReq layer values
	i := &IFStateReqTaggedLayer{}

	i.Update(lines)
	return i
}

func (p *IFStateReqTaggedLayer) Layer() gopacket.Layer {
	return &p.Payload
}

func (i *IFStateReqTaggedLayer) Clone() TaggedLayer {
	clone := *i
	return &clone
}

func (i *IFStateReqTaggedLayer) Update(lines []string) {
	if i == nil {
		panic(fmt.Errorf("IFStateReq Tagged Layer is nil!\n"))
	}
	// IFStateReq is either single line, or two lines with second being the revocation
	if len(lines) != 1 {
		panic(fmt.Errorf("Bad IFStateReq layer!\n%s\n", lines))
	}
	_, tag, kvStr := decodeLayerLine(lines[0])
	i.tag = tag

	kvs := getKeyValueMap(kvStr)
	i.updateFields(kvs)
	pmpld, err := path_mgmt.NewPld(&i.IFStateReq, nil)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate PathMgmt payload: %s\n%s\n",
			err, strings.Join(lines, "\n")))
	}
	blob, err := shared.CtrlCapnpEnc(infra.NullSigner, pmpld)
	if err != nil {
		panic(fmt.Sprintf("Failed to Sign IFStateReq: %s\n%s\n", err, strings.Join(lines, "\n")))
	}
	i.Payload = make([]byte, len(blob))
	copy(i.Payload, blob)
}

func (i *IFStateReqTaggedLayer) updateFields(kvs propMap) {
	for k, v := range kvs {
		switch k {
		case "IfID":
			i.IfID = common.IFIDType(StrToInt(v))
		default:
			panic(fmt.Errorf("Unknown IFStateReq field: %s", k))
		}
	}
}

var _ TaggedLayer = (*IFStateInfoTaggedLayer)(nil)

type IFStateInfoTaggedLayer struct {
	gopacket.Payload
	path_mgmt.IFStateInfo
	RevInfo
	tagged
	options
}

// IFStateInfoParser parses an Interface State Info with the following syntax:
//
// IFStateInfo: IfID=121 Active=true
//
// IFStateInfo: IfID=121 Active=false
//     SignRevInfo: IfID=121 IA=1-ff00:0:1 Link=peer TS=now TTL=60
//
// The SignedRevInfo is optional.
//
func IFStateInfoParser(lines []string) TaggedLayer {
	// default IFStateInfo layer values
	i := &IFStateInfoTaggedLayer{}

	i.Update(lines)
	return i
}

func (p *IFStateInfoTaggedLayer) Layer() gopacket.Layer {
	return &p.Payload
}

func (i *IFStateInfoTaggedLayer) Clone() TaggedLayer {
	clone := *i
	return &clone
}

func (i *IFStateInfoTaggedLayer) Update(lines []string) {
	if i == nil {
		panic(fmt.Errorf("IFStateInfo Tagged Layer is nil!\n"))
	}
	// IFStateInfo is either single line, or two lines with second being the revocation
	if len(lines) < 1 || len(lines) > 2 {
		panic(fmt.Errorf("Bad IFStateInfo layer!\n%s\n", strings.Join(lines, "\n")))
	}
	line := lines[0]
	_, tag, kvStr := decodeLayerLine(line)
	i.tag = tag

	kvs := getKeyValueMap(kvStr)
	i.updateFields(kvs)
	if len(lines) == 2 {
		layerType, _, kvStr := decodeLayerLine(lines[1])
		if layerType != "SignedRevInfo" {
			panic(fmt.Errorf("Bad SignedRevInfo layer!\n%s\n", lines[1]))
		}
		kvs := getKeyValueMap(kvStr)
		i.RevInfo.updateFields(kvs)
		i.SRevInfo = i.RevInfo.sign()
	}
	infos := &path_mgmt.IFStateInfos{Infos: []*path_mgmt.IFStateInfo{&i.IFStateInfo}}
	pmpld, err := path_mgmt.NewPld(infos, nil)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate PathMgmt payload: %s\n%s\n",
			err, strings.Join(lines, "\n")))
	}
	blob, err := shared.CtrlCapnpEnc(infra.NullSigner, pmpld)
	if err != nil {
		panic(fmt.Sprintf("Failed to Sign IFStateInfo: %s\n%s\n", err, strings.Join(lines, "\n")))
	}
	i.Payload = make([]byte, len(blob))
	copy(i.Payload, blob)
}

func (i *IFStateInfoTaggedLayer) updateFields(kvs propMap) {
	for k, v := range kvs {
		switch k {
		case "IfID":
			i.IFStateInfo.IfID = common.IFIDType(StrToInt(v))
		case "Active":
			i.IFStateInfo.Active = StrToBool(v)
		default:
			panic(fmt.Errorf("Unknown IFStateInfo field: %s", k))
		}
	}
}
