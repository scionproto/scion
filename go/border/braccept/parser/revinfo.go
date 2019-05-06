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
	"time"

	"github.com/google/gopacket"

	"github.com/scionproto/scion/go/border/braccept/shared"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/proto"
)

var _ TaggedLayer = (*SignedRevInfoTaggedLayer)(nil)

type SignedRevInfoTaggedLayer struct {
	gopacket.Payload
	SRevInfo *path_mgmt.SignedRevInfo
	RevInfo
	tagged
	options
}

// SignedRevInfoParser parses an Interface State Info with the following syntax:
//
// SignRevInfo: IfID=121 IA=1-ff00:0:1 Link=peer TS=now TTL=60
//
func SignedRevInfoParser(lines []string) TaggedLayer {
	// default SignedRevInfo layer values
	i := &SignedRevInfoTaggedLayer{}

	i.Update(lines)
	return i
}

func (p *SignedRevInfoTaggedLayer) Layer() gopacket.Layer {
	return &p.Payload
}

func (i *SignedRevInfoTaggedLayer) Clone() TaggedLayer {
	clone := *i
	return &clone
}

func (i *SignedRevInfoTaggedLayer) Update(lines []string) {
	if i == nil {
		panic(fmt.Errorf("SignedRevInfo Tagged Layer is nil!\n"))
	}
	if len(lines) != 1 {
		panic(fmt.Errorf("Bad SignedRevInfo layer!\n%s\n", strings.Join(lines, "\n")))
	}
	layerType, tag, kvStr := decodeLayerLine(lines[0])
	if layerType != "SignedRevInfo" {
		panic(fmt.Errorf("Bad RevInfo layer!\n%s\n", lines[0]))
	}
	i.tag = tag

	kvs := getKeyValueMap(kvStr)
	i.updateFields(kvs)
	srev := i.sign()

	pmpld, err := path_mgmt.NewPld(srev, nil)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate PathMgmt payload: %s\n%s\n",
			err, strings.Join(lines, "\n")))
	}
	blob, err := shared.CtrlCapnpEnc(infra.NullSigner, pmpld)
	if err != nil {
		panic(fmt.Sprintf("Failed to Sign SignedRevInfo: %s\n%s\n", err, strings.Join(lines, "\n")))
	}
	i.Payload = make([]byte, len(blob))
	copy(i.Payload, blob)
}

type RevInfo struct {
	path_mgmt.RevInfo
}

func (i *RevInfo) sign() *path_mgmt.SignedRevInfo {
	sRevInfo, err := path_mgmt.NewSignedRevInfo(&i.RevInfo, infra.NullSigner)
	if err != nil {
		panic(fmt.Sprintf("Failed to Sign RevInfo: %s\n", err))
	}
	return sRevInfo
}

func (i *RevInfo) updateFields(kvs propMap) {
	for k, v := range kvs {
		switch k {
		case "IfID":
			i.RevInfo.IfID = common.IFIDType(StrToInt(v))
		case "Link":
			i.LinkType = proto.LinkTypeFromString(v)
			if i.LinkType.String() != v {
				panic(fmt.Errorf("Bad LinkType: %s", v))
			}
		case "IA":
			ia, err := addr.IAFromString(v)
			if err != nil {
				panic(err)
			}
			i.RawIsdas = ia.IAInt()
		case "TS":
			if v != "now" {
				t, err := time.Parse(common.TimeFmt, v)
				if err != nil {
					panic(err)
				}
				i.RawTimestamp = uint32(t.Unix())
			} else {
				i.RawTimestamp = shared.TsNow32
			}
		case "TTL":
			i.RawTTL = uint32(StrToInt(v))
		default:
			panic(fmt.Errorf("Unknown RevInfo field: %s", k))
		}
	}
}
