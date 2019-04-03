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
	"time"

	"github.com/scionproto/scion/go/border/braccept/shared"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/proto"
)

type RevInfo struct {
	path_mgmt.RevInfo
}

func (i *RevInfo) parse(line string) {
	layerType, _, kvStr := decodeLayerLine(line)
	if layerType != "SignedRevInfo" {
		panic(fmt.Errorf("Bad RevInfo layer!\n%s\n", line))
	}

	kvs := getKeyValueMap(kvStr)
	i.updateFields(kvs)
}

func (i *RevInfo) sign() *path_mgmt.SignedRevInfo {
	sRevInfo, err := path_mgmt.NewSignedRevInfo(&i.RevInfo, nil)
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
