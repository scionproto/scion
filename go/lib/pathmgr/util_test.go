// Copyright 2018 ETH Zurich
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

package pathmgr_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/mock_snet"
	"github.com/scionproto/scion/go/lib/xtest"
)

func buildSDAnswer(t testing.TB, ctrl *gomock.Controller, pathStrings ...string) []snet.Path {
	var paths []snet.Path
	for _, path := range pathStrings {
		paths = append(paths, createPath(t, ctrl, path))
	}
	return paths
}

func createPath(t testing.TB, ctrl *gomock.Controller, desc string) snet.Path {
	parts := strings.Split(desc, " ")
	path := mock_snet.NewMockPath(ctrl)
	interfaces := make([]snet.PathInterface, 0, len(parts))
	for _, part := range parts {
		tokens := strings.Split(part, "#")
		if len(tokens) != 2 {
			t.Fatalf("Invalid path description: %s", desc)
		}
		interfaces = append(interfaces, intf{
			ia: xtest.MustParseIA(tokens[0]),
			id: mustIfID(t, tokens[1]),
		})
	}
	path.EXPECT().Interfaces().Return(interfaces).AnyTimes()
	return path
}

func mustIfID(t testing.TB, s string) common.IFIDType {
	ifID, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatalf("Failed to parse interface: %s", s)
	}
	return common.IFIDType(ifID)
}

type intf struct {
	ia addr.IA
	id common.IFIDType
}

func (i intf) IA() addr.IA         { return i.ia }
func (i intf) ID() common.IFIDType { return i.id }
