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

package registration_test

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/hidden_path_srv/internal/registration"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/hiddenpath"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	"github.com/scionproto/scion/go/proto"
)

var (
	as110 = xtest.MustParseAS("ff00:0:110")
	ia110 = xtest.MustParseIA("1-ff00:0:110")
	ia111 = xtest.MustParseIA("1-ff00:0:111")
	ia112 = xtest.MustParseIA("1-ff00:0:112")
	ia113 = xtest.MustParseIA("1-ff00:0:113")
	ia114 = xtest.MustParseIA("1-ff00:0:114")
	ia115 = xtest.MustParseIA("1-ff00:0:115")
)

var group = &hiddenpath.Group{
	Id: hiddenpath.GroupId{
		OwnerAS: as110,
		Suffix:  0x69b5,
	},
	Version:    1,
	Owner:      ia110,
	Writers:    []addr.IA{ia111, ia112},
	Readers:    []addr.IA{ia113, ia114},
	Registries: []addr.IA{ia110, ia115},
}

var wrongId = hiddenpath.GroupId{
	OwnerAS: as110,
	Suffix:  0x0,
}

var (
	seg110_133 *seg.Meta
	seg120_121 *seg.Meta
	seg210_212 *seg.Meta
	seg110_120 *seg.Meta
)

func newTestGraph(t *testing.T, ctrl *gomock.Controller) {
	t.Helper()
	g := graph.NewDefaultGraph(ctrl)
	// hidden down
	seg110_133 = markHidden(t, seg.NewMeta(
		g.Beacon([]common.IFIDType{
			graph.If_110_X_130_A,
			graph.If_130_A_131_X,
			graph.If_131_X_132_X,
			graph.If_132_X_133_X,
		}, false),
		proto.PathSegType_down,
	))
	// hidden up
	seg120_121 = markHidden(t, seg.NewMeta(
		g.Beacon([]common.IFIDType{
			graph.If_120_B_121_X,
		}, false),
		proto.PathSegType_up,
	))
	// missing hidden extn
	seg210_212 = seg.NewMeta(
		g.Beacon([]common.IFIDType{
			graph.If_210_X_211_A,
			graph.If_211_A_212_X,
		}, false),
		proto.PathSegType_down,
	)
	// core seg type
	seg110_120 = markHidden(t, seg.NewMeta(
		g.Beacon([]common.IFIDType{
			graph.If_110_X_120_A,
		}, false),
		proto.PathSegType_core,
	))
}

func TestValidator(t *testing.T) {
	newTestGraph(t, gomock.NewController(t))
	tests := map[string]struct {
		hpsIA          addr.IA
		peer           addr.IA
		groupId        hiddenpath.GroupId
		segs           []*seg.Meta
		Err            error
		ErrorAssertion require.ErrorAssertionFunc
	}{
		"writer can register": {
			hpsIA:   ia115,
			peer:    ia112,
			groupId: group.Id,
			segs:    []*seg.Meta{seg110_133},
			Err:     nil,
		},
		"owner can register": {
			hpsIA:   ia115,
			peer:    ia110,
			groupId: group.Id,
			segs:    []*seg.Meta{seg110_133, seg120_121},
			Err:     nil,
		},
		"unknown group": {
			hpsIA:   ia115,
			peer:    ia110,
			groupId: wrongId,
			segs:    []*seg.Meta{seg110_133},
			Err:     registration.ErrUnknownGroup,
		},
		"wrong registry": {
			hpsIA:   ia113,
			peer:    ia112,
			groupId: group.Id,
			segs:    []*seg.Meta{seg110_133},
			Err:     registration.ErrNotRegistry,
		},
		"not a writer": {
			hpsIA:   ia110,
			peer:    ia113,
			groupId: group.Id,
			segs:    []*seg.Meta{seg110_133},
			Err:     registration.ErrNotWriter,
		},
		"missing extension": {
			hpsIA:   ia115,
			peer:    ia110,
			groupId: group.Id,
			segs:    []*seg.Meta{seg210_212},
			Err:     registration.ErrMissingExtn,
		},
		"wrong seg type": {
			hpsIA:   ia115,
			peer:    ia110,
			groupId: group.Id,
			segs:    []*seg.Meta{seg110_120},
			Err:     registration.ErrWrongSegType,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			validator := registration.NewDefaultValidator(
				test.hpsIA,
				map[hiddenpath.GroupId]*hiddenpath.Group{
					group.Id: group,
				},
			)
			msg := &path_mgmt.HPSegReg{
				HPSegRecs: &path_mgmt.HPSegRecs{
					GroupId: test.groupId.ToMsg(),
					Recs:    test.segs,
				},
			}
			err := validator.Validate(msg, test.peer)
			xtest.AssertErrorsIs(t, err, test.Err)
		})
	}
}

func markHidden(t *testing.T, m *seg.Meta) *seg.Meta {
	t.Helper()
	s := m.Segment
	infoF, err := s.SData.InfoF()
	require.NoError(t, err)
	newSeg, err := seg.NewSeg(infoF)
	require.NoError(t, err)
	if s.MaxAEIdx() < 0 {
		panic("Segment has no AS entries")
	}
	s.ASEntries[s.MaxAEIdx()].Exts.HiddenPathSeg = seg.NewHiddenPathSegExtn()
	for _, entry := range s.ASEntries {
		newSeg.AddASEntry(entry, infra.NullSigner)
	}
	return seg.NewMeta(newSeg, m.Type)
}
