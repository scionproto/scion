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

package hpsegreq_test

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/hidden_path_srv/internal/hiddenpathdb/adapter"
	"github.com/scionproto/scion/go/hidden_path_srv/internal/hpsegreq"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/hiddenpath"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/pathdb/mock_pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	"github.com/scionproto/scion/go/proto"
)

var (
	as110 = xtest.MustParseAS("ff00:0:110")
	as111 = xtest.MustParseAS("ff00:0:111")
	as112 = xtest.MustParseAS("ff00:0:111")
	ia110 = xtest.MustParseIA("1-ff00:0:110")
	ia111 = xtest.MustParseIA("1-ff00:0:111")
	ia112 = xtest.MustParseIA("1-ff00:0:112")
	ia113 = xtest.MustParseIA("1-ff00:0:113")
	ia114 = xtest.MustParseIA("1-ff00:0:114")
	ia115 = xtest.MustParseIA("1-ff00:0:115")
)

var group1 = &hiddenpath.Group{
	Id: hiddenpath.GroupId{
		OwnerAS: as110,
		Suffix:  0x69b5,
	},
	Version:    1,
	Owner:      ia110,
	Writers:    []addr.IA{ia111, ia112},
	Readers:    []addr.IA{ia113},
	Registries: []addr.IA{ia110, ia115},
}

var group2 = &hiddenpath.Group{
	Id: hiddenpath.GroupId{
		OwnerAS: as111,
		Suffix:  0xabcd,
	},
	Version:    1,
	Owner:      ia111,
	Writers:    []addr.IA{ia111, ia112},
	Readers:    []addr.IA{ia113, ia114},
	Registries: []addr.IA{ia115},
}

var group3 = &hiddenpath.Group{
	Id: hiddenpath.GroupId{
		OwnerAS: as112,
		Suffix:  0xacdc,
	},
	Version:    1,
	Owner:      ia112,
	Writers:    []addr.IA{},
	Readers:    []addr.IA{ia113},
	Registries: []addr.IA{ia114},
}

var wrongId = hiddenpath.GroupId{
	OwnerAS: as110,
	Suffix:  0x0,
}

var (
	seg130_112     *seg.Meta
	seg130_111_112 *seg.Meta
	seg120_111_112 *seg.Meta
)

func newTestGraph(t *testing.T, ctrl *gomock.Controller) {
	t.Helper()
	g := graph.NewDefaultGraph(ctrl)
	seg130_112 = markHidden(t, seg.NewMeta(
		g.Beacon([]common.IFIDType{
			graph.If_130_A_112_X,
		}, false),
		proto.PathSegType_down,
	))
	seg130_111_112 = markHidden(t, seg.NewMeta(
		g.Beacon([]common.IFIDType{
			graph.If_130_B_111_A,
			graph.If_111_A_112_X,
		}, false),
		proto.PathSegType_up,
	))
	seg120_111_112 = markHidden(t, seg.NewMeta(
		g.Beacon([]common.IFIDType{
			graph.If_120_X_111_B,
			graph.If_111_A_112_X,
		}, false),
		proto.PathSegType_core,
	))
}

func TestFetcher(t *testing.T) {
	newTestGraph(t, gomock.NewController(t))
	tests := map[string]struct {
		req   *path_mgmt.HPSegReq
		peer  *snet.UDPAddr
		err   error
		res   []*path_mgmt.HPSegRecs
		setup func(mockDB *mock_pathdb.MockPathDB, mockMsgr *mock_infra.MockMessenger)
	}{
		"only DB": {
			req: &path_mgmt.HPSegReq{
				RawDstIA: ia111.IAInt(),
				GroupIds: []*path_mgmt.HPGroupId{group1.Id.ToMsg()},
			},
			peer: &snet.UDPAddr{IA: ia113},
			res: []*path_mgmt.HPSegRecs{
				{
					GroupId: group1.Id.ToMsg(),
					Recs: []*seg.Meta{
						seg130_112,
					},
				},
			},
			setup: func(mockDB *mock_pathdb.MockPathDB, mockMsgr *mock_infra.MockMessenger) {
				res := query.Results{
					&query.Result{Seg: seg130_112.Segment, Type: seg130_112.Type},
				}
				mockDB.EXPECT().Get(gomock.Any(), gomock.Any()).Return(res, nil)
			},
		},
		"only remote": {
			req: &path_mgmt.HPSegReq{
				RawDstIA: ia111.IAInt(),
				GroupIds: []*path_mgmt.HPGroupId{group2.Id.ToMsg()},
			},
			peer: &snet.UDPAddr{IA: ia113},
			res: []*path_mgmt.HPSegRecs{
				{
					GroupId: group2.Id.ToMsg(),
					Recs: []*seg.Meta{
						seg130_111_112,
					},
				},
			},
			setup: func(mockDB *mock_pathdb.MockPathDB, mockMsgr *mock_infra.MockMessenger) {
				reply := &path_mgmt.HPSegReply{
					Recs: []*path_mgmt.HPSegRecs{
						{
							GroupId: group2.Id.ToMsg(),
							Recs: []*seg.Meta{
								seg130_111_112,
							},
						},
					},
				}
				addr := &snet.SVCAddr{IA: ia115, SVC: addr.SvcHPS}
				mockMsgr.EXPECT().GetHPSegs(gomock.Any(), gomock.Any(),
					addr, gomock.Any()).Return(reply, nil)
			},
		},
		"DB and remote": {
			req: &path_mgmt.HPSegReq{
				RawDstIA: ia111.IAInt(),
				GroupIds: []*path_mgmt.HPGroupId{group1.Id.ToMsg(), group2.Id.ToMsg()},
			},
			peer: &snet.UDPAddr{IA: ia113},
			res: []*path_mgmt.HPSegRecs{
				{
					GroupId: group1.Id.ToMsg(),
					Recs: []*seg.Meta{
						seg130_112,
					},
				},
				{
					GroupId: group2.Id.ToMsg(),
					Recs: []*seg.Meta{
						seg130_111_112,
					},
				},
			},
			setup: func(mockDB *mock_pathdb.MockPathDB, mockMsgr *mock_infra.MockMessenger) {
				res := query.Results{
					&query.Result{Seg: seg130_112.Segment, Type: seg130_112.Type},
				}
				reply := &path_mgmt.HPSegReply{
					Recs: []*path_mgmt.HPSegRecs{
						{
							GroupId: group2.Id.ToMsg(),
							Recs: []*seg.Meta{
								seg130_111_112,
							},
						},
					},
				}
				addr := &snet.SVCAddr{IA: ia115, SVC: addr.SvcHPS}
				mockDB.EXPECT().Get(gomock.Any(), gomock.Any()).Return(res, nil)
				mockMsgr.EXPECT().GetHPSegs(gomock.Any(), gomock.Any(), addr,
					gomock.Any()).Return(reply, nil)
			},
		},
		"two remote": {
			req: &path_mgmt.HPSegReq{
				RawDstIA: ia111.IAInt(),
				GroupIds: []*path_mgmt.HPGroupId{group2.Id.ToMsg(), group3.Id.ToMsg()},
			},
			peer: &snet.UDPAddr{IA: ia113},
			res: []*path_mgmt.HPSegRecs{
				{
					GroupId: group2.Id.ToMsg(),
					Recs: []*seg.Meta{
						seg130_111_112,
					},
				},
				{
					GroupId: group3.Id.ToMsg(),
					Recs: []*seg.Meta{
						seg120_111_112,
					},
				},
			},
			setup: func(mockDB *mock_pathdb.MockPathDB, mockMsgr *mock_infra.MockMessenger) {
				reply2 := &path_mgmt.HPSegReply{
					Recs: []*path_mgmt.HPSegRecs{
						{
							GroupId: group2.Id.ToMsg(),
							Recs: []*seg.Meta{
								seg130_111_112,
							},
						},
					},
				}
				reply3 := &path_mgmt.HPSegReply{
					Recs: []*path_mgmt.HPSegRecs{
						{
							GroupId: group3.Id.ToMsg(),
							Recs: []*seg.Meta{
								seg120_111_112,
							},
						},
					},
				}
				addr2 := &snet.SVCAddr{IA: ia115, SVC: addr.SvcHPS}
				mockMsgr.EXPECT().GetHPSegs(gomock.Any(), gomock.Any(), addr2,
					gomock.Any()).Return(reply2, nil)
				addr3 := &snet.SVCAddr{IA: ia114, SVC: addr.SvcHPS}
				mockMsgr.EXPECT().GetHPSegs(gomock.Any(), gomock.Any(), addr3,
					gomock.Any()).Return(reply3, nil)
			},
		},
		"DB error": {
			req: &path_mgmt.HPSegReq{
				RawDstIA: ia111.IAInt(),
				GroupIds: []*path_mgmt.HPGroupId{group1.Id.ToMsg()},
			},
			peer: &snet.UDPAddr{IA: ia113},
			res: []*path_mgmt.HPSegRecs{
				{
					GroupId: group1.Id.ToMsg(),
					Err:     "dummy",
				},
			},
			setup: func(mockDB *mock_pathdb.MockPathDB, mockMsgr *mock_infra.MockMessenger) {
				mockDB.EXPECT().Get(gomock.Any(), gomock.Any()).Return(nil, errors.New("dummy"))
			},
		},
		"remote error": {
			req: &path_mgmt.HPSegReq{
				RawDstIA: ia111.IAInt(),
				GroupIds: []*path_mgmt.HPGroupId{group2.Id.ToMsg()},
			},
			peer: &snet.UDPAddr{IA: ia113},
			res: []*path_mgmt.HPSegRecs{
				{
					GroupId: group2.Id.ToMsg(),
					Err:     "dummy",
				},
			},
			setup: func(mockDB *mock_pathdb.MockPathDB, mockMsgr *mock_infra.MockMessenger) {
				addr := &snet.SVCAddr{IA: ia115, SVC: addr.SvcHPS}
				mockMsgr.EXPECT().GetHPSegs(gomock.Any(), gomock.Any(),
					addr, gomock.Any()).Return(nil, errors.New("dummy"))
			},
		},
		"unknown group": {
			req: &path_mgmt.HPSegReq{
				RawDstIA: ia111.IAInt(),
				GroupIds: []*path_mgmt.HPGroupId{wrongId.ToMsg()},
			},
			peer:  &snet.UDPAddr{IA: ia114},
			err:   hpsegreq.ErrUnknownGroup,
			setup: func(mockDB *mock_pathdb.MockPathDB, mockMsgr *mock_infra.MockMessenger) {},
		},
		"not a reader": {
			req: &path_mgmt.HPSegReq{
				RawDstIA: ia111.IAInt(),
				GroupIds: []*path_mgmt.HPGroupId{group1.Id.ToMsg()},
			},
			peer:  &snet.UDPAddr{IA: ia114},
			err:   hpsegreq.ErrNotReader,
			setup: func(mockDB *mock_pathdb.MockPathDB, mockMsgr *mock_infra.MockMessenger) {},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(&xtest.PanickingReporter{T: t})
			defer ctrl.Finish()
			groupInfo := &hpsegreq.GroupInfo{
				LocalIA: ia110,
				Groups: map[hiddenpath.GroupId]*hiddenpath.Group{
					group1.Id: group1,
					group2.Id: group2,
					group3.Id: group3,
				},
			}
			mockDB := mock_pathdb.NewMockPathDB(ctrl)
			mockMsgr := mock_infra.NewMockMessenger(ctrl)
			f := hpsegreq.NewDefaultFetcher(groupInfo, mockMsgr, adapter.New(mockDB))
			test.setup(mockDB, mockMsgr)
			recs, err := f.Fetch(context.Background(), test.req, test.peer)
			xtest.AssertErrorsIs(t, err, test.err)
			assert.ElementsMatch(t, test.res, recs)
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
