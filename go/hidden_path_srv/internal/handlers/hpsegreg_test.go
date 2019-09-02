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

package handlers_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/hidden_path_srv/internal/handlers"
	"github.com/scionproto/scion/go/hidden_path_srv/internal/hiddenpathdb/adapter"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/ack"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/hiddenpath"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb/mock_pathdb"
	"github.com/scionproto/scion/go/lib/snet"
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
		}),
		proto.PathSegType_down,
	))
	// hidden up
	seg120_121 = markHidden(t, seg.NewMeta(
		g.Beacon([]common.IFIDType{
			graph.If_120_B_121_X,
		}),
		proto.PathSegType_up,
	))
	// missing hidden extn
	seg210_212 = seg.NewMeta(
		g.Beacon([]common.IFIDType{
			graph.If_210_X_211_A,
			graph.If_211_A_212_X,
		}),
		proto.PathSegType_down,
	)
	// core seg type
	seg110_120 = markHidden(t, seg.NewMeta(
		g.Beacon([]common.IFIDType{
			graph.If_110_X_120_A,
		}),
		proto.PathSegType_core,
	))
}

func TestSegReg(t *testing.T) {
	newTestGraph(t, gomock.NewController(t))
	tests := map[string]struct {
		hpsIA   addr.IA
		peer    *snet.Addr
		groupId hiddenpath.GroupId
		segs    []*seg.Meta
		ack     *ackMatcher
		result  *infra.HandlerResult
		exp     func(*mocks, *ackMatcher)
	}{
		"writer can register": {
			hpsIA:   ia115,
			peer:    &snet.Addr{IA: ia112},
			groupId: group.Id,
			segs:    []*seg.Meta{seg110_133},
			ack: &ackMatcher{
				Err:     proto.Ack_ErrCode_ok,
				ErrDesc: "",
			},
			result: infra.MetricsResultOk,
			exp: func(m *mocks, a *ackMatcher) {
				m.ts.EXPECT().NewVerifier().Return(infra.NullSigVerifier)
				m.db.EXPECT().BeginTransaction(gomock.Any(), gomock.Any()).Return(m.tx, nil)
				m.tx.EXPECT().InsertWithHPCfgIDs(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
				m.tx.EXPECT().Commit()
				m.rw.EXPECT().SendAckReply(gomock.Any(), a)
			},
		},
		"owner can register": {
			hpsIA:   ia115,
			peer:    &snet.Addr{IA: ia110},
			groupId: group.Id,
			segs:    []*seg.Meta{seg110_133, seg120_121},
			ack: &ackMatcher{
				Err:     proto.Ack_ErrCode_ok,
				ErrDesc: "",
			},
			result: infra.MetricsResultOk,
			exp: func(m *mocks, a *ackMatcher) {
				m.ts.EXPECT().NewVerifier().Return(infra.NullSigVerifier)
				m.db.EXPECT().BeginTransaction(gomock.Any(), gomock.Any()).Return(m.tx, nil)
				m.tx.EXPECT().InsertWithHPCfgIDs(gomock.Any(), gomock.Any(), gomock.Any()).Times(2)
				m.tx.EXPECT().Commit()
				m.rw.EXPECT().SendAckReply(gomock.Any(), a)
			},
		},
		"unknown group": {
			hpsIA:   ia115,
			peer:    &snet.Addr{IA: ia110},
			groupId: wrongId,
			segs:    []*seg.Meta{seg110_133},
			ack: &ackMatcher{
				Err:     proto.Ack_ErrCode_reject,
				ErrDesc: handlers.UnknownGroupErr.Error(),
			},
			result: infra.MetricsErrInvalid,
			exp: func(m *mocks, a *ackMatcher) {
				m.rw.EXPECT().SendAckReply(gomock.Any(), a)
			},
		},
		"wrong registry": {
			hpsIA:   ia113,
			peer:    &snet.Addr{IA: ia112},
			groupId: group.Id,
			segs:    []*seg.Meta{seg110_133},
			ack: &ackMatcher{
				Err:     proto.Ack_ErrCode_reject,
				ErrDesc: handlers.NotRegistryErr.Error(),
			},
			result: infra.MetricsErrInvalid,
			exp: func(m *mocks, a *ackMatcher) {
				m.rw.EXPECT().SendAckReply(gomock.Any(), a)
			},
		},
		"not a writer": {
			hpsIA:   ia110,
			peer:    &snet.Addr{IA: ia113},
			groupId: group.Id,
			segs:    []*seg.Meta{seg110_133},
			ack: &ackMatcher{
				Err:     proto.Ack_ErrCode_reject,
				ErrDesc: handlers.NotWriterErr.Error(),
			},
			result: infra.MetricsErrInvalid,
			exp: func(m *mocks, a *ackMatcher) {
				m.rw.EXPECT().SendAckReply(gomock.Any(), a)
			},
		},
		"missing extension": {
			hpsIA:   ia115,
			peer:    &snet.Addr{IA: ia110},
			groupId: group.Id,
			segs:    []*seg.Meta{seg210_212},
			ack: &ackMatcher{
				Err:     proto.Ack_ErrCode_reject,
				ErrDesc: handlers.NoSegmentsErr.Error(),
			},
			result: infra.MetricsErrInvalid,
			exp: func(m *mocks, a *ackMatcher) {
				m.rw.EXPECT().SendAckReply(gomock.Any(), a)
			},
		},
		"wrong seg type": {
			hpsIA:   ia115,
			peer:    &snet.Addr{IA: ia110},
			groupId: group.Id,
			segs:    []*seg.Meta{seg110_120},
			ack: &ackMatcher{
				Err:     proto.Ack_ErrCode_reject,
				ErrDesc: handlers.NoSegmentsErr.Error(),
			},
			result: infra.MetricsErrInvalid,
			exp: func(m *mocks, a *ackMatcher) {
				m.rw.EXPECT().SendAckReply(gomock.Any(), a)
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			m := getMocks(ctrl)
			log.Root().SetHandler(log.DiscardHandler())
			ctx := infra.NewContextWithResponseWriter(
				context.Background(), m.rw)
			args := handlers.HandlerArgs{
				HiddenPathDB: adapter.New(m.db),
				Groups: map[hiddenpath.GroupId]*hiddenpath.Group{
					group.Id: group,
				},
				LocalIA:         test.hpsIA,
				VerifierFactory: m.ts,
			}
			h := handlers.NewSegRegHandler(args)
			msg := &path_mgmt.HPSegReg{
				HPSegRecs: &path_mgmt.HPSegRecs{
					GroupId: test.groupId.ToMsg(),
					Recs:    test.segs,
				},
			}
			r := infra.NewRequest(ctx, msg, nil, test.peer, messenger.NextId())
			test.exp(m, test.ack)
			res := h.Handle(r)
			assert.Equal(t, test.result, res)
		})
	}
}

type mocks struct {
	db *mock_pathdb.MockPathDB
	tx *mock_pathdb.MockTransaction
	ts *mock_infra.MockTrustStore
	rw *mock_infra.MockResponseWriter
}

func getMocks(ctrl *gomock.Controller) *mocks {
	return &mocks{
		db: mock_pathdb.NewMockPathDB(ctrl),
		tx: mock_pathdb.NewMockTransaction(ctrl),
		ts: mock_infra.NewMockTrustStore(ctrl),
		rw: mock_infra.NewMockResponseWriter(ctrl),
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

type ackMatcher struct {
	Err     proto.Ack_ErrCode
	ErrDesc string
}

func (m *ackMatcher) Matches(x interface{}) bool {
	a, ok := x.(*ack.Ack)
	if !ok {
		return false
	}
	return m.Err == a.Err && strings.Contains(a.ErrDesc, m.ErrDesc)
}
func (m *ackMatcher) String() string {
	return fmt.Sprintf("Ack %v: %v", m.Err, m.ErrDesc)
}
