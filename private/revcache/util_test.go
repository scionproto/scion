// Copyright 2018 Anapaya Systems
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

package revcache_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt/proto"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/private/xtest/graph"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/private/revcache"
	"github.com/scionproto/scion/private/revcache/mock_revcache"
)

var (
	ia211   = addr.MustParseIA("2-ff00:0:211")
	timeout = time.Second
)

func TestNoRevokedHopIntf(t *testing.T) {
	now := time.Now()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	seg210_222_1 := createSeg(ctrl)

	t.Run("empty", func(t *testing.T) {
		revCache := mock_revcache.NewMockRevCache(ctrl)
		revCache.EXPECT().Get(gomock.Eq(ctx), gomock.Any()).AnyTimes()
		noR, err := revcache.NoRevokedHopIntf(ctx, revCache, seg210_222_1)
		assert.NoError(t, err)
		assert.True(t, noR, "no revocation expected")
	})
	t.Run("on segment revocation", func(t *testing.T) {
		sRev := defaultRevInfo(ia211, graph.If_211_A_210_X, now)
		revCache := mock_revcache.NewMockRevCache(ctrl)
		revCache.EXPECT().Get(gomock.Eq(ctx), gomock.Any()).DoAndReturn(
			func(_ context.Context, key revcache.Key) (*path_mgmt.RevInfo, error) {
				iaFmt := key.IA.String()
				_ = iaFmt
				if key.IA == ia211 && key.IfID == iface.ID(graph.If_211_A_210_X) {
					return sRev, nil
				}
				return nil, nil
			}).AnyTimes()

		noR, err := revcache.NoRevokedHopIntf(ctx, revCache, seg210_222_1)
		assert.NoError(t, err)
		assert.False(t, noR, "revocation expected")
	})
	t.Run("error progation", func(t *testing.T) {
		revCache := mock_revcache.NewMockRevCache(ctrl)
		revCache.EXPECT().Get(gomock.Eq(ctx), gomock.Any()).Return(
			nil, serrors.New("TestError"),
		).AnyTimes()
		_, err := revcache.NoRevokedHopIntf(ctx, revCache, seg210_222_1)
		assert.Error(t, err)
	})
}

func defaultRevInfo(ia addr.IA, ifID uint16, ts time.Time) *path_mgmt.RevInfo {
	return &path_mgmt.RevInfo{
		IfID:         iface.ID(ifID),
		RawIsdas:     ia,
		LinkType:     proto.LinkType_core,
		RawTimestamp: util.TimeToSecs(ts),
		RawTTL:       uint32((time.Duration(10) * time.Second).Seconds()),
	}
}

func createSeg(ctrl *gomock.Controller) *seg.PathSegment {
	g := graph.NewDefaultGraph(ctrl)
	return g.Beacon([]uint16{graph.If_210_X_211_A, graph.If_211_A_222_X})
}
