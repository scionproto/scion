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

package segutil

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/revcache/mock_revcache"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

var (
	g            = graph.NewDefaultGraph()
	seg210_222_1 = g.Beacon([]common.IFIDType{graph.If_210_X_211_A, graph.If_211_A_222_X})

	timeout = time.Second
)

func TestNoRevokedHopIntf(t *testing.T) {
	Convey("NoRevokedHopIntf", t, func() {
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		revCache := mock_revcache.NewMockRevCache(ctrl)
		Convey("Given an empty revcache", func() {
			revCache.EXPECT().Get(gomock.Eq(ctx), gomock.Any())
			noR, err := NoRevokedHopIntf(ctx, revCache, seg210_222_1)
			SoMsg("No err expected", err, ShouldBeNil)
			SoMsg("No revocation expected", noR, ShouldBeTrue)
		})
		Convey("Given a revcache with an on segment revocation", func() {
			sRev := toSigned(t, defaultRevInfo(graph.If_210_X_211_A))
			revCache.EXPECT().Get(gomock.Eq(ctx), gomock.Any()).Return(
				revcache.Revocations{
					revcache.Key{IA: xtest.MustParseIA("2-ff00:0:211"),
						IfId: graph.If_210_X_211_A}: sRev,
				}, nil,
			)
			noR, err := NoRevokedHopIntf(ctx, revCache, seg210_222_1)
			SoMsg("No err expected", err, ShouldBeNil)
			SoMsg("Revocation expected", noR, ShouldBeFalse)
		})
		Convey("Given an error in the revache it is propagated", func() {
			revCache.EXPECT().Get(gomock.Eq(ctx), gomock.Any()).Return(
				nil, common.NewBasicError("TestError", nil),
			)
			_, err := NoRevokedHopIntf(ctx, revCache, seg210_222_1)
			SoMsg("Err expected", err, ShouldNotBeNil)
		})
	})
}

func TestRelevantRevInfos(t *testing.T) {
	Convey("TestRelevantRevInfos", t, func() {
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		segs := []*seg.PathSegment{seg210_222_1}
		revCache := mock_revcache.NewMockRevCache(ctrl)
		Convey("Given an empty revcache", func() {
			revCache.EXPECT().Get(gomock.Eq(ctx), gomock.Any())
			revs, err := RelevantRevInfos(ctx, revCache, segs)
			SoMsg("No err expected", err, ShouldBeNil)
			SoMsg("No revocation expected", revs, ShouldBeEmpty)
		})
		// TODO(lukedirtwalker): Add test with revocations
		Convey("Given an error in the revache it is propagated", func() {
			revCache.EXPECT().Get(gomock.Eq(ctx), gomock.Any()).Return(
				nil, common.NewBasicError("TestError", nil),
			)
			_, err := RelevantRevInfos(ctx, revCache, segs)
			SoMsg("Err expected", err, ShouldNotBeNil)
		})
	})
}

func toSigned(t *testing.T, r *path_mgmt.RevInfo) *path_mgmt.SignedRevInfo {
	sr, err := path_mgmt.NewSignedRevInfo(r, nil)
	xtest.FailOnErr(t, err)
	return sr
}

func defaultRevInfo(ifId common.IFIDType) *path_mgmt.RevInfo {
	return &path_mgmt.RevInfo{
		IfID:     ifId,
		RawIsdas: xtest.MustParseIA("2-ff00:0:211").IAInt(),
	}
}
