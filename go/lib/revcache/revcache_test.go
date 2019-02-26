// Copyright 2019 Anapaya Systems
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
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/revcache/mock_revcache"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/proto"
)

var (
	ia110  = xtest.MustParseIA("1-ff00:0:110")
	ifid10 = common.IFIDType(10)
	ifid11 = common.IFIDType(11)

	now = time.Now()
)

func TestFilterNew(t *testing.T) {
	sr10 := toSigned(t, defaultRevInfo(ia110, ifid10, now))
	sr11 := toSigned(t, defaultRevInfo(ia110, ifid11, now))
	sr11Old := toSigned(t, defaultRevInfo(ia110, ifid11, now.Add(-10*time.Second)))
	Convey("TestFilterNew", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		revCache := mock_revcache.NewMockRevCache(ctrl)
		Convey("Given an empty cache", func() {
			revCache.EXPECT().Get(gomock.Any(), gomock.Any()).Return(nil, nil)
			rMap, err := revcache.RevocationToMap([]*path_mgmt.SignedRevInfo{sr10})
			expectedMap := copy(rMap)
			SoMsg("No error expected", err, ShouldBeNil)
			err = rMap.FilterNew(context.Background(), revCache)
			SoMsg("No error expected", err, ShouldBeNil)
			SoMsg("All revocations should be considered new", rMap, ShouldResemble, expectedMap)
		})
		Convey("Given a cache with an old revocation", func() {
			revCache.EXPECT().Get(gomock.Any(), gomock.Any()).Return(revcache.Revocations{
				revcache.Key{IA: ia110, IfId: ifid11}: sr11Old,
			}, nil)
			rMap, err := revcache.RevocationToMap([]*path_mgmt.SignedRevInfo{sr10, sr11})
			expectedMap := copy(rMap)
			SoMsg("No error expected", err, ShouldBeNil)
			err = rMap.FilterNew(context.Background(), revCache)
			SoMsg("No error expected", err, ShouldBeNil)
			SoMsg("All revocations should be considered new", rMap, ShouldResemble, expectedMap)
		})
		Convey("Given a cache with a newer revocation", func() {
			revCache.EXPECT().Get(gomock.Any(), gomock.Any()).Return(revcache.Revocations{
				revcache.Key{IA: ia110, IfId: ifid11}: sr11,
			}, nil)
			rMap, err := revcache.RevocationToMap([]*path_mgmt.SignedRevInfo{sr10, sr11Old})
			expectedMap := copy(rMap)
			delete(expectedMap, revcache.Key{IA: ia110, IfId: ifid11})
			SoMsg("No error expected", err, ShouldBeNil)
			err = rMap.FilterNew(context.Background(), revCache)
			SoMsg("No error expected", err, ShouldBeNil)
			SoMsg("Only new revocations should stay in map", rMap, ShouldResemble, expectedMap)
		})
		Convey("Given a cache with an error", func() {
			expectedErr := common.NewBasicError("TESTERR", nil)
			revCache.EXPECT().Get(gomock.Any(), gomock.Any()).Return(nil, expectedErr)
			rMap, err := revcache.RevocationToMap([]*path_mgmt.SignedRevInfo{})
			SoMsg("No error expected", err, ShouldBeNil)
			err = rMap.FilterNew(context.Background(), revCache)
			SoMsg("Error from cache expected", err, ShouldResemble, expectedErr)
		})
	})

}

func copy(revs revcache.Revocations) revcache.Revocations {
	res := make(revcache.Revocations, len(revs))
	for k, v := range revs {
		res[k] = v
	}
	return res
}

func toSigned(t *testing.T, r *path_mgmt.RevInfo) *path_mgmt.SignedRevInfo {
	sr, err := path_mgmt.NewSignedRevInfo(r, nil)
	xtest.FailOnErr(t, err)
	return sr
}

func defaultRevInfo(ia addr.IA, ifId common.IFIDType, ts time.Time) *path_mgmt.RevInfo {
	return &path_mgmt.RevInfo{
		IfID:         ifId,
		RawIsdas:     ia.IAInt(),
		LinkType:     proto.LinkType_core,
		RawTimestamp: util.TimeToSecs(ts),
		RawTTL:       uint32((time.Duration(10) * time.Second).Seconds()),
	}
}
