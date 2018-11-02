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

package revcachetest

import (
	"context"
	"sort"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/proto"
)

var (
	ia110  = xtest.MustParseIA("1-ff00:0:110")
	ia120  = xtest.MustParseIA("1-ff00:0:120")
	ifId15 = common.IFIDType(15)
	ifId19 = common.IFIDType(19)

	TimeOut = 5 * time.Second
)

// TestRevCache should be used to test any implementation of the RevCache interface.
//
// setup should return a RevCache in a clean state, i.e. no entries in the cache.
// cleanup can be used to release any resources that have been allocated during setup.
func TestRevCache(t *testing.T, setup func() revcache.RevCache, cleanup func()) {
	testWrapper := func(test func(*testing.T, revcache.RevCache)) func() {
		return func() {
			test(t, setup())
			cleanup()
		}
	}

	Convey("InsertGet", testWrapper(testInsertGet))
	Convey("GetAll", testWrapper(testGetAll))
	Convey("InsertExpired", testWrapper(testInsertExpired))
	Convey("InsertNewer", testWrapper(testInsertNewer))
}

func testInsertGet(t *testing.T, revCache revcache.RevCache) {
	sr := toSigned(t, defaultRevInfo(ia110, ifId15))
	ctx, cancelF := context.WithTimeout(context.Background(), TimeOut)
	defer cancelF()
	inserted, err := revCache.Insert(ctx, sr)
	SoMsg("Insert should return true for a new entry", inserted, ShouldBeTrue)
	SoMsg("Insert a new entry should not err", err, ShouldBeNil)
	srCache, ok, err := revCache.Get(ctx, revcache.NewKey(ia110, ifId15))
	MustParseRevInfo(t, srCache)
	SoMsg("Get should return ok for existing entry", ok, ShouldBeTrue)
	SoMsg("Get should not err for existing entry", err, ShouldBeNil)
	SoMsg("Get should return previously inserted value", srCache, ShouldResemble, sr)
	inserted, err = revCache.Insert(ctx, sr)
	SoMsg("Insert should return false for already existing entry", inserted, ShouldBeFalse)
	SoMsg("Insert should not err", err, ShouldBeNil)
	srCache, ok, err = revCache.Get(ctx, revcache.NewKey(ia110, ifId19))
	SoMsg("Get should return nil for not present value", srCache, ShouldBeNil)
	SoMsg("Get should return false for not present value", ok, ShouldBeFalse)
	SoMsg("Get should not err", err, ShouldBeNil)
}

func testGetAll(t *testing.T, revCache revcache.RevCache) {
	sr1 := toSigned(t, defaultRevInfo(ia110, ifId15))
	sr2 := toSigned(t, defaultRevInfo(ia110, ifId19))
	sr3 := toSigned(t, defaultRevInfo(ia120, ifId15))
	sr4 := toSigned(t, defaultRevInfo(ia120, common.IFIDType(10)))
	ctx, cancelF := context.WithTimeout(context.Background(), TimeOut)
	defer cancelF()
	_, err := revCache.Insert(ctx, sr1)
	xtest.FailOnErr(t, err)
	_, err = revCache.Insert(ctx, sr2)
	xtest.FailOnErr(t, err)
	_, err = revCache.Insert(ctx, sr3)
	xtest.FailOnErr(t, err)
	_, err = revCache.Insert(ctx, sr4)
	xtest.FailOnErr(t, err)

	revs, err := revCache.GetAll(ctx, map[revcache.Key]struct{}{
		*revcache.NewKey(ia110, ifId15): {},
	})
	SoMsg("GetAll should not err", err, ShouldBeNil)
	SoMsg("Should contain one rev", 1, ShouldEqual, len(revs))
	MustParseRevInfo(t, revs[0])
	SoMsg("GetAll should return revs for the given keys", revs, ShouldResemble,
		[]*path_mgmt.SignedRevInfo{sr1})

	revs, err = revCache.GetAll(ctx, map[revcache.Key]struct{}{
		*revcache.NewKey(ia110, ifId15): {},
		*revcache.NewKey(ia110, ifId19): {},
		*revcache.NewKey(ia120, ifId15): {},
		*revcache.NewKey(ia120, ifId19): {},
	})
	SoMsg("GetAll should not err", err, ShouldBeNil)
	// we don't care about the order, so sort here to make sure the comparison always works.
	sort.Slice(revs, func(i, j int) bool {
		iInfo, err := revs[i].RevInfo()
		xtest.FailOnErr(t, err)
		jInfo, err := revs[j].RevInfo()
		xtest.FailOnErr(t, err)
		return iInfo.IA().IAInt() < jInfo.IA().IAInt() ||
			(iInfo.IA().IAInt() == jInfo.IA().IAInt() && iInfo.IfID < jInfo.IfID)
	})
	SoMsg("GetAll should return the requested revocations", revs, ShouldResemble,
		[]*path_mgmt.SignedRevInfo{sr1, sr2, sr3})
}

func testInsertExpired(t *testing.T, revCache revcache.RevCache) {
	r := &path_mgmt.RevInfo{
		IfID:         ifId15,
		RawIsdas:     ia110.IAInt(),
		LinkType:     proto.LinkType_core,
		RawTimestamp: util.TimeToSecs(time.Now().Add(-15 * time.Second)),
		RawTTL:       uint32((time.Duration(10) * time.Second).Seconds()),
	}
	ctx, cancelF := context.WithTimeout(context.Background(), TimeOut)
	defer cancelF()
	inserted, err := revCache.Insert(ctx, toSigned(t, r))
	SoMsg("Insert should return false for expired rev", inserted, ShouldBeFalse)
	SoMsg("Insert should not err", err, ShouldBeNil)
}

func testInsertNewer(t *testing.T, revCache revcache.RevCache) {
	sr := toSigned(t, defaultRevInfo(ia110, ifId15))
	ctx, cancelF := context.WithTimeout(context.Background(), TimeOut)
	defer cancelF()
	_, err := revCache.Insert(ctx, sr)
	xtest.FailOnErr(t, err)
	srNew := toSigned(t, &path_mgmt.RevInfo{
		IfID:         ifId15,
		RawIsdas:     ia110.IAInt(),
		LinkType:     proto.LinkType_core,
		RawTimestamp: util.TimeToSecs(time.Now().Add(10 * time.Second)),
		RawTTL:       uint32((time.Duration(10) * time.Second).Seconds()),
	})
	inserted, err := revCache.Insert(ctx, srNew)
	SoMsg("Insert should return true for a new entry", inserted, ShouldBeTrue)
	SoMsg("Insert a new entry should not err", err, ShouldBeNil)
	srCache, ok, err := revCache.Get(ctx, revcache.NewKey(ia110, ifId15))
	MustParseRevInfo(t, srCache)
	SoMsg("Get should return ok for existing entry", ok, ShouldBeTrue)
	SoMsg("Get should not err for existing entry", err, ShouldBeNil)
	SoMsg("Get should return previously inserted value", srCache, ShouldResemble, srNew)
}

func toSigned(t *testing.T, r *path_mgmt.RevInfo) *path_mgmt.SignedRevInfo {
	sr, err := path_mgmt.NewSignedRevInfo(r, nil)
	xtest.FailOnErr(t, err)
	return sr
}

func defaultRevInfo(ia addr.IA, ifId common.IFIDType) *path_mgmt.RevInfo {
	return &path_mgmt.RevInfo{
		IfID:         ifId,
		RawIsdas:     ia.IAInt(),
		LinkType:     proto.LinkType_core,
		RawTimestamp: util.TimeToSecs(time.Now()),
		RawTTL:       uint32((time.Duration(10) * time.Second).Seconds()),
	}
}

func MustParseRevInfo(t *testing.T, sr *path_mgmt.SignedRevInfo) {
	_, err := sr.RevInfo()
	xtest.FailOnErr(t, err)
}
