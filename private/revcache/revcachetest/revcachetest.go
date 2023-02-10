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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt/proto"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/private/revcache"
)

var (
	ia110  = xtest.MustParseIA("1-ff00:0:110")
	ia120  = xtest.MustParseIA("1-ff00:0:120")
	ifId15 = common.IFIDType(15)
	ifId19 = common.IFIDType(19)

	TimeOut = 5 * time.Second
)

// TestableRevCache extends the RevCache interface with methods that are needed for testing.
type TestableRevCache interface {
	revcache.RevCache
	// InsertExpired should insert the given expired revocation.
	// The testing parameter should be used to fail in case of an error.
	// The method is used to test if expired revocations are not returned.
	InsertExpired(t *testing.T, ctx context.Context, rev *path_mgmt.RevInfo)
	// Prepare should reset the internal state so that the cache is empty and is ready to be tested.
	Prepare(t *testing.T, ctx context.Context)
}

// TestRevCache should be used to test any implementation of the RevCache interface.
//
// setup should return a RevCache in a clean state, i.e. no entries in the cache.
// cleanup can be used to release any resources that have been allocated during setup.
func TestRevCache(t *testing.T, revCache TestableRevCache) {
	testWrapper := func(test func(*testing.T, TestableRevCache)) func() {
		return func() {
			prepareCtx, cancelF := context.WithTimeout(context.Background(), TimeOut)
			defer cancelF()
			revCache.Prepare(t, prepareCtx)
			test(t, revCache)
		}
	}
	Convey("InsertGet", testWrapper(testInsertGet))
	Convey("GetMultikey", testWrapper(testGetMultikey))
	Convey("GetAll", testWrapper(testGetAll))
	Convey("GetAllExpired", testWrapper(testGetAllExpired))
	Convey("InsertExpired", testWrapper(testInsertExpired))
	Convey("InsertNewer", testWrapper(testInsertNewer))
	Convey("GetExpired", testWrapper(testGetExpired))
	Convey("GetMultikeyExpired", testWrapper(testGetMuliKeysExpired))
	Convey("DeleteExpired", testWrapper(testDeleteExpired))
}

func testInsertGet(t *testing.T, revCache TestableRevCache) {
	rev := defaultRevInfo(ia110, ifId15)
	ctx, cancelF := context.WithTimeout(context.Background(), TimeOut)
	defer cancelF()
	inserted, err := revCache.Insert(ctx, rev)
	SoMsg("Insert should return true for a new entry", inserted, ShouldBeTrue)
	SoMsg("Insert a new entry should not err", err, ShouldBeNil)
	key1 := *revcache.NewKey(ia110, ifId15)
	revs, err := revCache.Get(ctx, revcache.KeySet{key1: {}})
	SoMsg("Get should not err for existing entry", err, ShouldBeNil)
	SoMsg("Get should return existing entry", revs, ShouldNotBeEmpty)
	SoMsg("Get should return previously inserted value", revs[key1], ShouldResemble, rev)
	inserted, err = revCache.Insert(ctx, rev)
	SoMsg("Insert should return false for already existing entry", inserted, ShouldBeFalse)
	SoMsg("Insert should not err", err, ShouldBeNil)
	revs, err = revCache.Get(ctx, revcache.SingleKey(ia110, ifId19))
	SoMsg("Get should not err", err, ShouldBeNil)
	SoMsg("Get should return empty result for not present value", revs, ShouldBeEmpty)
}

func testGetMultikey(t *testing.T, revCache TestableRevCache) {
	rev1 := defaultRevInfo(ia110, ifId15)
	rev2 := defaultRevInfo(ia110, ifId19)
	rev3 := defaultRevInfo(ia120, ifId15)
	rev4 := defaultRevInfo(ia120, common.IFIDType(10))
	ctx, cancelF := context.WithTimeout(context.Background(), TimeOut)
	defer cancelF()

	// First test the empty cache
	revs, err := revCache.Get(ctx, revcache.KeySet{})
	SoMsg("Get should not err", err, ShouldBeNil)
	SoMsg("Should return no revs", revs, ShouldBeEmpty)

	_, err = revCache.Insert(ctx, rev1)
	require.NoError(t, err)
	_, err = revCache.Insert(ctx, rev2)
	require.NoError(t, err)
	_, err = revCache.Insert(ctx, rev3)
	require.NoError(t, err)
	_, err = revCache.Insert(ctx, rev4)
	require.NoError(t, err)

	key1 := *revcache.NewKey(ia110, ifId15)
	revs, err = revCache.Get(ctx, revcache.KeySet{key1: {}})
	SoMsg("Get should not err", err, ShouldBeNil)
	SoMsg("Should contain one rev", 1, ShouldEqual, len(revs))
	SoMsg("Get should return revs for the given keys", revs, ShouldResemble,
		revcache.Revocations{key1: rev1})

	key2 := *revcache.NewKey(ia110, ifId19)
	key3 := *revcache.NewKey(ia120, ifId15)
	key4 := *revcache.NewKey(ia120, ifId19) // not the key of sr4
	searchKeys := revcache.KeySet{key1: {}, key2: {}, key3: {}, key4: {}}
	revs, err = revCache.Get(ctx, searchKeys)
	SoMsg("Get should not err", err, ShouldBeNil)
	expectedResult := revcache.Revocations{
		key1: rev1, key2: rev2, key3: rev3,
	}
	SoMsg("Get should return the requested revocations", revs, ShouldResemble,
		expectedResult)
}

func testGetAll(t *testing.T, revCache TestableRevCache) {
	ctx, cancelF := context.WithTimeout(context.Background(), TimeOut)
	defer cancelF()
	// Empty cache should return an empty chan
	resChan, err := revCache.GetAll(ctx)
	SoMsg("No error expected", err, ShouldBeNil)
	res, more := <-resChan
	SoMsg("No result expected", res, ShouldResemble, revcache.RevOrErr{})
	SoMsg("No more entries expected", more, ShouldBeFalse)

	// Insert some stuff and query again
	rev1 := defaultRevInfo(ia110, ifId15)
	rev2 := defaultRevInfo(ia110, ifId19)
	rev3 := defaultRevInfo(ia120, ifId15)
	rev4 := defaultRevInfo(ia120, common.IFIDType(20))
	_, err = revCache.Insert(ctx, rev1)
	require.NoError(t, err)
	_, err = revCache.Insert(ctx, rev2)
	require.NoError(t, err)
	_, err = revCache.Insert(ctx, rev3)
	require.NoError(t, err)
	_, err = revCache.Insert(ctx, rev4)
	require.NoError(t, err)

	expectedRevs := []*path_mgmt.RevInfo{rev1, rev2, rev3, rev4}

	resChan, err = revCache.GetAll(ctx)
	SoMsg("No error expected", err, ShouldBeNil)
	revs := make([]*path_mgmt.RevInfo, 0, len(expectedRevs))
	for res := range resChan {
		SoMsg("No error expected", res.Err, ShouldBeNil)
		SoMsg("Revocation expected", res.Rev, ShouldNotBeNil)
		revs = append(revs, res.Rev)
	}
	// we don't care about the order, so sort here to make sure the comparison always works.
	sort.Slice(revs, func(i, j int) bool {
		iInfo := revs[i]
		jInfo := revs[j]
		return iInfo.IA() < jInfo.IA() ||
			(iInfo.IA() == jInfo.IA() && iInfo.IfID < jInfo.IfID)
	})
	SoMsg("All revocations should have been returned", revs, ShouldResemble, expectedRevs)
}

func testGetAllExpired(t *testing.T, revCache TestableRevCache) {
	ctx, cancelF := context.WithTimeout(context.Background(), TimeOut)
	defer cancelF()
	// insert expired rev
	revNew := &path_mgmt.RevInfo{
		IfID:         ifId15,
		RawIsdas:     ia110,
		LinkType:     proto.LinkType_core,
		RawTimestamp: util.TimeToSecs(time.Now().Add(-2 * time.Second)),
		RawTTL:       1,
	}
	revCache.InsertExpired(t, ctx, revNew)
	// Now test that we don't get the expired rev
	resChan, err := revCache.GetAll(ctx)
	SoMsg("No error expected", err, ShouldBeNil)
	res, more := <-resChan
	SoMsg("No result expected", res, ShouldResemble, revcache.RevOrErr{})
	SoMsg("No more entries expected", more, ShouldBeFalse)
}

func testInsertExpired(t *testing.T, revCache TestableRevCache) {
	r := &path_mgmt.RevInfo{
		IfID:         ifId15,
		RawIsdas:     ia110,
		LinkType:     proto.LinkType_core,
		RawTimestamp: util.TimeToSecs(time.Now().Add(-15 * time.Second)),
		RawTTL:       uint32((time.Duration(10) * time.Second).Seconds()),
	}
	ctx, cancelF := context.WithTimeout(context.Background(), TimeOut)
	defer cancelF()
	inserted, err := revCache.Insert(ctx, r)
	SoMsg("Insert should return false for expired rev", inserted, ShouldBeFalse)
	SoMsg("Insert should not err", err, ShouldBeNil)
}

func testInsertNewer(t *testing.T, revCache TestableRevCache) {
	rev := defaultRevInfo(ia110, ifId15)
	ctx, cancelF := context.WithTimeout(context.Background(), TimeOut)
	defer cancelF()
	_, err := revCache.Insert(ctx, rev)
	require.NoError(t, err)
	revNew := &path_mgmt.RevInfo{
		IfID:         ifId15,
		RawIsdas:     ia110,
		LinkType:     proto.LinkType_core,
		RawTimestamp: util.TimeToSecs(time.Now().Add(10 * time.Second)),
		RawTTL:       uint32((time.Duration(10) * time.Second).Seconds()),
	}
	require.NoError(t, err)
	inserted, err := revCache.Insert(ctx, revNew)
	SoMsg("Insert should return true for a new entry", inserted, ShouldBeTrue)
	SoMsg("Insert a new entry should not err", err, ShouldBeNil)
	key1 := *revcache.NewKey(ia110, ifId15)
	revs, err := revCache.Get(ctx, revcache.KeySet{key1: {}})
	SoMsg("Get should not err for existing entry", err, ShouldBeNil)
	SoMsg("Get should return non empty map for inserted value", revs, ShouldNotBeEmpty)
	SoMsg("Get should return previously inserted value", revs[key1], ShouldResemble, revNew)
}

func testGetExpired(t *testing.T, revCache TestableRevCache) {
	ctx, cancelF := context.WithTimeout(context.Background(), TimeOut)
	defer cancelF()
	revNew := &path_mgmt.RevInfo{
		IfID:         ifId15,
		RawIsdas:     ia110,
		LinkType:     proto.LinkType_core,
		RawTimestamp: util.TimeToSecs(time.Now().Add(-2 * time.Second)),
		RawTTL:       1,
	}
	revCache.InsertExpired(t, ctx, revNew)
	revs, err := revCache.Get(ctx, revcache.SingleKey(ia110, ifId15))
	SoMsg("Expired entry should not be returned", revs, ShouldBeEmpty)
	SoMsg("Should not error for expired entry", err, ShouldBeNil)
}

func testGetMuliKeysExpired(t *testing.T, revCache TestableRevCache) {
	ctx, cancelF := context.WithTimeout(context.Background(), TimeOut)
	defer cancelF()
	revNew := &path_mgmt.RevInfo{
		IfID:         ifId15,
		RawIsdas:     ia110,
		LinkType:     proto.LinkType_core,
		RawTimestamp: util.TimeToSecs(time.Now().Add(-2 * time.Second)),
		RawTTL:       1,
	}
	revCache.InsertExpired(t, ctx, revNew)
	rev110_19 := defaultRevInfo(ia110, ifId19)
	_, err := revCache.Insert(ctx, rev110_19)
	assert.NoError(t, err)
	validKey := *revcache.NewKey(ia110, ifId19)
	srCache, err := revCache.Get(ctx, revcache.KeySet{
		*revcache.NewKey(ia110, ifId15): {},
		validKey:                        {},
	})
	SoMsg("Should not error for expired entry", err, ShouldBeNil)
	SoMsg("Expired entry should not be returned", srCache, ShouldResemble,
		revcache.Revocations{validKey: rev110_19})
}

func testDeleteExpired(t *testing.T, revCache TestableRevCache) {
	ctx, cancelF := context.WithTimeout(context.Background(), TimeOut)
	defer cancelF()
	del, err := revCache.DeleteExpired(ctx)
	SoMsg("DeleteExpired on empty should not error", err, ShouldBeNil)
	SoMsg("DeleteExpired on empty should delete 0", del, ShouldEqual, 0)
	rev110_19 := defaultRevInfo(ia110, ifId19)
	_, err = revCache.Insert(ctx, rev110_19)
	assert.NoError(t, err)
	del, err = revCache.DeleteExpired(ctx)
	SoMsg("DeleteExpired should not error", err, ShouldBeNil)
	SoMsg("DeleteExpired should delete 0 if entry is not expired", del, ShouldEqual, 0)
	revNew := &path_mgmt.RevInfo{
		IfID:         ifId15,
		RawIsdas:     ia110,
		LinkType:     proto.LinkType_core,
		RawTimestamp: util.TimeToSecs(time.Now().Add(-2 * time.Second)),
		RawTTL:       1,
	}
	revCache.InsertExpired(t, ctx, revNew)
	del, err = revCache.DeleteExpired(ctx)
	SoMsg("DeleteExpired should not error", err, ShouldBeNil)
	SoMsg("DeleteExpired should delete 1 if entry is expired", del, ShouldEqual, 1)
	del, err = revCache.DeleteExpired(ctx)
	SoMsg("DeleteExpired should not error", err, ShouldBeNil)
	SoMsg("DeleteExpired should delete 0 if entry is not expired", del, ShouldEqual, 0)
}

func defaultRevInfo(ia addr.IA, ifId common.IFIDType) *path_mgmt.RevInfo {
	return &path_mgmt.RevInfo{
		IfID:         ifId,
		RawIsdas:     ia,
		LinkType:     proto.LinkType_core,
		RawTimestamp: util.TimeToSecs(time.Now()),
		RawTTL:       uint32((time.Duration(10) * time.Second).Seconds()),
	}
}
