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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt/proto"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/private/revcache"
)

var (
	ia110  = addr.MustParseIA("1-ff00:0:110")
	ia120  = addr.MustParseIA("1-ff00:0:120")
	ifID15 = iface.ID(15)
	ifID19 = iface.ID(19)

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
	subtest := func(name string, test func(*testing.T, TestableRevCache)) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			prepareCtx, cancelF := context.WithTimeout(context.Background(), TimeOut)
			defer cancelF()
			revCache.Prepare(t, prepareCtx)
			test(t, revCache)
		})
	}

	subtest("InsertGet", testInsertGet)
	subtest("GetMultikey", testGetMultikey)
	subtest("GetAll", testGetAll)
	subtest("GetAllExpired", testGetAllExpired)
	subtest("InsertExpired", testInsertExpired)
	subtest("InsertNewer", testInsertNewer)
	subtest("GetExpired", testGetExpired)
	subtest("GetMultikeyExpired", testGetMuliKeysExpired)
	subtest("DeleteExpired", testDeleteExpired)
}

func testInsertGet(t *testing.T, revCache TestableRevCache) {
	rev := defaultRevInfo(ia110, ifID15)
	ctx, cancelF := context.WithTimeout(context.Background(), TimeOut)
	defer cancelF()
	inserted, err := revCache.Insert(ctx, rev)
	assert.True(t, inserted, "Insert should return true for a new entry")
	assert.NoError(t, err, "Insert a new entry should not err")
	key1 := revcache.NewKey(ia110, ifID15)
	aRev, err := revCache.Get(ctx, key1)
	assert.NoError(t, err, "Get should not err for existing entry")
	assert.Equal(t, rev, aRev, "Get should return previously inserted value")
	inserted, err = revCache.Insert(ctx, rev)
	assert.False(t, inserted, "Insert should return false for already existing entry")
	assert.NoError(t, err, "Insert should not err")
	aRev, err = revCache.Get(ctx, revcache.NewKey(ia110, ifID19))
	assert.NoError(t, err, "Get should not err")
	assert.Nil(t, aRev, "Get should return empty result for not present value")
}

func testGetMultikey(t *testing.T, revCache TestableRevCache) {
	rev1 := defaultRevInfo(ia110, ifID15)
	rev2 := defaultRevInfo(ia110, ifID19)
	rev3 := defaultRevInfo(ia120, ifID15)
	rev4 := defaultRevInfo(ia120, iface.ID(10))
	ctx, cancelF := context.WithTimeout(context.Background(), TimeOut)
	defer cancelF()

	_, err := revCache.Insert(ctx, rev1)
	require.NoError(t, err)
	_, err = revCache.Insert(ctx, rev2)
	require.NoError(t, err)
	_, err = revCache.Insert(ctx, rev3)
	require.NoError(t, err)
	_, err = revCache.Insert(ctx, rev4)
	require.NoError(t, err)

	key1 := revcache.NewKey(ia110, ifID15)
	aRev1, err := revCache.Get(ctx, key1)
	assert.NoError(t, err, "Get should not err")
	assert.Equal(t, rev1, aRev1, "Get should return rev for the given keys")

	key2 := revcache.NewKey(ia110, ifID19)
	key3 := revcache.NewKey(ia120, ifID15)
	key4 := revcache.NewKey(ia120, ifID19) // not the key of sr4
	searchKeys := map[revcache.Key]*path_mgmt.RevInfo{key1: rev1, key2: rev2, key3: rev3, key4: nil}
	for key, eRev := range searchKeys {
		aRev, err := revCache.Get(ctx, key)
		assert.NoError(t, err, "Get should not err")
		assert.Equal(t, eRev, aRev, "Get should return the requested revocation for key %s", key)
	}
}

func testGetAll(t *testing.T, revCache TestableRevCache) {
	ctx, cancelF := context.WithTimeout(context.Background(), TimeOut)
	defer cancelF()
	// Empty cache should return an empty chan
	resChan, err := revCache.GetAll(ctx)
	assert.NoError(t, err)
	res, more := <-resChan
	assert.Equal(t, revcache.RevOrErr{}, res, "No result expected")
	assert.False(t, more, "No more entries expected")

	// Insert some stuff and query again
	rev1 := defaultRevInfo(ia110, ifID15)
	rev2 := defaultRevInfo(ia110, ifID19)
	rev3 := defaultRevInfo(ia120, ifID15)
	rev4 := defaultRevInfo(ia120, iface.ID(20))
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
	assert.NoError(t, err)
	revs := make([]*path_mgmt.RevInfo, 0, len(expectedRevs))
	for res := range resChan {
		assert.NoError(t, res.Err)
		assert.NotNil(t, res.Rev, "Revocation expected")
		revs = append(revs, res.Rev)
	}
	// we don't care about the order, so sort here to make sure the comparison always works.
	sort.Slice(revs, func(i, j int) bool {
		iInfo := revs[i]
		jInfo := revs[j]
		return iInfo.IA() < jInfo.IA() ||
			(iInfo.IA() == jInfo.IA() && iInfo.IfID < jInfo.IfID)
	})
	assert.Equal(t, expectedRevs, revs, "All revocations should have been returned")
}

func testGetAllExpired(t *testing.T, revCache TestableRevCache) {
	ctx, cancelF := context.WithTimeout(context.Background(), TimeOut)
	defer cancelF()
	// insert expired rev
	revNew := &path_mgmt.RevInfo{
		IfID:         ifID15,
		RawIsdas:     ia110,
		LinkType:     proto.LinkType_core,
		RawTimestamp: util.TimeToSecs(time.Now().Add(-2 * time.Second)),
		RawTTL:       1,
	}
	revCache.InsertExpired(t, ctx, revNew)
	// Now test that we don't get the expired rev
	resChan, err := revCache.GetAll(ctx)
	assert.NoError(t, err)
	res, more := <-resChan
	assert.Equal(t, revcache.RevOrErr{}, res, "No result expected")
	assert.False(t, more, "No more entries expected")
}

func testInsertExpired(t *testing.T, revCache TestableRevCache) {
	r := &path_mgmt.RevInfo{
		IfID:         ifID15,
		RawIsdas:     ia110,
		LinkType:     proto.LinkType_core,
		RawTimestamp: util.TimeToSecs(time.Now().Add(-15 * time.Second)),
		RawTTL:       uint32((time.Duration(10) * time.Second).Seconds()),
	}
	ctx, cancelF := context.WithTimeout(context.Background(), TimeOut)
	defer cancelF()
	inserted, err := revCache.Insert(ctx, r)
	assert.False(t, inserted, "Insert should return false for expired rev")
	assert.NoError(t, err, "Insert should not err")
}

func testInsertNewer(t *testing.T, revCache TestableRevCache) {
	rev := defaultRevInfo(ia110, ifID15)
	ctx, cancelF := context.WithTimeout(context.Background(), TimeOut)
	defer cancelF()
	_, err := revCache.Insert(ctx, rev)
	require.NoError(t, err)
	revNew := &path_mgmt.RevInfo{
		IfID:         ifID15,
		RawIsdas:     ia110,
		LinkType:     proto.LinkType_core,
		RawTimestamp: util.TimeToSecs(time.Now().Add(10 * time.Second)),
		RawTTL:       uint32((time.Duration(10) * time.Second).Seconds()),
	}
	require.NoError(t, err)
	inserted, err := revCache.Insert(ctx, revNew)
	assert.True(t, inserted, "Insert should return true for a new entry")
	assert.NoError(t, err, "Insert a new entry should not err")
	key1 := revcache.NewKey(ia110, ifID15)
	aRev, err := revCache.Get(ctx, key1)
	assert.NoError(t, err, "Get should not err for existing entry")
	assert.Equal(t, revNew, aRev, "Get should return previously inserted value")
}

func testGetExpired(t *testing.T, revCache TestableRevCache) {
	ctx, cancelF := context.WithTimeout(context.Background(), TimeOut)
	defer cancelF()
	revNew := &path_mgmt.RevInfo{
		IfID:         ifID15,
		RawIsdas:     ia110,
		LinkType:     proto.LinkType_core,
		RawTimestamp: util.TimeToSecs(time.Now().Add(-2 * time.Second)),
		RawTTL:       1,
	}
	revCache.InsertExpired(t, ctx, revNew)
	aRev, err := revCache.Get(ctx, revcache.NewKey(ia110, ifID15))
	assert.Nil(t, aRev, "Expired entry should not be returned")
	assert.NoError(t, err, "Should not error for expired entry")
}

func testGetMuliKeysExpired(t *testing.T, revCache TestableRevCache) {
	ctx, cancelF := context.WithTimeout(context.Background(), TimeOut)
	defer cancelF()
	revNew := &path_mgmt.RevInfo{
		IfID:         ifID15,
		RawIsdas:     ia110,
		LinkType:     proto.LinkType_core,
		RawTimestamp: util.TimeToSecs(time.Now().Add(-2 * time.Second)),
		RawTTL:       1,
	}
	revCache.InsertExpired(t, ctx, revNew)
	rev110_19 := defaultRevInfo(ia110, ifID19)
	_, err := revCache.Insert(ctx, rev110_19)
	assert.NoError(t, err)
	validKey := revcache.NewKey(ia110, ifID19)
	aRev, err := revCache.Get(ctx, validKey)
	assert.NoError(t, err, "Should not error for valid entry")
	assert.Equal(t, rev110_19, aRev, "Valid entry should be returned")
	aRev, err = revCache.Get(ctx, revcache.NewKey(ia110, ifID15))
	assert.Nil(t, aRev, "Expired entry should not be returned")
	assert.NoError(t, err, "Should not error for expired entry")
}

func testDeleteExpired(t *testing.T, revCache TestableRevCache) {
	ctx, cancelF := context.WithTimeout(context.Background(), TimeOut)
	defer cancelF()
	del, err := revCache.DeleteExpired(ctx)
	assert.NoError(t, err, "DeleteExpired on empty should not error")
	assert.EqualValues(t, 0, del, "DeleteExpired on empty should delete 0")
	rev110_19 := defaultRevInfo(ia110, ifID19)
	_, err = revCache.Insert(ctx, rev110_19)
	assert.NoError(t, err)
	del, err = revCache.DeleteExpired(ctx)
	assert.NoError(t, err, "DeleteExpired should not error")
	assert.EqualValues(t, 0, del, "DeleteExpired should delete 0 if entry is not expired")
	revNew := &path_mgmt.RevInfo{
		IfID:         ifID15,
		RawIsdas:     ia110,
		LinkType:     proto.LinkType_core,
		RawTimestamp: util.TimeToSecs(time.Now().Add(-2 * time.Second)),
		RawTTL:       1,
	}
	revCache.InsertExpired(t, ctx, revNew)
	del, err = revCache.DeleteExpired(ctx)
	assert.NoError(t, err, "DeleteExpired should not error")
	assert.EqualValues(t, 1, del, "DeleteExpired should delete 1 if entry is expired")
	del, err = revCache.DeleteExpired(ctx)
	assert.NoError(t, err, "DeleteExpired should not error")
	assert.EqualValues(t, 0, del, "DeleteExpired should delete 0 if entry is not expired")
}

func defaultRevInfo(ia addr.IA, ifID iface.ID) *path_mgmt.RevInfo {
	return &path_mgmt.RevInfo{
		IfID:         ifID,
		RawIsdas:     ia,
		LinkType:     proto.LinkType_core,
		RawTimestamp: util.TimeToSecs(time.Now()),
		RawTTL:       uint32((time.Duration(10) * time.Second).Seconds()),
	}
}
