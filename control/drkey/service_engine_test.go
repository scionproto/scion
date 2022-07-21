// Copyright 2022 ETH Zurich
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

package drkey_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cs_drkey "github.com/scionproto/scion/control/drkey"
	"github.com/scionproto/scion/control/drkey/mock_drkey"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/private/xtest"
	level1_sql "github.com/scionproto/scion/private/storage/drkey/level1/sqlite"
	secret_sql "github.com/scionproto/scion/private/storage/drkey/secret/sqlite"
)

var (
	masterKey = xtest.MustParseHexString("305554050357005ae398259bcdae7468")
	srcIA     = xtest.MustParseIA("1-ff00:0:112")
	dstIA     = xtest.MustParseIA("1-ff00:0:111")
)

func TestGetSV(t *testing.T) {
	svdb := newSVDatabase(t)
	defer svdb.Close()
	list, err := cs_drkey.NewLevel1ARC(10)
	require.NoError(t, err)

	store := &cs_drkey.ServiceEngine{
		SecretBackend:  cs_drkey.NewSecretValueBackend(svdb, masterKey, time.Minute),
		LocalIA:        srcIA,
		PrefetchKeeper: list,
	}

	// We check that we retrieve the same SV within the same epoch [0,1) minute and a
	// a different one, with high-probability for the next epoch.
	meta := drkey.SecretValueMeta{
		ProtoId:  drkey.Generic,
		Validity: util.SecsToTime(0).UTC(),
	}
	rcvKey1, err := store.GetSecretValue(context.Background(), meta)
	assert.NoError(t, err)
	meta.Validity = util.SecsToTime(1).UTC()
	rcvKey2, err := store.GetSecretValue(context.Background(), meta)
	assert.NoError(t, err)
	assert.EqualValues(t, rcvKey1, rcvKey2)
	meta.Validity = util.SecsToTime(61).UTC()
	rcvKey3, err := store.GetSecretValue(context.Background(), meta)
	assert.NoError(t, err)
	assert.NotEqualValues(t, rcvKey1, rcvKey3)
}

func TestDeriveLevel1Key(t *testing.T) {
	svdb := newSVDatabase(t)
	defer svdb.Close()
	list, err := cs_drkey.NewLevel1ARC(10)
	require.NoError(t, err)

	store := &cs_drkey.ServiceEngine{
		SecretBackend:  cs_drkey.NewSecretValueBackend(svdb, masterKey, time.Minute),
		LocalIA:        srcIA,
		PrefetchKeeper: list,
	}

	meta := drkey.Level1Meta{
		DstIA:    dstIA,
		ProtoId:  drkey.Protocol(0),
		Validity: time.Now(),
	}

	key, err := store.DeriveLevel1(meta)
	assert.NoError(t, err)
	assert.Equal(t, meta.DstIA, key.DstIA)
	assert.Equal(t, meta.ProtoId, key.ProtoId)
	assert.WithinDuration(t, key.Epoch.NotBefore, meta.Validity, time.Minute)
}

func TestGetLevel1Key(t *testing.T) {
	svdb := newSVDatabase(t)
	defer svdb.Close()
	lvl1db := newLevel1Database(t)
	defer lvl1db.Close()
	k := xtest.MustParseHexString("c584cad32613547c64823c756651b6f5") // just a level 1 key

	firstLevel1Key := drkey.Level1Key{
		Epoch:   drkey.NewEpoch(0, 2),
		SrcIA:   srcIA,
		DstIA:   dstIA,
		ProtoId: drkey.Generic,
	}
	copy(firstLevel1Key.Key[:], k)
	secondLevel1Key := drkey.Level1Key{
		Epoch:   drkey.NewEpoch(2, 4),
		SrcIA:   srcIA,
		DstIA:   dstIA,
		ProtoId: drkey.Generic,
	}
	copy(secondLevel1Key.Key[:], k)

	mctrl := gomock.NewController(t)
	defer mctrl.Finish()

	fetcher := mock_drkey.NewMockFetcher(mctrl)
	gomock.InOrder(
		fetcher.EXPECT().Level1(gomock.Any(), gomock.Any()).
			Return(firstLevel1Key, nil),
		fetcher.EXPECT().Level1(gomock.Any(), gomock.Any()).
			Return(secondLevel1Key, nil),
		fetcher.EXPECT().Level1(gomock.Any(), gomock.Any()).
			Return(drkey.Level1Key{}, serrors.New("error retrieving key")),
	)

	cache := mock_drkey.NewMockLevel1PrefetchListKeeper(mctrl)
	// It must be called exactly 3 times
	cache.EXPECT().Update(gomock.Any()).Times(3)

	store := &cs_drkey.ServiceEngine{
		SecretBackend:  cs_drkey.NewSecretValueBackend(svdb, masterKey, time.Minute),
		LocalIA:        dstIA,
		DB:             lvl1db,
		Fetcher:        fetcher,
		PrefetchKeeper: cache,
	}

	// it must fetch first key from remote
	rcvKey1, err := store.GetLevel1Key(context.Background(), drkey.Level1Meta{
		ProtoId:  firstLevel1Key.ProtoId,
		DstIA:    firstLevel1Key.DstIA,
		SrcIA:    firstLevel1Key.SrcIA,
		Validity: util.SecsToTime(0).UTC(),
	})
	assert.NoError(t, err)
	assert.Equal(t, firstLevel1Key, rcvKey1)
	// it must not fetch key from remote and return previous key
	rcvKey2, err := store.GetLevel1Key(context.Background(), drkey.Level1Meta{
		ProtoId:  firstLevel1Key.ProtoId,
		DstIA:    firstLevel1Key.DstIA,
		SrcIA:    firstLevel1Key.SrcIA,
		Validity: util.SecsToTime(1).UTC(),
	})
	assert.NoError(t, err)
	assert.Equal(t, firstLevel1Key, rcvKey2)
	// it must fetch second key from remote
	rcvKey3, err := store.GetLevel1Key(context.Background(), drkey.Level1Meta{
		ProtoId:  firstLevel1Key.ProtoId,
		DstIA:    firstLevel1Key.DstIA,
		SrcIA:    firstLevel1Key.SrcIA,
		Validity: util.SecsToTime(3).UTC(),
	})
	assert.NoError(t, err)
	assert.Equal(t, secondLevel1Key, rcvKey3)
	//Simulate a call coming from the prefetcher, it must not update cache
	pref_ctx := context.WithValue(context.Background(), cs_drkey.FromPrefetcher(), true)
	rcvKey4, err := store.GetLevel1Key(pref_ctx, drkey.Level1Meta{
		ProtoId:  firstLevel1Key.ProtoId,
		DstIA:    firstLevel1Key.DstIA,
		SrcIA:    firstLevel1Key.SrcIA,
		Validity: util.SecsToTime(3).UTC(),
	})
	assert.NoError(t, err)
	assert.Equal(t, secondLevel1Key, rcvKey4)
	// This call returns an error, hence the cache must not be updated
	_, err = store.GetLevel1Key(context.Background(), drkey.Level1Meta{
		ProtoId:  firstLevel1Key.ProtoId,
		DstIA:    firstLevel1Key.DstIA,
		SrcIA:    firstLevel1Key.SrcIA,
		Validity: util.SecsToTime(5).UTC(),
	})
	assert.Error(t, err)
	// Requesting local key should not update the cache
	locallvl1Meta := drkey.Level1Meta{
		SrcIA:    dstIA,
		DstIA:    xtest.MustParseIA("1-ff00:0:111"),
		ProtoId:  drkey.Generic,
		Validity: util.SecsToTime(1).UTC(),
	}
	_, err = store.GetLevel1Key(context.Background(), locallvl1Meta)
	assert.NoError(t, err)

}

func newLevel1Database(t *testing.T) *level1_sql.Backend {
	db, err := level1_sql.NewBackend("file::memory:")
	require.NoError(t, err)

	return db
}

func newSVDatabase(t *testing.T) *secret_sql.Backend {
	db, err := secret_sql.NewBackend("file::memory:")
	require.NoError(t, err)

	return db
}
