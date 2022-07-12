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

package dbtest

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/drkey/drkeytest"
)

const (
	timeOffset = 10 * 60 * time.Second // 10 minutes
	timeout    = 3 * time.Second
)

var (
	srcIA   = xtest.MustParseIA("1-ff00:0:111")
	dstIA   = xtest.MustParseIA("1-ff00:0:112")
	srcHost = "192.168.1.37"
	dstHost = "192.168.1.38"
)

type TestableDB interface {
	drkey.Level2DB
	Prepare(t *testing.T, ctx context.Context)
}

// Test should be used to test any implementation of the Level2DB interface. An
// implementation of the Level2DB interface should at least have one test
// method that calls this test-suite.
func TestDB(t *testing.T, db TestableDB) {
	prepareCtx, cancelF := context.WithTimeout(context.Background(), 2*timeout)
	db.Prepare(t, prepareCtx)
	cancelF()
	defer db.Close()
	testDRKeyLevel2(t, db)
}

func testDRKeyLevel2(t *testing.T, db drkey.Level2DB) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	epoch := drkey.Epoch{
		Validity: cppki.Validity{
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(timeOffset),
		},
	}
	protoId := drkey.Protocol(0)
	drkeyLevel1 := drkeytest.GetLevel1(t, protoId, epoch, srcIA, dstIA)

	// AS-Host
	as2HostMeta := drkey.ASHostMeta{
		ProtoId:  25,
		SrcIA:    srcIA,
		DstIA:    dstIA,
		Validity: time.Now(),
		DstHost:  dstHost,
	}
	asHostKey, err := drkeytest.DeriveASHostGeneric(as2HostMeta, drkeyLevel1)
	require.NoError(t, err)

	err = db.InsertASHostKey(ctx, asHostKey)
	assert.NoError(t, err)
	err = db.InsertASHostKey(ctx, asHostKey)
	assert.NoError(t, err)

	newKey, err := db.GetASHostKey(ctx, as2HostMeta)
	assert.NoError(t, err)
	assert.Equal(t, asHostKey.Key, newKey.Key)

	// Host-AS
	hostASMeta := drkey.HostASMeta{
		ProtoId:  25,
		SrcIA:    srcIA,
		DstIA:    dstIA,
		Validity: time.Now(),
		SrcHost:  srcHost,
	}
	hostASKey, err := drkeytest.DeriveHostASGeneric(hostASMeta, drkeyLevel1)
	require.NoError(t, err)

	err = db.InsertHostASKey(ctx, hostASKey)
	assert.NoError(t, err)
	err = db.InsertHostASKey(ctx, hostASKey)
	assert.NoError(t, err)

	newHostASKey, err := db.GetHostASKey(ctx, hostASMeta)
	assert.NoError(t, err)
	assert.Equal(t, hostASKey.Key, newHostASKey.Key)

	// Host-Host
	h2hMeta := drkey.HostHostMeta{
		ProtoId:  25,
		SrcIA:    srcIA,
		DstIA:    dstIA,
		Validity: time.Now(),
		SrcHost:  srcHost,
		DstHost:  dstHost,
	}
	h2hKey, err := drkeytest.DeriveHostHostGeneric(h2hMeta, drkeyLevel1)
	require.NoError(t, err)

	err = db.InsertHostHostKey(ctx, h2hKey)
	assert.NoError(t, err)
	err = db.InsertHostHostKey(ctx, h2hKey)
	assert.NoError(t, err)

	newh2hKey, err := db.GetHostHostKey(ctx, h2hMeta)
	assert.NoError(t, err)
	assert.Equal(t, h2hKey.Key, newh2hKey.Key)

	n, err := db.DeleteExpiredASHostKeys(ctx,
		time.Now().Add(2*timeOffset))
	assert.NoError(t, err)
	assert.Equal(t, 1, n)
	n, err = db.DeleteExpiredHostASKeys(ctx,
		time.Now().Add(2*timeOffset))
	assert.NoError(t, err)
	assert.Equal(t, 1, n)
	n, err = db.DeleteExpiredHostHostKeys(ctx,
		time.Now().Add(2*timeOffset))
	assert.NoError(t, err)
	assert.Equal(t, 1, n)

}
