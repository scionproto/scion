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

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/private/drkey/drkeytest"
)

const (
	timeOffset = 10 * 60 * time.Second // 10 minutes
	timeout    = 3 * time.Second
)

var (
	srcIA = addr.MustParseIA("1-ff00:0:111")
	dstIA = addr.MustParseIA("1-ff00:0:112")
)

type TestableDB interface {
	drkey.Level1DB
	Prepare(t *testing.T, ctx context.Context)
}

// Test should be used to test any implementation of the Level1DB interface. An
// implementation of the Level1DB interface should at least have one test
// method that calls this test-suite.
func TestDB(t *testing.T, db TestableDB) {
	prepareCtx, cancelF := context.WithTimeout(context.Background(), 2*timeout)
	db.Prepare(t, prepareCtx)
	cancelF()
	defer db.Close()
	testDRKeyLevel1(t, db)
}

func testDRKeyLevel1(t *testing.T, db drkey.Level1DB) {
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()

	epoch := drkey.Epoch{
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(timeOffset),
	}
	protoId := drkey.Protocol(0)
	drkeyLevel1 := drkeytest.GetLevel1(t, protoId, epoch, srcIA, dstIA)

	lvl1Meta := drkey.Level1Meta{
		Validity: time.Now(),
		ProtoId:  protoId,
		SrcIA:    srcIA,
		DstIA:    dstIA,
	}

	err := db.InsertLevel1Key(ctx, drkeyLevel1)
	assert.NoError(t, err)
	// same key again. It should be okay.
	err = db.InsertLevel1Key(ctx, drkeyLevel1)
	assert.NoError(t, err)

	newKey, err := db.GetLevel1Key(ctx, lvl1Meta)
	assert.NoError(t, err)
	assert.Equal(t, drkeyLevel1.Key, newKey.Key)

	rows, err := db.DeleteExpiredLevel1Keys(ctx,
		time.Now().Add(-timeOffset))
	assert.NoError(t, err)
	assert.EqualValues(t, 0, rows)

	rows, err = db.DeleteExpiredLevel1Keys(ctx,
		time.Now().Add(2*timeOffset))
	assert.NoError(t, err)
	assert.EqualValues(t, 1, rows)

}
