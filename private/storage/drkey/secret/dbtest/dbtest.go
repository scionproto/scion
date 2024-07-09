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

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

const (
	timeOffset = 10 * 60 * time.Second // 10 minutes
	timeout    = 3 * time.Second
)

var (
	srcIA = addr.MustParseIA("1-ff00:0:111")
)

type TestableDB interface {
	drkey.SecretValueDB
	Prepare(t *testing.T, ctx context.Context)
}

// TestDB should be used to test any implementation of the SecretValueDB interface. An
// implementation of the SecretValueDB interface should at least have one test
// method that calls this test-suite.
func TestDB(t *testing.T, db TestableDB) {
	prepareCtx, cancelF := context.WithTimeout(context.Background(), 2*timeout)
	db.Prepare(t, prepareCtx)
	cancelF()
	defer db.Close()
	testDB(t, db)
}

func testDB(t *testing.T, db drkey.SecretValueDB) {
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()

	epoch := drkey.Epoch{
		Validity: cppki.Validity{
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(timeOffset),
		},
	}
	asSecret := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	asSecret = append(asSecret, byte(srcIA))
	sv, err := drkey.DeriveSV(drkey.Protocol(0), epoch, asSecret)
	require.NoError(t, err)

	err = db.InsertValue(ctx, sv.ProtoId, sv.Epoch)
	assert.NoError(t, err)
	// same key again. It should be okay.
	err = db.InsertValue(ctx, sv.ProtoId, sv.Epoch)
	assert.NoError(t, err)
	newSecretValue, err := db.GetValue(ctx, drkey.SecretValueMeta{
		ProtoId:  drkey.Protocol(0),
		Validity: time.Now(),
	},
		asSecret,
	)
	assert.NoError(t, err)
	assert.EqualValues(t, sv.Key, newSecretValue.Key)

	rows, err := db.DeleteExpiredValues(ctx,
		time.Now().Add(-timeOffset))
	assert.NoError(t, err)
	assert.EqualValues(t, 0, rows)

	rows, err = db.DeleteExpiredValues(ctx,
		time.Now().Add(2*timeOffset))
	assert.NoError(t, err)
	assert.EqualValues(t, 1, rows)
}
