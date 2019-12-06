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

package trustdbtest

import (
	"context"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2/internal/decoded"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	Timeout         = time.Second
	TestDataRelPath = "../trustdbtest/testdata"
)

// TestableTrustDB extends the trust db interface with methods that are needed for testing.
type TestableTrustDB interface {
	trust.DB
	// Prepare should reset the internal state so that the db is empty and is ready to be tested.
	Prepare(*testing.T, context.Context)
}

// TestTrustDB should be used to test any implementation of the trust.DB
// interface. An implementation interface should at least have on test method
// that calls this test-suite.
//
// Prepare should return a trust database in a clean state, i.e. no entries in the
// DB.
func TestTrustDB(t *testing.T, db TestableTrustDB) {
	tests := map[string]func(*testing.T, trust.ReadWrite){
		"test TRC":   testTRC,
		"test chain": testChain,
	}
	// Run test suite on DB directly.
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancelF := context.WithTimeout(context.Background(), Timeout)
			defer cancelF()
			db.Prepare(t, ctx)
			test(t, db)
		})
	}
	t.Run("test rollback", func(t *testing.T) {
		ctx, cancelF := context.WithTimeout(context.Background(), Timeout)
		defer cancelF()
		db.Prepare(t, ctx)
		testRollback(t, db)
	})
	// Run test suite on transaction.
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancelF := context.WithTimeout(context.Background(), Timeout)
			defer cancelF()
			db.Prepare(t, ctx)
			tx, err := db.BeginTransaction(ctx, nil)
			require.NoError(t, err)
			test(t, tx)
			err = tx.Commit()
			require.NoError(t, err)
		})
	}

}

func testTRC(t *testing.T, db trust.ReadWrite) {
	ctx, cancelF := context.WithTimeout(context.Background(), Timeout)
	defer cancelF()
	dec, err := decoded.DecodeTRC(loadFile(t, "ISD1-V1.trc"))
	require.NoError(t, err)
	inserted, err := db.InsertTRC(ctx, dec)
	assert.NoError(t, err)
	assert.True(t, inserted)
	t.Run("TRCExists", func(t *testing.T) {
		other, err := decoded.DecodeTRC(loadFile(t, "ISD2-V1.trc"))
		require.NoError(t, err)
		// Check existing TRC.
		exists, err := db.TRCExists(ctx, dec)
		assert.NoError(t, err)
		assert.True(t, exists)
		// Check inexistent TRC.
		exists, err = db.TRCExists(ctx, other)
		assert.NoError(t, err)
		assert.False(t, exists)
		// Check existing TRC with different content.
		mismatch := dec
		mismatch.Signed.EncodedTRC = []byte("some garbage")
		exists, err = db.TRCExists(ctx, mismatch)
		xtest.AssertErrorsIs(t, err, trust.ErrContentMismatch)
		assert.True(t, exists)
	})
	t.Run("GetTRC", func(t *testing.T) {
		// Fetch existing TRC.
		fetched, err := db.GetTRC(ctx, dec.TRC.ISD, dec.TRC.Version)
		assert.NoError(t, err)
		assert.Equal(t, dec.TRC, fetched)
		// Fetch max of existing TRC.
		max, err := db.GetTRC(ctx, dec.TRC.ISD, scrypto.LatestVer)
		assert.NoError(t, err)
		assert.Equal(t, dec.TRC, max)
		// Fetch inexistent TRC.
		_, err = db.GetTRC(ctx, 42, scrypto.LatestVer)
		xtest.AssertErrorsIs(t, err, trust.ErrNotFound)
	})
	t.Run("GetRawTRC", func(t *testing.T) {
		// Fetch existing TRC.
		fetched, err := db.GetRawTRC(ctx, dec.TRC.ISD, dec.TRC.Version)
		assert.NoError(t, err)
		assert.Equal(t, dec.Raw, fetched)
		// Fetch max of existing TRC.
		max, err := db.GetRawTRC(ctx, dec.TRC.ISD, scrypto.LatestVer)
		assert.NoError(t, err)
		assert.Equal(t, dec.Raw, max)
		// Fetch inexistent TRC.
		_, err = db.GetRawTRC(ctx, 42, scrypto.LatestVer)
		xtest.AssertErrorsIs(t, err, trust.ErrNotFound)
	})
	t.Run("GetTRCInfo", func(t *testing.T) {
		info := trust.TRCInfo{
			Validity:    *dec.TRC.Validity,
			GracePeriod: dec.TRC.GracePeriod.Duration,
			Version:     dec.TRC.Version,
		}
		// Fetch existing TRC.
		fetched, err := db.GetTRCInfo(ctx, dec.TRC.ISD, dec.TRC.Version)
		assert.NoError(t, err)
		assert.Equal(t, info, fetched)
		// Fetch max of existing TRC.
		max, err := db.GetTRCInfo(ctx, dec.TRC.ISD, scrypto.LatestVer)
		assert.NoError(t, err)
		assert.Equal(t, info, max)
		// Fetch inexistent TRC.
		_, err = db.GetTRCInfo(ctx, 42, scrypto.LatestVer)
		xtest.AssertErrorsIs(t, err, trust.ErrNotFound)
	})
	t.Run("InsertTRC", func(t *testing.T) {
		// Insert existing TRC.
		inserted, err = db.InsertTRC(ctx, dec)
		assert.NoError(t, err)
		assert.False(t, inserted)
		// Insert existing TRC with different contents.
		mismatch := dec
		mismatch.Signed.EncodedTRC = []byte("some garbage")
		inserted, err = db.InsertTRC(ctx, mismatch)
		xtest.AssertErrorsIs(t, err, trust.ErrContentMismatch)
		assert.False(t, inserted)
	})
}

func testChain(t *testing.T, db trust.ReadWrite) {
	ctx, cancelF := context.WithTimeout(context.Background(), Timeout)
	defer cancelF()
	dec, err := decoded.DecodeChain(loadFile(t, "ISD1-ASff00_0_110-V1.crt"))
	require.NoError(t, err)
	asInserted, issInserted, err := db.InsertChain(ctx, dec)
	assert.NoError(t, err)
	assert.True(t, asInserted)
	assert.True(t, issInserted)
	t.Run("ChainExists", func(t *testing.T) {
		other, err := decoded.DecodeChain(loadFile(t, "ISD1-ASff00_0_111-V1.crt"))
		require.NoError(t, err)

		// Check existing certificate chain.
		exists, err := db.ChainExists(ctx, dec)
		assert.NoError(t, err)
		assert.True(t, exists)
		// Check inexistent certificate chain.
		exists, err = db.ChainExists(ctx, other)
		assert.NoError(t, err)
		assert.False(t, exists)
		// Check existing certificate chain with different content in AS certificate.
		mismatch := dec
		mismatch.Chain.AS.Encoded = []byte("some garbage")
		exists, err = db.ChainExists(ctx, mismatch)
		xtest.AssertErrorsIs(t, err, trust.ErrContentMismatch)
		assert.False(t, exists)
		// Check existing certificate chain with different content in issuer certificate.
		mismatch = dec
		mismatch.Chain.Issuer.Encoded = []byte("some garbage")
		exists, err = db.ChainExists(ctx, mismatch)
		xtest.AssertErrorsIs(t, err, trust.ErrContentMismatch)
		assert.False(t, exists)
	})
	t.Run("GetRawChain", func(t *testing.T) {
		// Check existing certificate chain.
		fetched, err := db.GetRawChain(ctx, dec.AS.Subject, dec.AS.Version)
		assert.NoError(t, err)
		assert.Equal(t, dec.Raw, fetched)
		// Check max of existing certificate chain.
		max, err := db.GetRawChain(ctx, dec.AS.Subject, scrypto.LatestVer)
		assert.NoError(t, err)
		assert.Equal(t, dec.Raw, max)
		// Check inexistent certificate chain.
		_, err = db.GetRawChain(ctx, xtest.MustParseIA("42-ff00:0:142"), scrypto.LatestVer)
		xtest.AssertErrorsIs(t, err, trust.ErrNotFound)
	})
	t.Run("InsertChain", func(t *testing.T) {
		other, err := decoded.DecodeChain(loadFile(t, "ISD1-ASff00_0_111-V1.crt"))
		require.NoError(t, err)
		// Check inexistent certificate chain with existing issuer certifcate.
		asInserted, issInserted, err := db.InsertChain(ctx, other)
		assert.NoError(t, err)
		assert.True(t, asInserted)
		assert.False(t, issInserted)
		// Check existing certificate chain.
		asInserted, issInserted, err = db.InsertChain(ctx, dec)
		assert.NoError(t, err)
		assert.False(t, asInserted)
		assert.False(t, issInserted)
		// Check existing certificate chain with different content in AS certificate.
		mismatch := dec
		mismatch.Chain.AS.Encoded = []byte("some garbage")
		asInserted, issInserted, err = db.InsertChain(ctx, mismatch)
		xtest.AssertErrorsIs(t, err, trust.ErrContentMismatch)
		assert.False(t, asInserted)
		assert.False(t, issInserted)
		// Check existing certificate chain with different content in AS certificate.
		mismatch = dec
		mismatch.Chain.Issuer.Encoded = []byte("some garbage")
		asInserted, issInserted, err = db.InsertChain(ctx, mismatch)
		xtest.AssertErrorsIs(t, err, trust.ErrContentMismatch)
		assert.False(t, asInserted)
		assert.False(t, issInserted)
	})
}

func testRollback(t *testing.T, db trust.DB) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	tx, err := db.BeginTransaction(ctx, nil)
	require.NoError(t, err)

	trcobj, err := decoded.DecodeTRC(loadFile(t, "ISD1-V1.trc"))
	require.NoError(t, err)
	inserted, err := tx.InsertTRC(ctx, trcobj)
	assert.NoError(t, err)
	assert.True(t, inserted)
	err = tx.Rollback()
	assert.NoError(t, err)
	// Check that TRC is not in database after rollback.
	_, err = db.GetTRCInfo(ctx, 1, scrypto.LatestVer)
	xtest.AssertErrorsIs(t, err, trust.ErrNotFound)
}

func loadFile(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := ioutil.ReadFile(filePath(name))
	require.NoError(t, err)
	return raw
}

func filePath(fName string) string {
	return fmt.Sprintf("%s/%s", strings.TrimSuffix(TestDataRelPath, "/"), fName)
}
