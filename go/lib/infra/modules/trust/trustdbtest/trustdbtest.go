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
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/decoded"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	// DefaultTimeout is the default timeout for running the test harness.
	DefaultTimeout = time.Second
	// DefaultRelPath is the default relative path to the test data.
	DefaultRelPath = "../trustdbtest/testdata"
)

// Config holds the configuration for the trust database testing harness.
type Config struct {
	Timeout time.Duration
	RelPath string
}

// InitDefaults initializes the default values for the config.
func (cfg *Config) InitDefaults() {
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.RelPath == "" {
		cfg.RelPath = DefaultRelPath
	}
}

func (cfg *Config) filePath(name string) string {
	return filepath.Join(cfg.RelPath, name)
}

// TestableDB extends the trust db interface with methods that are needed for testing.
type TestableDB interface {
	trust.DB
	// Prepare should reset the internal state so that the db is empty and is ready to be tested.
	Prepare(*testing.T, context.Context)
}

// TestDB should be used to test any implementation of the trust.DB interface.
// An implementation interface should at least have one test method that calls
// this test-suite.
func TestDB(t *testing.T, db TestableDB, cfg Config) {
	cfg.InitDefaults()
	tests := map[string]func(*testing.T, trust.ReadWrite, Config){
		"test TRC":   testTRC,
		"test chain": testChain,
	}
	// Run test suite on DB directly.
	for name, test := range tests {
		t.Run("DB: "+name, func(t *testing.T) {
			ctx, cancelF := context.WithTimeout(context.Background(), cfg.Timeout)
			defer cancelF()
			db.Prepare(t, ctx)
			test(t, db, cfg)
		})
	}
	t.Run("DB: test rollback", func(t *testing.T) {
		ctx, cancelF := context.WithTimeout(context.Background(), cfg.Timeout)
		defer cancelF()
		db.Prepare(t, ctx)
		testRollback(t, db, cfg)
	})
	// Run test suite on transaction.
	for name, test := range tests {
		t.Run("TX: "+name, func(t *testing.T) {
			ctx, cancelF := context.WithTimeout(context.Background(), cfg.Timeout)
			defer cancelF()
			db.Prepare(t, ctx)
			tx, err := db.BeginTransaction(ctx, nil)
			require.NoError(t, err)
			test(t, tx, cfg)
			err = tx.Commit()
			require.NoError(t, err)
		})
	}
}

func testTRC(t *testing.T, db trust.ReadWrite, cfg Config) {
	ctx, cancelF := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancelF()
	insert := func(name string) decoded.TRC {
		dec, err := decoded.DecodeTRC(loadFile(t, cfg.filePath(name)))
		require.NoError(t, err)
		inserted, err := db.InsertTRC(ctx, dec)
		assert.NoError(t, err)
		assert.True(t, inserted)
		return dec
	}
	v1 := insert("ISD1-V1.trc")
	v2 := insert("ISD1-V2.trc")

	t.Run("TRCExists", func(t *testing.T) {
		// Check existing TRC.
		exists, err := db.TRCExists(ctx, v1)
		assert.NoError(t, err)
		assert.True(t, exists)
		// Check inexistent TRC.
		other, err := decoded.DecodeTRC(loadFile(t, cfg.filePath("ISD1-V3.trc")))
		require.NoError(t, err)
		exists, err = db.TRCExists(ctx, other)
		assert.NoError(t, err)
		assert.False(t, exists)
		// Check existing TRC with different content.
		mismatch := v1
		mismatch.Signed.EncodedTRC = "some garbage"
		exists, err = db.TRCExists(ctx, mismatch)
		xtest.AssertErrorsIs(t, err, trust.ErrContentMismatch)
		assert.True(t, exists)
	})
	t.Run("GetTRC", func(t *testing.T) {
		// Fetch existing TRC.
		fetched, err := db.GetTRC(ctx, trust.TRCID{ISD: v1.TRC.ISD, Version: v1.TRC.Version})
		assert.NoError(t, err)
		assert.Equal(t, v1.TRC, fetched)
		// Fetch max of existing TRC.
		max, err := db.GetTRC(ctx, trust.TRCID{ISD: v1.TRC.ISD, Version: scrypto.LatestVer})
		assert.NoError(t, err)
		assert.Equal(t, v2.TRC, max)
		// Fetch inexistent TRC.
		_, err = db.GetTRC(ctx, trust.TRCID{ISD: 42, Version: scrypto.LatestVer})
		xtest.AssertErrorsIs(t, err, trust.ErrNotFound)
	})
	t.Run("GetRawTRC", func(t *testing.T) {
		// Fetch existing TRC.
		fetched, err := db.GetRawTRC(ctx, trust.TRCID{ISD: v1.TRC.ISD, Version: v1.TRC.Version})
		assert.NoError(t, err)
		assert.Equal(t, v1.Raw, fetched)
		// Fetch max of existing TRC.
		max, err := db.GetRawTRC(ctx, trust.TRCID{ISD: v1.TRC.ISD, Version: scrypto.LatestVer})
		assert.NoError(t, err)
		assert.Equal(t, v2.Raw, max)
		// Fetch inexistent TRC.
		_, err = db.GetRawTRC(ctx, trust.TRCID{ISD: 42, Version: scrypto.LatestVer})
		xtest.AssertErrorsIs(t, err, trust.ErrNotFound)
	})
	t.Run("GetTRCInfo", func(t *testing.T) {
		// Fetch existing TRC.
		info := trust.TRCInfo{
			Validity:    *v1.TRC.Validity,
			GracePeriod: v1.TRC.GracePeriod.Duration,
			Version:     v1.TRC.Version,
		}
		fetched, err := db.GetTRCInfo(ctx, trust.TRCID{ISD: v1.TRC.ISD, Version: v1.TRC.Version})
		assert.NoError(t, err)
		assert.Equal(t, info, fetched)
		// Fetch max of existing TRC.
		info = trust.TRCInfo{
			Validity:    *v2.TRC.Validity,
			GracePeriod: v2.TRC.GracePeriod.Duration,
			Version:     v2.TRC.Version,
		}
		max, err := db.GetTRCInfo(ctx, trust.TRCID{ISD: v1.TRC.ISD, Version: scrypto.LatestVer})
		assert.NoError(t, err)
		assert.Equal(t, info, max)
		// Fetch inexistent TRC.
		_, err = db.GetTRCInfo(ctx, trust.TRCID{ISD: 42, Version: scrypto.LatestVer})
		xtest.AssertErrorsIs(t, err, trust.ErrNotFound)
	})
	t.Run("GetIssuingGrantKeyInfo", func(t *testing.T) {
		ia110 := xtest.MustParseIA("1-ff00:0:110")
		ia120 := xtest.MustParseIA("1-ff00:0:120")
		ia130 := xtest.MustParseIA("1-ff00:0:130")
		trcInfo1 := trust.TRCInfo{
			Validity:    *v1.TRC.Validity,
			GracePeriod: v1.TRC.GracePeriod.Duration,
			Version:     v1.TRC.Version,
		}
		expectedKeyInfos1 := map[addr.IA]trust.KeyInfo{
			ia110: {TRC: trcInfo1, Version: 1},
			ia120: {TRC: trcInfo1, Version: 1},
			ia130: {TRC: trcInfo1, Version: 1},
		}
		trcInfo2 := trust.TRCInfo{
			Validity:    *v2.TRC.Validity,
			GracePeriod: v2.TRC.GracePeriod.Duration,
			Version:     v2.TRC.Version,
		}
		expectedKeyInfos2 := map[addr.IA]trust.KeyInfo{
			ia110: {TRC: trcInfo2, Version: 1},
			ia120: {TRC: trcInfo2, Version: 1},
		}
		okTests := map[scrypto.Version]map[addr.IA]trust.KeyInfo{
			1: expectedKeyInfos1,
			2: expectedKeyInfos2,
		}
		for ver, expectedKeyInfos := range okTests {
			for ia, expected := range expectedKeyInfos {
				t.Run(fmt.Sprintf("fetch existing %s-v%d", ia, ver), func(t *testing.T) {
					actual, err := db.GetIssuingGrantKeyInfo(context.Background(), ia, ver)
					assert.NoError(t, err)
					assert.Equal(t, expected, actual)
				})
			}
		}
		t.Run("fetch non-existent ia", func(t *testing.T) {
			ia140 := xtest.MustParseIA("1-ff00:0:140")
			actual, err := db.GetIssuingGrantKeyInfo(context.Background(), ia140, 1)
			xtest.AssertErrorsIs(t, err, trust.ErrNotFound)
			assert.Equal(t, trust.KeyInfo{}, actual)
		})
		t.Run("fetch non-existent version", func(t *testing.T) {
			actual, err := db.GetIssuingGrantKeyInfo(context.Background(), ia110, 42)
			xtest.AssertErrorsIs(t, err, trust.ErrNotFound)
			assert.Equal(t, trust.KeyInfo{}, actual)
		})
		t.Run("fetch non-issuing ia", func(t *testing.T) {
			actual, err := db.GetIssuingGrantKeyInfo(context.Background(), ia130, 2)
			xtest.AssertErrorsIs(t, err, trust.ErrNotFound)
			assert.Equal(t, trust.KeyInfo{}, actual)
		})
	})
	t.Run("InsertTRC", func(t *testing.T) {
		// Insert existing TRC.
		inserted, err := db.InsertTRC(ctx, v1)
		assert.NoError(t, err)
		assert.False(t, inserted)
		// Insert existing TRC with different contents.
		mismatch := v1
		mismatch.Signed.EncodedTRC = "some garbage"
		inserted, err = db.InsertTRC(ctx, mismatch)
		xtest.AssertErrorsIs(t, err, trust.ErrContentMismatch)
		assert.False(t, inserted)
	})
}

func testChain(t *testing.T, db trust.ReadWrite, cfg Config) {
	ctx, cancelF := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancelF()
	insert := func(name string, freshIssuer bool) decoded.Chain {
		dec, err := decoded.DecodeChain(loadFile(t, cfg.filePath(name)))
		require.NoError(t, err)
		asInserted, issInserted, err := db.InsertChain(ctx, dec)
		assert.NoError(t, err)
		assert.True(t, asInserted)
		assert.Equal(t, freshIssuer, issInserted)
		return dec
	}
	v1 := insert("ISD1-ASff00_0_110-V1.crt", true)
	v2 := insert("ISD1-ASff00_0_110-V10.crt", false)

	t.Run("ChainExists", func(t *testing.T) {
		// Check existing certificate chain.
		exists, err := db.ChainExists(ctx, v1)
		assert.NoError(t, err)
		assert.True(t, exists)
		// Check inexistent certificate chain.
		other, err := decoded.DecodeChain(loadFile(t, cfg.filePath("ISD1-ASff00_0_111-V1.crt")))
		require.NoError(t, err)
		exists, err = db.ChainExists(ctx, other)
		assert.NoError(t, err)
		assert.False(t, exists)
		// Check existing certificate chain with different content in AS certificate.
		mismatch := v1
		mismatch.Chain.AS.Encoded = "some garbage"
		exists, err = db.ChainExists(ctx, mismatch)
		xtest.AssertErrorsIs(t, err, trust.ErrContentMismatch)
		assert.False(t, exists)
		// Check existing certificate chain with different content in issuer certificate.
		mismatch = v1
		mismatch.Chain.Issuer.Encoded = "some garbage"
		exists, err = db.ChainExists(ctx, mismatch)
		xtest.AssertErrorsIs(t, err, trust.ErrContentMismatch)
		assert.False(t, exists)
	})
	t.Run("GetRawChain", func(t *testing.T) {
		// Check existing certificate chain.
		fetched, err := db.GetRawChain(ctx, trust.ChainID{
			IA: v1.AS.Subject, Version: v1.AS.Version})
		assert.NoError(t, err)
		assert.Equal(t, v1.Raw, fetched)
		// Check max of existing certificate chain.
		max, err := db.GetRawChain(ctx, trust.ChainID{
			IA: v1.AS.Subject, Version: scrypto.LatestVer})
		assert.NoError(t, err)
		assert.Equal(t, v2.Raw, max)
		// Check inexistent certificate chain.
		_, err = db.GetRawChain(ctx, trust.ChainID{
			IA:      xtest.MustParseIA("42-ff00:0:142"),
			Version: scrypto.LatestVer,
		})
		xtest.AssertErrorsIs(t, err, trust.ErrNotFound)
	})
	t.Run("InsertChain", func(t *testing.T) {
		// Check inexistent certificate chain with existing issuer certifcate.
		other, err := decoded.DecodeChain(loadFile(t, cfg.filePath("ISD1-ASff00_0_111-V1.crt")))
		require.NoError(t, err)
		asInserted, issInserted, err := db.InsertChain(ctx, other)
		assert.NoError(t, err)
		assert.True(t, asInserted)
		assert.False(t, issInserted)
		// Check existing certificate chain.
		asInserted, issInserted, err = db.InsertChain(ctx, v1)
		assert.NoError(t, err)
		assert.False(t, asInserted)
		assert.False(t, issInserted)
		// Check existing certificate chain with different content in AS certificate.
		mismatch := v1
		mismatch.Chain.AS.Encoded = "some garbage"
		asInserted, issInserted, err = db.InsertChain(ctx, mismatch)
		xtest.AssertErrorsIs(t, err, trust.ErrContentMismatch)
		assert.False(t, asInserted)
		assert.False(t, issInserted)
		// Check existing certificate chain with different content in AS certificate.
		mismatch = v1
		mismatch.Chain.Issuer.Encoded = "some garbage"
		asInserted, issInserted, err = db.InsertChain(ctx, mismatch)
		xtest.AssertErrorsIs(t, err, trust.ErrContentMismatch)
		assert.False(t, asInserted)
		assert.False(t, issInserted)
	})
}

func testRollback(t *testing.T, db trust.DB, cfg Config) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	tx, err := db.BeginTransaction(ctx, nil)
	require.NoError(t, err)

	trcobj, err := decoded.DecodeTRC(loadFile(t, cfg.filePath("ISD1-V1.trc")))
	require.NoError(t, err)
	inserted, err := tx.InsertTRC(ctx, trcobj)
	assert.NoError(t, err)
	assert.True(t, inserted)
	err = tx.Rollback()
	assert.NoError(t, err)
	// Check that TRC is not in database after rollback.
	_, err = db.GetTRCInfo(ctx, trust.TRCID{ISD: 1, Version: scrypto.LatestVer})
	xtest.AssertErrorsIs(t, err, trust.ErrNotFound)
}

func loadFile(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := ioutil.ReadFile(name)
	require.NoError(t, err)
	return raw
}
