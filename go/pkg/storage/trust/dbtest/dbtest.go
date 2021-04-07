// Copyright 2020 Anapaya Systems
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
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/storage"
	truststorage "github.com/scionproto/scion/go/pkg/storage/trust"
	"github.com/scionproto/scion/go/pkg/trust/dbtest"
)

// Config holds the configuration for the trust database testing harness.
type Config dbtest.Config

func (cfg *Config) InitDefaults() {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.RelPath == "" {
		cfg.RelPath = "../../../trust/dbtest/testdata"
	}
}

func (cfg *Config) filePath(name string) string {
	return filepath.Join(cfg.RelPath, name)
}

// TestableDB extends the trust db interface with methods that are needed for testing.
type TestableDB interface {
	storage.TrustDB
	// Prepare should reset the internal state so that the db is empty and is ready to be tested.
	Prepare(*testing.T, context.Context)
}

// Run should be used to test any implementation of the storage.TrustDB
// interface. An implementation interface should at least have one test method
// that calls this test-suite.
func Run(t *testing.T, db TestableDB, cfg Config) {
	cfg.InitDefaults()
	c := dbtest.Config(cfg)
	dbtest.Run(t, db, c)
	run(t, db, cfg)
}

func run(t *testing.T, db TestableDB, cfg Config) {
	ctx, cancelF := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancelF()
	db.Prepare(t, ctx)

	trc1b1s1 := xtest.LoadTRC(t, cfg.filePath("ISD1-B1-S1.trc"))
	trc1b1s2 := modSignedTRCS(t, trc1b1s1, 1, 2)
	trc2b1s1 := xtest.LoadTRC(t, cfg.filePath("ISD2-B1-S1.trc"))
	trc2b1s2 := modSignedTRCS(t, trc2b1s1, 1, 2)
	trc2b3s3 := modSignedTRCS(t, trc2b1s1, 3, 3)

	allSignedTRCS := cppki.SignedTRCs{
		trc1b1s1,
		trc2b1s1,
		trc1b1s2,
		trc2b3s3,
		trc2b1s2,
	}
	latestSignedTRCS := cppki.SignedTRCs{trc1b1s2, trc2b3s3}
	isd1SignedTRCs := cppki.SignedTRCs{trc1b1s1, trc1b1s2}

	t.Run("insert signedTRCs", func(t *testing.T) {
		for _, SignedTRC := range allSignedTRCS {
			in, err := db.InsertTRC(ctx, SignedTRC)
			require.NoError(t, err)
			require.True(t, in)
		}
	})
	t.Run("query all signedTRCs", func(t *testing.T) {
		actualTRCs, err := db.SignedTRCs(ctx, truststorage.TRCsQuery{Latest: false})
		require.NoError(t, err)
		assert.ElementsMatch(t, allSignedTRCS, actualTRCs)
	})
	t.Run("query latest signedTRCs", func(t *testing.T) {
		actualTRCs, err := db.SignedTRCs(ctx, truststorage.TRCsQuery{Latest: true})
		require.NoError(t, err)
		assert.ElementsMatch(t, latestSignedTRCS, actualTRCs)
	})
	t.Run("query all signedTRCs from ISD 1", func(t *testing.T) {
		actualTRCs, err := db.SignedTRCs(ctx, truststorage.TRCsQuery{ISD: []addr.ISD{1}})
		require.NoError(t, err)
		assert.ElementsMatch(t, isd1SignedTRCs, actualTRCs)
	})
	t.Run("query all signedTRCs inexistent", func(t *testing.T) {
		actualTRCs, err := db.SignedTRCs(ctx, truststorage.TRCsQuery{ISD: []addr.ISD{1337}})
		require.NoError(t, err)
		assert.Empty(t, actualTRCs)
	})

	t.Run("Chain", func(t *testing.T) {
		// first load a chain
		bern1Chain := []*x509.Certificate{
			xtest.LoadChain(t, cfg.filePath("bern/cp-as1.crt"))[0],
			xtest.LoadChain(t, cfg.filePath("bern/cp-ca.crt"))[0],
		}
		ctx, cancelF := context.WithTimeout(context.Background(), cfg.Timeout)
		defer cancelF()

		// prefill DB with the chain that we expect to exist.
		in, err := db.InsertChain(ctx, bern1Chain)
		require.NoError(t, err)
		require.True(t, in)
		t.Run("Valid ChainID", func(t *testing.T) {
			chain, err := db.Chain(ctx, truststorage.ChainID(bern1Chain))
			assert.NoError(t, err)
			assert.Equal(t, bern1Chain, chain)
		})
		t.Run("Invalid ChainID", func(t *testing.T) {
			chain, err := db.Chain(ctx, []byte("fa53a04h"))
			assert.Error(t, err)
			assert.Empty(t, chain)
		})
	})
}

func modSignedTRCS(t *testing.T, trc cppki.SignedTRC,
	base scrypto.Version,
	serial scrypto.Version,
) cppki.SignedTRC {
	trcb := trc
	trcb.TRC.ID.Serial = serial
	trcb.TRC.ID.Base = base
	rawTRCb, err := trcb.TRC.Encode()
	require.NoError(t, err)
	trcb.TRC.Raw = rawTRCb
	rawSignedTRCb, err := trcb.Encode()
	require.NoError(t, err)
	trcb.Raw = rawSignedTRCb
	return trcb
}
