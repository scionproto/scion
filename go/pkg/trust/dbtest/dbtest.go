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
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/trust"
)

var (
	// DefaultTimeout is the default timeout for running the test harness.
	DefaultTimeout = 5 * time.Second
	// DefaultRelPath is the default relative path to the test data.
	DefaultRelPath = "../dbtest/testdata"
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

// Run should be used to test any implementation of the trust.DB interface.
// An implementation interface should at least have one test method that calls
// this test-suite.
func Run(t *testing.T, db TestableDB, cfg Config) {
	cfg.InitDefaults()
	tests := map[string]func(*testing.T, trust.DB, Config){
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
}

func testTRC(t *testing.T, db trust.DB, cfg Config) {
	trc := loadTRCFile(t, "ISD1-B1-S1.trc", cfg)

	ctx, cancelF := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancelF()

	in, err := db.InsertTRC(ctx, trc)
	require.NoError(t, err)
	require.True(t, in)

	t.Run("InsertTRC", func(t *testing.T) {
		t.Run("Insert existing", func(t *testing.T) {
			in, err := db.InsertTRC(ctx, trc)
			assert.NoError(t, err)
			assert.False(t, in)
		})
		t.Run("Insert existing modified", func(t *testing.T) {
			trcCopy := trc
			trcCopy.TRC.Raw = append([]byte{}, trc.TRC.Raw...)
			trcCopy.TRC.Raw[0] = trcCopy.TRC.Raw[0] ^ 0xFF
			in, err := db.InsertTRC(ctx, trcCopy)
			assert.Error(t, err)
			assert.False(t, in)
		})
	})
	t.Run("SignedTRC", func(t *testing.T) {
		t.Run("Non existing TRC", func(t *testing.T) {
			aTRC, err := db.SignedTRC(ctx, cppki.TRCID{
				ISD:    trc.TRC.ID.ISD + 1,
				Base:   trc.TRC.ID.Base,
				Serial: trc.TRC.ID.Serial,
			})
			assert.NoError(t, err)
			assert.Equal(t, cppki.SignedTRC{}, aTRC)
		})
		t.Run("Invalid request", func(t *testing.T) {
			aTRC, err := db.SignedTRC(ctx, cppki.TRCID{
				ISD:    trc.TRC.ID.ISD,
				Base:   scrypto.LatestVer,
				Serial: trc.TRC.ID.Serial,
			})
			assert.Error(t, err)
			assert.Equal(t, cppki.SignedTRC{}, aTRC)
		})
		t.Run("Existing TRC", func(t *testing.T) {
			aTRC, err := db.SignedTRC(ctx, trc.TRC.ID)
			assert.NoError(t, err)
			assert.Equal(t, trc, aTRC)
		})
		t.Run("Latest TRC single", func(t *testing.T) {
			aTRC, err := db.SignedTRC(ctx, cppki.TRCID{
				ISD:    trc.TRC.ID.ISD,
				Base:   scrypto.LatestVer,
				Serial: scrypto.LatestVer,
			})
			assert.NoError(t, err)
			assert.Equal(t, trc, aTRC)
		})
		t.Run("Latest TRC multiple in DB", func(t *testing.T) {
			t.Run("same base, higher serial", func(t *testing.T) {
				trcS5 := trc
				trcS5.TRC.ID.Serial = 5
				rawS5, err := trcS5.Encode()
				require.NoError(t, err)
				trcS5, err = cppki.DecodeSignedTRC(rawS5)
				require.NoError(t, err)
				_, err = db.InsertTRC(ctx, trcS5)
				require.NoError(t, err)

				aTRC, err := db.SignedTRC(ctx, cppki.TRCID{
					ISD:    trc.TRC.ID.ISD,
					Base:   scrypto.LatestVer,
					Serial: scrypto.LatestVer,
				})
				assert.NoError(t, err)
				assert.Equal(t, trcS5, aTRC)
			})
			t.Run("higher base, lower serial", func(t *testing.T) {
				trcB2S4 := trc
				trcB2S4.TRC.ID.Base, trcB2S4.TRC.ID.Serial = 2, 4
				rawB2S4, err := trcB2S4.Encode()
				require.NoError(t, err)
				trcB2S4, err = cppki.DecodeSignedTRC(rawB2S4)
				require.NoError(t, err)
				_, err = db.InsertTRC(ctx, trcB2S4)
				require.NoError(t, err)

				aTRC, err := db.SignedTRC(ctx, cppki.TRCID{
					ISD:    trc.TRC.ID.ISD,
					Base:   scrypto.LatestVer,
					Serial: scrypto.LatestVer,
				})
				assert.NoError(t, err)
				assert.Equal(t, trcB2S4, aTRC)
			})
		})
	})
}

func testChain(t *testing.T, db trust.DB, cfg Config) {
	// first load all chains
	bern1Chain := loadChainFiles(t, "bern", 1, cfg)
	bern2Chain := loadChainFiles(t, "bern", 2, cfg)
	bern3Chain := loadChainFiles(t, "bern", 3, cfg)
	geneva1Chain := loadChainFiles(t, "geneva", 1, cfg)
	geneva2Chain := loadChainFiles(t, "geneva", 2, cfg)

	ctx, cancelF := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancelF()

	// prefill DB with chains that we expect to exist.
	in, err := db.InsertChain(ctx, bern1Chain)
	require.NoError(t, err)
	require.True(t, in)

	t.Run("InsertChain", func(t *testing.T) {
		t.Run("Invalid chain length", func(t *testing.T) {
			in, err := db.InsertChain(ctx, geneva1Chain[:1])
			assert.False(t, in)
			assert.Error(t, err)
			in, err = db.InsertChain(ctx, append(geneva1Chain, geneva2Chain...))
			assert.False(t, in)
			assert.Error(t, err)
		})
		t.Run("New chain", func(t *testing.T) {
			in, err := db.InsertChain(ctx, geneva1Chain)
			assert.True(t, in)
			assert.NoError(t, err)
		})
		t.Run("Insert existing chain", func(t *testing.T) {
			in, err := db.InsertChain(ctx, bern1Chain)
			assert.False(t, in)
			assert.NoError(t, err)
		})
	})
	t.Run("Chain", func(t *testing.T) {
		t.Run("Non existing chain", func(t *testing.T) {
			chains, err := db.Chains(ctx, trust.ChainQuery{
				IA:           xtest.MustParseIA("1-ff00:0:111"),
				SubjectKeyID: []byte("non-existing"),
				Date:         time.Now(),
			})
			assert.NoError(t, err)
			assert.Empty(t, chains)
		})
		t.Run("Existing chain no overlap", func(t *testing.T) {
			chains, err := db.Chains(ctx, trust.ChainQuery{
				IA:           xtest.MustParseIA("1-ff00:0:110"),
				SubjectKeyID: bern1Chain[0].SubjectKeyId,
				Date:         time.Date(2020, 6, 25, 13, 0, 0, 0, time.UTC),
			})
			assert.NoError(t, err)
			assert.Equal(t, [][]*x509.Certificate{bern1Chain}, chains)
		})
		t.Run("Existing chain query time out of range", func(t *testing.T) {
			// insert another chain to make sure it is not found
			_, err = db.InsertChain(ctx, bern2Chain)
			require.NoError(t, err)
			chains, err := db.Chains(ctx, trust.ChainQuery{
				IA:           xtest.MustParseIA("1-ff00:0:110"),
				SubjectKeyID: bern1Chain[0].SubjectKeyId,
				Date:         time.Date(2020, 6, 27, 12, 0, 1, 0, time.UTC),
			})
			assert.NoError(t, err)
			assert.Empty(t, chains)
			chains, err = db.Chains(ctx, trust.ChainQuery{
				IA:           xtest.MustParseIA("1-ff00:0:110"),
				SubjectKeyID: bern1Chain[0].SubjectKeyId,
				Date:         time.Date(2020, 6, 24, 11, 59, 59, 0, time.UTC),
			})
			assert.NoError(t, err)
			assert.Empty(t, chains)
		})
		t.Run("All certificate chains", func(t *testing.T) {
			chains, err := db.Chains(ctx, trust.ChainQuery{})
			assert.NoError(t, err)
			assert.Equal(t, [][]*x509.Certificate{bern1Chain, geneva1Chain, bern2Chain}, chains)
		})
		t.Run("Active certificate chain in a given time", func(t *testing.T) {
			chains, err := db.Chains(ctx, trust.ChainQuery{
				Date: time.Date(2020, 6, 26, 11, 59, 59, 0, time.UTC),
			})
			assert.NoError(t, err)
			assert.Equal(t, [][]*x509.Certificate{bern1Chain, geneva1Chain}, chains)
		})
		t.Run("certificate chain for a given ISD-AS", func(t *testing.T) {
			chains, err := db.Chains(ctx, trust.ChainQuery{
				IA: xtest.MustParseIA("1-ff00:0:110"),
			})
			assert.NoError(t, err)
			assert.Equal(t, [][]*x509.Certificate{bern1Chain, bern2Chain}, chains)
		})
		t.Run("Existing chain overlap different key", func(t *testing.T) {
			_, err := db.InsertChain(ctx, bern2Chain)
			require.NoError(t, err)
			chains, err := db.Chains(ctx, trust.ChainQuery{
				IA:           xtest.MustParseIA("1-ff00:0:110"),
				SubjectKeyID: bern1Chain[0].SubjectKeyId,
				Date:         time.Date(2020, 6, 26, 13, 0, 0, 0, time.UTC),
			})
			assert.NoError(t, err)
			assert.Equal(t, [][]*x509.Certificate{bern1Chain}, chains)
			chains, err = db.Chains(ctx, trust.ChainQuery{
				IA:           xtest.MustParseIA("1-ff00:0:110"),
				SubjectKeyID: bern2Chain[0].SubjectKeyId,
				Date:         time.Date(2020, 6, 26, 13, 0, 0, 0, time.UTC),
			})
			assert.NoError(t, err)
			assert.Equal(t, [][]*x509.Certificate{bern2Chain}, chains)
		})
		t.Run("Existing chain overlap same key", func(t *testing.T) {
			_, err := db.InsertChain(ctx, bern3Chain)
			require.NoError(t, err)
			chains, err := db.Chains(ctx, trust.ChainQuery{
				IA:           xtest.MustParseIA("1-ff00:0:110"),
				SubjectKeyID: bern3Chain[0].SubjectKeyId,
				Date:         time.Date(2020, 6, 28, 13, 0, 0, 0, time.UTC),
			})
			assert.NoError(t, err)
			assert.Equal(t, [][]*x509.Certificate{bern2Chain, bern3Chain}, chains)
		})
	})
}

func loadTRCFile(t *testing.T, file string, cfg Config) cppki.SignedTRC {
	return xtest.LoadTRC(t, cfg.filePath(file))
}

func loadChainFiles(t *testing.T, org string, asVersion int, cfg Config) []*x509.Certificate {
	return []*x509.Certificate{
		loadCertFile(t, filepath.Join(org, fmt.Sprintf("cp-as%d.crt", asVersion)), cfg),
		loadCertFile(t, filepath.Join(org, "cp-ca.crt"), cfg),
	}
}

func loadCertFile(t *testing.T, name string, cfg Config) *x509.Certificate {
	certs, err := cppki.ReadPEMCerts(cfg.filePath(name))
	require.NoError(t, err)
	require.Len(t, certs, 1)
	return certs[0]
}
