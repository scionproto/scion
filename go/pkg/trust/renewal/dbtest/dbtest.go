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

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/renewal"
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
	renewal.DB
	// Prepare should reset the internal state so that the db is empty and is ready to be tested.
	Prepare(*testing.T, context.Context)
}

// Run should be used to test any implementation of the renewal.DB interface.
// An implementation interface should at least have one test method that calls
// this test-suite.
func Run(t *testing.T, db TestableDB, cfg Config) {
	cfg.InitDefaults()

	// first load all chains
	bern1Chain := loadChainFiles(t, "bern", 1, cfg)
	bern2Chain := loadChainFiles(t, "bern", 2, cfg)
	bern3Chain := loadChainFiles(t, "bern", 3, cfg)

	ctx, cancelF := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancelF()

	db.Prepare(t, ctx)

	// prefill DB with chains that we expect to exist.
	inserted, err := db.InsertClientChain(ctx, bern1Chain)
	require.NoError(t, err)
	assert.True(t, inserted)

	t.Run("InsertClientChain", func(t *testing.T) {
		t.Run("Insert already existing ok", func(t *testing.T) {
			inserted, err := db.InsertClientChain(ctx, bern1Chain)
			assert.NoError(t, err)
			assert.False(t, inserted)
		})
		t.Run("Insert different with same serial fails", func(t *testing.T) {
			asCert := *bern2Chain[0]
			asCert.SerialNumber = bern1Chain[0].SerialNumber
			inserted, err := db.InsertClientChain(ctx, []*x509.Certificate{&asCert, bern2Chain[1]})
			assert.Error(t, err)
			assert.False(t, inserted)
		})
		t.Run("Insert subsequent succeeds", func(t *testing.T) {
			inserted, err := db.InsertClientChain(ctx, bern2Chain)
			assert.NoError(t, err)
			assert.True(t, inserted)
		})
	})
	t.Run("ClientChains", func(t *testing.T) {
		t.Run("Non existing chain", func(t *testing.T) {
			chains, err := db.ClientChains(ctx, trust.ChainQuery{
				IA:           xtest.MustParseIA("1-ff00:0:111"),
				SubjectKeyID: []byte("non-existing"),
				Date:         time.Now(),
			})
			assert.NoError(t, err)
			assert.Empty(t, chains)
		})
		t.Run("Existing chain no overlap", func(t *testing.T) {
			chains, err := db.ClientChains(ctx, trust.ChainQuery{
				IA:           xtest.MustParseIA("1-ff00:0:110"),
				SubjectKeyID: bern1Chain[0].SubjectKeyId,
				Date:         time.Date(2020, 6, 25, 13, 0, 0, 0, time.UTC),
			})
			assert.NoError(t, err)
			assert.Equal(t, [][]*x509.Certificate{bern1Chain}, chains)
		})
		t.Run("Existing chain query time out of range", func(t *testing.T) {
			// insert another chain to make sure it is not found
			db.InsertClientChain(ctx, bern2Chain)

			chains, err := db.ClientChains(ctx, trust.ChainQuery{
				IA:           xtest.MustParseIA("1-ff00:0:110"),
				SubjectKeyID: bern1Chain[0].SubjectKeyId,
				Date:         time.Date(2020, 6, 27, 12, 0, 1, 0, time.UTC),
			})
			assert.NoError(t, err)
			assert.Empty(t, chains)
			chains, err = db.ClientChains(ctx, trust.ChainQuery{
				IA:           xtest.MustParseIA("1-ff00:0:110"),
				SubjectKeyID: bern1Chain[0].SubjectKeyId,
				Date:         time.Date(2020, 6, 24, 11, 59, 59, 0, time.UTC),
			})
			assert.NoError(t, err)
			assert.Empty(t, chains)
		})
		t.Run("Existing chain overlap different key", func(t *testing.T) {
			db.InsertClientChain(ctx, bern2Chain)
			chains, err := db.ClientChains(ctx, trust.ChainQuery{
				IA:           xtest.MustParseIA("1-ff00:0:110"),
				SubjectKeyID: bern1Chain[0].SubjectKeyId,
				Date:         time.Date(2020, 6, 26, 13, 0, 0, 0, time.UTC),
			})
			assert.NoError(t, err)
			assert.Equal(t, [][]*x509.Certificate{bern1Chain}, chains)
			chains, err = db.ClientChains(ctx, trust.ChainQuery{
				IA:           xtest.MustParseIA("1-ff00:0:110"),
				SubjectKeyID: bern2Chain[0].SubjectKeyId,
				Date:         time.Date(2020, 6, 26, 13, 0, 0, 0, time.UTC),
			})
			assert.NoError(t, err)
			assert.Equal(t, [][]*x509.Certificate{bern2Chain}, chains)
		})
		t.Run("Existing chain overlap same key", func(t *testing.T) {
			db.InsertClientChain(ctx, bern3Chain)
			chains, err := db.ClientChains(ctx, trust.ChainQuery{
				IA:           xtest.MustParseIA("1-ff00:0:110"),
				SubjectKeyID: bern3Chain[0].SubjectKeyId,
				Date:         time.Date(2020, 6, 28, 13, 0, 0, 0, time.UTC),
			})
			assert.NoError(t, err)
			assert.Equal(t, [][]*x509.Certificate{bern2Chain, bern3Chain}, chains)
		})
	})
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
