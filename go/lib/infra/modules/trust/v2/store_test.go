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

package trust_test

import (
	"context"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2/trustdbsqlite"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestStoreLoadCryptoMaterial(t *testing.T) {
	tests := map[string]struct {
		Prepare      func(t *testing.T, scratch string)
		ErrAssertion assert.ErrorAssertionFunc
	}{
		"valid": {
			Prepare: func(t *testing.T, scratch string) {
				collectTRCs(t, tmpDir, scratch)
				collectChains(t, tmpDir, scratch)
			},
			ErrAssertion: assert.NoError,
		},
		"unreadable TRC": {
			Prepare: func(t *testing.T, scratch string) {
				collectChains(t, tmpDir, scratch)
				err := ioutil.WriteFile(filepath.Join(scratch, "ISD1-V1.trc"), []byte("no"), 0x000)
				require.NoError(t, err)
			},
			ErrAssertion: assert.Error,
		},
		"garbage TRC": {
			Prepare: func(t *testing.T, scratch string) {
				collectChains(t, tmpDir, scratch)
				err := ioutil.WriteFile(filepath.Join(scratch, "ISD1-V1.trc"), []byte("no"), 0x777)
				require.NoError(t, err)
			},
			ErrAssertion: assert.Error,
		},
		"unreadable chain": {
			Prepare: func(t *testing.T, scratch string) {
				collectTRCs(t, tmpDir, scratch)
				err := ioutil.WriteFile(filepath.Join(scratch, "ISD1-AS1-V1.crt"),
					[]byte("no"), 0x000)
				require.NoError(t, err)
			},
			ErrAssertion: assert.Error,
		},
		"garbage chain": {
			Prepare: func(t *testing.T, scratch string) {
				collectTRCs(t, tmpDir, scratch)
				err := ioutil.WriteFile(filepath.Join(scratch, "ISD1-AS1-V1.crt"),
					[]byte("no"), 0x777)
				require.NoError(t, err)
			},
			ErrAssertion: assert.Error,
		},
	}
	for n, tc := range tests {
		name, test := n, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			scratch, clean := xtest.MustTempDir("", "trust-load-crypto")
			defer clean()
			db, err := trustdbsqlite.New(":memory:")
			require.NoError(t, err)
			store := trust.Store{
				DB: db,
				CryptoProvider: trust.Provider{
					DB: db,
				},
			}
			test.Prepare(t, scratch)
			err = store.LoadCryptoMaterial(context.Background(), scratch)
			test.ErrAssertion(t, err)
			if err != nil {
				return
			}
			trcOpts := infra.TRCOpts{AllowInactive: true}
			for v := scrypto.Version(1); v < 5; v++ {
				id := trust.TRCID{ISD: 1, Version: v}
				raw, err := store.GetRawTRC(context.Background(), id, trcOpts)
				assert.NoError(t, err)
				assert.Equal(t, loadTRC(t, TRCDesc{ISD: 1, Version: v}).Raw, raw)
			}
			chainOpts := infra.ChainOpts{AllowInactive: true}
			for _, ia := range []addr.IA{ia110, ia120, ia122, ia130, ia210} {
				id := trust.ChainID{IA: ia, Version: 1}
				raw, err := store.GetRawChain(context.Background(), id, chainOpts)
				assert.NoError(t, err)
				assert.Equal(t, loadChain(t, ChainDesc{IA: ia, Version: 1}).Raw, raw)
			}
		})
	}
}

func collectTRCs(t *testing.T, origDir, outDir string) {
	t.Helper()
	trcs, err := filepath.Glob(filepath.Join(origDir, "ISD*/trcs/*.trc"))
	require.NoError(t, err, help)
	require.Greater(t, len(trcs), 0)
	for _, trc := range trcs {
		raw, err := ioutil.ReadFile(trc)
		require.NoError(t, err)
		_, file := filepath.Split(trc)
		err = ioutil.WriteFile(filepath.Join(outDir, file), raw, 0x777)
		require.NoError(t, err)
	}
}

func collectChains(t *testing.T, origDir, outDir string) {
	t.Helper()
	chains, err := filepath.Glob(filepath.Join(origDir, "ISD*/AS*/certs/*.crt"))
	require.NoError(t, err, help)
	require.Greater(t, len(chains), 0)
	for _, chain := range chains {
		raw, err := ioutil.ReadFile(chain)
		require.NoError(t, err)
		_, file := filepath.Split(chain)
		err = ioutil.WriteFile(filepath.Join(outDir, file), raw, 0x777)
		require.NoError(t, err)
	}
}
