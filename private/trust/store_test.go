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

package trust_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/private/trust"
	"github.com/scionproto/scion/private/trust/mock_trust"
	"github.com/scionproto/scion/scion-pki/testcrypto"
)

func TestLoadChains(t *testing.T) {
	expectTRCCalls := func(db *mock_trust.MockDB, trcs map[cppki.TRCID]cppki.SignedTRC) {
		for id, trc := range trcs {
			db.EXPECT().SignedTRC(ctxMatcher{}, id).Return(trc, nil).AnyTimes()
		}
	}
	noFiles := func(_ string) []string { return nil }
	defaultGen := func(t *testing.T) (string, func()) {
		dir, cleanF := xtest.MustTempDir("", "trust_load_chains")

		cmd := testcrypto.Cmd(command.StringPather(""))
		cmd.SetArgs([]string{
			"-t", "testdata/golden.topo",
			"-o", dir,
			"--isd-dir",
			"--as-validity", "1y",
		})
		err := cmd.Execute()
		require.NoError(t, err)
		err = os.WriteFile(filepath.Join(dir, "certs", "dummy.pem"), []byte{}, 0666)
		require.NoError(t, err)
		return dir, cleanF
	}
	testCases := map[string]struct {
		genCrypto  func(t *testing.T) (string, func())
		setupDB    func(*gomock.Controller, string) trust.DB
		assertFunc assert.ErrorAssertionFunc
		ignored    func(dir string) []string
		loaded     func(dir string) []string
	}{
		"valid": {
			genCrypto: func(t *testing.T) (string, func()) {
				dir, cleanF := defaultGen(t)
				return dir, cleanF
			},
			setupDB: func(ctlr *gomock.Controller, dir string) trust.DB {
				db := mock_trust.NewMockDB(ctlr)
				trc := xtest.LoadTRC(t, filepath.Join(dir, "ISD1/trcs/ISD1-B1-S1.trc"))
				expectTRCCalls(db, map[cppki.TRCID]cppki.SignedTRC{
					{ISD: trc.TRC.ID.ISD}: trc,
				})
				db.EXPECT().InsertChain(ctxMatcher{}, gomock.Any()).Return(true, nil).AnyTimes()
				return db
			},
			assertFunc: assert.NoError,
			loaded: func(dir string) []string {
				return []string{
					filepath.Join(dir, "certs/ISD1-ASff00_0_110.pem"),
					filepath.Join(dir, "certs/ISD1-ASff00_0_111.pem"),
					filepath.Join(dir, "certs/ISD1-ASff00_0_112.pem"),
				}
			},
			ignored: func(dir string) []string {
				return []string{
					filepath.Join(dir, "certs/dummy.pem"),
				}
			},
		},
		"valid with grace period": {
			genCrypto: func(t *testing.T) (string, func()) {
				// note that defaultGen already does a simple testcrypto update,
				// but we want a full re-gen.
				dir, cleanF := defaultGen(t)
				cmd := testcrypto.Cmd(command.StringPather(""))
				cmd.SetArgs([]string{
					"update",
					"--scenario", "re-gen",
					"--out", dir,
				})
				err := cmd.Execute()
				require.NoError(t, err)
				return dir, cleanF
			},
			setupDB: func(ctlr *gomock.Controller, dir string) trust.DB {
				db := mock_trust.NewMockDB(ctlr)
				trc1 := xtest.LoadTRC(t, filepath.Join(dir, "trcs/ISD1-B1-S1.trc"))
				trc2 := xtest.LoadTRC(t, filepath.Join(dir, "trcs/ISD1-B1-S2.trc"))
				expectTRCCalls(db, map[cppki.TRCID]cppki.SignedTRC{
					trc1.TRC.ID:            trc1,
					{ISD: trc2.TRC.ID.ISD}: trc2,
				})
				db.EXPECT().InsertChain(ctxMatcher{}, gomock.Any()).Return(true, nil).AnyTimes()
				return db
			},
			assertFunc: assert.NoError,
			loaded: func(dir string) []string {
				return []string{
					filepath.Join(dir, "certs/ISD1-ASff00_0_110.pem"),
					filepath.Join(dir, "certs/ISD1-ASff00_0_111.pem"),
					filepath.Join(dir, "certs/ISD1-ASff00_0_112.pem"),
				}
			},
			ignored: func(dir string) []string {
				return []string{
					filepath.Join(dir, "certs/dummy.pem"),
				}
			},
		},
		"invalid dir": {
			genCrypto: func(t *testing.T) (string, func()) {
				return "./path/to/nowhere", func() {}
			},
			setupDB: func(ctlr *gomock.Controller, _ string) trust.DB {
				return mock_trust.NewMockDB(ctlr)
			},
			assertFunc: assert.Error,
			loaded:     noFiles,
			ignored:    noFiles,
		},
		"db.SignedTRC error": {
			genCrypto: defaultGen,
			setupDB: func(ctlr *gomock.Controller, _ string) trust.DB {
				db := mock_trust.NewMockDB(ctlr)
				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1}).Return(
					cppki.SignedTRC{}, serrors.New("db failed"))
				return db
			},
			assertFunc: assert.Error,
			loaded:     noFiles,
			ignored:    noFiles,
		},
		"db.SignedTRC not found": {
			genCrypto: defaultGen,
			setupDB: func(ctlr *gomock.Controller, _ string) trust.DB {
				db := mock_trust.NewMockDB(ctlr)
				db.EXPECT().SignedTRC(ctxMatcher{},
					cppki.TRCID{ISD: 1}).AnyTimes().Return(
					cppki.SignedTRC{}, nil,
				)
				return db
			},
			assertFunc: assert.NoError,
			loaded:     noFiles,
			ignored: func(dir string) []string {
				return []string{
					filepath.Join(dir, "certs/ISD1-ASff00_0_110.pem"),
					filepath.Join(dir, "certs/ISD1-ASff00_0_111.pem"),
					filepath.Join(dir, "certs/ISD1-ASff00_0_112.pem"),
					filepath.Join(dir, "certs/dummy.pem"),
				}
			},
		},
		"db.Chain error": {
			genCrypto: defaultGen,
			setupDB: func(ctlr *gomock.Controller, dir string) trust.DB {
				db := mock_trust.NewMockDB(ctlr)
				trc := xtest.LoadTRC(t, filepath.Join(dir, "ISD1/trcs/ISD1-B1-S1.trc"))
				expectTRCCalls(db, map[cppki.TRCID]cppki.SignedTRC{
					{ISD: trc.TRC.ID.ISD}: trc,
				})
				db.EXPECT().InsertChain(ctxMatcher{}, gomock.Any()).Return(
					false, fmt.Errorf("db failed"),
				)
				return db
			},
			assertFunc: assert.Error,
			loaded:     noFiles,
			ignored:    noFiles,
		},
		"invalid TRC validation": {
			genCrypto: defaultGen,
			setupDB: func(ctlr *gomock.Controller, _ string) trust.DB {
				db := mock_trust.NewMockDB(ctlr)
				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1}).Return(
					cppki.SignedTRC{}, nil).AnyTimes()
				db.EXPECT().InsertChain(ctxMatcher{}, gomock.Any()).Return(true, nil).AnyTimes()
				return db
			},
			assertFunc: assert.NoError,
			loaded:     noFiles,
			ignored: func(dir string) []string {
				return []string{
					filepath.Join(dir, "certs/ISD1-ASff00_0_110.pem"),
					filepath.Join(dir, "certs/ISD1-ASff00_0_111.pem"),
					filepath.Join(dir, "certs/ISD1-ASff00_0_112.pem"),
					filepath.Join(dir, "certs/dummy.pem"),
				}
			},
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctlr := gomock.NewController(t)
			defer ctlr.Finish()

			dir, cleanF := tc.genCrypto(t)
			defer cleanF()

			db := tc.setupDB(ctlr, dir)
			res, err := trust.LoadChains(context.Background(), filepath.Join(dir, "certs"), db)
			tc.assertFunc(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, tc.loaded(dir), res.Loaded, "loaded")

			var ignored []string
			for f := range res.Ignored {
				ignored = append(ignored, f)
			}
			expectedIgnored := tc.ignored(dir)
			sort.Strings(expectedIgnored)
			sort.Strings(ignored)
			assert.Equal(t, expectedIgnored, ignored, "ignored")
		})
	}
}

func TestLoadTRCs(t *testing.T) {
	dir := genCrypto(t)

	mctrl := gomock.NewController(t)
	defer mctrl.Finish()

	testCases := map[string]struct {
		inputDir   string
		setupDB    func() trust.DB
		assertFunc assert.ErrorAssertionFunc
		ignored    []string
		loaded     []string
	}{
		"valid": {
			inputDir: filepath.Join(dir, "ISD1/trcs"),
			setupDB: func() trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				db.EXPECT().InsertTRC(gomock.Any(), gomock.Any()).Times(2).Return(
					true, nil,
				)
				return db
			},
			assertFunc: assert.NoError,
			loaded: []string{
				filepath.Join(dir, "ISD1/trcs/ISD1-B1-S1.trc"),
				filepath.Join(dir, "ISD1/trcs/ISD1-B1-S1.pem.trc"),
			},
		},
		"invalid dir": {
			inputDir: "./path/to/nowhere",
			setupDB: func() trust.DB {
				return mock_trust.NewMockDB(mctrl)
			},
			assertFunc: assert.Error,
		},
		"invalid TRC": {
			inputDir: "./testdata/store/invalid-trc",
			setupDB: func() trust.DB {
				return mock_trust.NewMockDB(mctrl)
			},
			assertFunc: assert.Error,
		},
		"db.InsertTRC error": {
			inputDir: filepath.Join(dir, "ISD1/trcs"),
			setupDB: func() trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				db.EXPECT().InsertTRC(ctxMatcher{}, gomock.Any()).Return(
					false, fmt.Errorf("db failed"),
				)
				return db
			},
			assertFunc: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			res, err := trust.LoadTRCs(context.Background(), tc.inputDir, tc.setupDB())
			tc.assertFunc(t, err)
			assert.ElementsMatch(t, tc.loaded, res.Loaded)

			var ignored []string
			for f := range res.Ignored {
				ignored = append(ignored, f)
			}
			assert.Equal(t, tc.ignored, ignored)
		})
	}
}

func TestTRCLoaderLoad(t *testing.T) {
	dir := genCrypto(t)

	testCases := map[string]struct {
		inputDir string
		setupDB  func(ctrl *gomock.Controller) trust.DB
		test     func(t *testing.T, loader *trust.TRCLoader)
	}{
		"repeated load": {
			inputDir: filepath.Join(dir, "ISD1/trcs"),
			setupDB: func(ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().InsertTRC(gomock.Any(), gomock.Any()).Times(2).Return(
					true, nil,
				)
				return db
			},
			test: func(t *testing.T, loader *trust.TRCLoader) {
				res, err := loader.Load(context.Background())
				require.NoError(t, err)
				assert.Len(t, res.Loaded, 2)
				res, err = loader.Load(context.Background())
				require.NoError(t, err)
				assert.Len(t, res.Loaded, 0)
			},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			db := tc.setupDB(ctrl)
			loader := &trust.TRCLoader{
				DB:  db,
				Dir: tc.inputDir,
			}
			tc.test(t, loader)
		})
	}
}
