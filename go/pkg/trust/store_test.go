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
	"path/filepath"
	"sort"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/mock_trust"
)

func TestLoadChains(t *testing.T) {
	if *update {
		t.Skip("test crypto is being updated")
	}
	trc := xtest.LoadTRC(t, filepath.Join(goldenDir, "ISD1/trcs/ISD1-B1-S1.trc"))

	testCases := map[string]struct {
		inputDir   string
		setupDB    func(*gomock.Controller) trust.DB
		assertFunc assert.ErrorAssertionFunc
		ignored    []string
		loaded     []string
	}{
		"valid": {
			inputDir: filepath.Join(goldenDir, "certs"),
			setupDB: func(mctlr *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctlr)
				db.EXPECT().SignedTRC(ctxMatcher{},
					TRCIDMatcher{ISD: 1}).Return(trc, nil).AnyTimes()
				db.EXPECT().InsertChain(ctxMatcher{}, gomock.Any()).Return(true, nil).AnyTimes()
				return db
			},
			assertFunc: assert.NoError,
			loaded: []string{
				filepath.Join(goldenDir, "certs/ISD1-ASff00_0_110.pem"),
				filepath.Join(goldenDir, "certs/ISD1-ASff00_0_111.pem"),
				filepath.Join(goldenDir, "certs/ISD1-ASff00_0_112.pem"),
			},
			ignored: []string{
				filepath.Join(goldenDir, "certs/dummy.pem"),
			},
		},
		"invalid dir": {
			inputDir: "./path/to/nowhere",
			setupDB: func(mctlr *gomock.Controller) trust.DB {
				return mock_trust.NewMockDB(mctlr)
			},
			assertFunc: assert.Error,
		},
		"db.SignedTRC error": {
			inputDir: filepath.Join(goldenDir, "certs"),
			setupDB: func(mctlr *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctlr)
				db.EXPECT().SignedTRC(ctxMatcher{},
					TRCIDMatcher{ISD: 1}).Return(
					cppki.SignedTRC{}, serrors.New("db failed")).AnyTimes()
				return db
			},
			assertFunc: assert.Error,
		},
		"db.SignedTRC not found": {
			inputDir: filepath.Join(goldenDir, "certs"),
			setupDB: func(mctlr *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctlr)
				db.EXPECT().SignedTRC(ctxMatcher{},
					TRCIDMatcher{ISD: 1}).AnyTimes().Return(
					cppki.SignedTRC{}, nil,
				)
				return db
			},
			assertFunc: assert.NoError,
			ignored: []string{
				filepath.Join(goldenDir, "certs/ISD1-ASff00_0_110.pem"),
				filepath.Join(goldenDir, "certs/ISD1-ASff00_0_111.pem"),
				filepath.Join(goldenDir, "certs/ISD1-ASff00_0_112.pem"),
				filepath.Join(goldenDir, "certs/dummy.pem"),
			},
		},
		"db.Chain error": {
			inputDir: filepath.Join(goldenDir, "certs"),
			setupDB: func(mctlr *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctlr)
				db.EXPECT().SignedTRC(ctxMatcher{},
					TRCIDMatcher{ISD: 1}).Return(trc, nil).AnyTimes()
				db.EXPECT().InsertChain(ctxMatcher{}, gomock.Any()).Return(
					false, fmt.Errorf("db failed"),
				)
				return db
			},
			assertFunc: assert.Error,
		},
		"invalid TRC validation": {
			inputDir: filepath.Join(goldenDir, "certs"),
			setupDB: func(mctlr *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctlr)
				db.EXPECT().SignedTRC(ctxMatcher{},
					TRCIDMatcher{ISD: 1}).Return(
					cppki.SignedTRC{}, nil).AnyTimes()
				db.EXPECT().InsertChain(ctxMatcher{}, gomock.Any()).Return(true, nil).AnyTimes()
				return db
			},
			assertFunc: assert.NoError,
			ignored: []string{
				filepath.Join(goldenDir, "certs/ISD1-ASff00_0_110.pem"),
				filepath.Join(goldenDir, "certs/ISD1-ASff00_0_111.pem"),
				filepath.Join(goldenDir, "certs/ISD1-ASff00_0_112.pem"),
				filepath.Join(goldenDir, "certs/dummy.pem"),
			},
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctlr := gomock.NewController(t)
			defer ctlr.Finish()
			db := tc.setupDB(ctlr)
			res, err := trust.LoadChains(context.Background(), tc.inputDir, db)
			tc.assertFunc(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, tc.loaded, res.Loaded)

			var ignored []string
			for f := range res.Ignored {
				ignored = append(ignored, f)
			}
			sort.Strings(tc.ignored)
			sort.Strings(ignored)
			assert.Equal(t, tc.ignored, ignored)
		})
	}
}

func TestLoadTRCs(t *testing.T) {
	if *update {
		t.Skip("test crypto is being updated")
	}

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
			inputDir: filepath.Join(goldenDir, "ISD1/trcs"),
			setupDB: func() trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				db.EXPECT().InsertTRC(gomock.Any(), gomock.Any()).Times(2).Return(
					true, nil,
				)
				return db
			},
			assertFunc: assert.NoError,
			loaded: []string{filepath.Join(goldenDir, "ISD1/trcs/ISD1-B1-S1.trc"),
				filepath.Join(goldenDir, "ISD1/trcs/ISD1-B1-S1.pem.trc")},
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
			inputDir: filepath.Join(goldenDir, "ISD1/trcs"),
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
