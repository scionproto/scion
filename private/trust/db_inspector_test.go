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
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/trust"
	"github.com/scionproto/scion/private/trust/mock_trust"
)

type isdInfo struct {
	authoritatives []addr.IA
	cores          []addr.IA
	rootCAs        []addr.IA
}

func (i isdInfo) any() []addr.IA {
	return joinUnique(i.authoritatives, i.cores, i.rootCAs)
}

var attributes = isdInfo{
	authoritatives: []addr.IA{
		addr.MustParseIA("1-ff00:0:110"),
		addr.MustParseIA("1-ff00:0:130"),
		addr.MustParseIA("1-ff00:0:111"),
	},
	cores: []addr.IA{
		addr.MustParseIA("1-ff00:0:110"),
		addr.MustParseIA("1-ff00:0:120"),
		addr.MustParseIA("1-ff00:0:130"),
	},
	rootCAs: []addr.IA{
		addr.MustParseIA("1-ff00:0:110"),
		addr.MustParseIA("1-ff00:0:111"),
	},
}

type byAttrQuery struct {
	ISD   addr.ISD
	Attrs trust.Attribute
}

func TestDBInspectorByAttributes(t *testing.T) {
	trc1 := xtest.LoadTRC(t, "testdata/ISD1-B1-S1.trc")
	testCases := map[string]struct {
		db        func(ctrl *gomock.Controller) trust.DB
		query     byAttrQuery
		expected  []addr.IA
		assertErr assert.ErrorAssertionFunc
	}{
		"valid any": {
			db:        trcDB(trc1),
			query:     byAttrQuery{ISD: 1, Attrs: trust.Any},
			expected:  attributes.any(),
			assertErr: assert.NoError,
		},
		"valid authoritatives": {
			db:        trcDB(trc1),
			query:     byAttrQuery{ISD: 1, Attrs: trust.Authoritative},
			expected:  attributes.authoritatives,
			assertErr: assert.NoError,
		},
		"valid cores": {
			db:        trcDB(trc1),
			query:     byAttrQuery{ISD: 1, Attrs: trust.Core},
			expected:  attributes.cores,
			assertErr: assert.NoError,
		},
		"valid rootCAs": {
			db:        trcDB(trc1),
			query:     byAttrQuery{ISD: 1, Attrs: trust.RootCA},
			expected:  attributes.rootCAs,
			assertErr: assert.NoError,
		},
		"valid rootCAs&cores": {
			db:        trcDB(trc1),
			query:     byAttrQuery{ISD: 1, Attrs: trust.RootCA | trust.Core},
			expected:  intersection(toMap(attributes.rootCAs), toMap(attributes.cores)),
			assertErr: assert.NoError,
		},
		"db error": {
			db:        errorDB,
			query:     byAttrQuery{ISD: 1, Attrs: trust.Any},
			assertErr: assert.Error,
		},
		"trc not found": {
			db:        trcDB(trc1),
			query:     byAttrQuery{ISD: 2, Attrs: trust.Any},
			assertErr: assert.Error,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			i := trust.DBInspector{DB: tc.db(ctrl)}
			ias, err := i.ByAttributes(context.Background(), tc.query.ISD, tc.query.Attrs)
			tc.assertErr(t, err)
			assert.ElementsMatch(t, tc.expected, ias)
		})
	}
}

type hasAttrQuery struct {
	IA    addr.IA
	Attrs trust.Attribute
}

func TestDBInspectorHasAttributes(t *testing.T) {
	trc1 := xtest.LoadTRC(t, "testdata/ISD1-B1-S1.trc")

	testCases := map[string]struct {
		db        func(ctrl *gomock.Controller) trust.DB
		query     hasAttrQuery
		expected  bool
		assertErr assert.ErrorAssertionFunc
	}{
		"valid authoritatives": {
			db: trcDB(trc1),
			query: hasAttrQuery{
				IA:    attributes.authoritatives[0],
				Attrs: trust.Authoritative,
			},
			expected:  true,
			assertErr: assert.NoError,
		},
		"valid cores": {
			db:        trcDB(trc1),
			query:     hasAttrQuery{IA: attributes.cores[0], Attrs: trust.Core},
			expected:  true,
			assertErr: assert.NoError,
		},
		"valid rootCAs": {
			db:        trcDB(trc1),
			query:     hasAttrQuery{IA: attributes.rootCAs[0], Attrs: trust.RootCA},
			expected:  true,
			assertErr: assert.NoError,
		},
		"valid rootCAs&cores": {
			db:        trcDB(trc1),
			query:     hasAttrQuery{IA: attributes.cores[0], Attrs: trust.RootCA & trust.Core},
			expected:  true,
			assertErr: assert.NoError,
		},
		"valid non-primary": {
			db:        trcDB(trc1),
			query:     hasAttrQuery{IA: addr.MustParseIA("1-ff00:0:112"), Attrs: trust.Any},
			expected:  false,
			assertErr: assert.NoError,
		},
		"db error": {
			db:        errorDB,
			query:     hasAttrQuery{IA: attributes.cores[0], Attrs: trust.Any},
			assertErr: assert.Error,
		},
		"trc not found": {
			db:        trcDB(trc1),
			query:     hasAttrQuery{IA: addr.MustParseIA("2-ff00:0:210"), Attrs: trust.Any},
			assertErr: assert.Error,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			i := trust.DBInspector{DB: tc.db(ctrl)}
			has, err := i.HasAttributes(context.Background(), tc.query.IA, tc.query.Attrs)
			tc.assertErr(t, err)
			assert.Equal(t, tc.expected, has)
		})
	}
}

func errorDB(ctrl *gomock.Controller) trust.DB {
	db := mock_trust.NewMockDB(ctrl)
	db.EXPECT().SignedTRC(gomock.Any(), gomock.Any()).
		Return(cppki.SignedTRC{}, serrors.New("test err"))
	return db
}

func trcDB(trc cppki.SignedTRC) func(*gomock.Controller) trust.DB {
	return func(ctrl *gomock.Controller) trust.DB {
		db := mock_trust.NewMockDB(ctrl)
		db.EXPECT().SignedTRC(gomock.Any(), cppki.TRCID{
			ISD:    trc.TRC.ID.ISD,
			Base:   scrypto.LatestVer,
			Serial: scrypto.LatestVer,
		}).Return(trc, nil).AnyTimes()
		db.EXPECT().SignedTRC(gomock.Any(), gomock.Any()).AnyTimes()
		return db
	}
}

func toMap(ias []addr.IA) map[addr.IA]struct{} {
	result := map[addr.IA]struct{}{}
	for _, ia := range ias {
		result[ia] = struct{}{}
	}
	return result
}

func intersection(base map[addr.IA]struct{}, others ...map[addr.IA]struct{}) []addr.IA {
	var result []addr.IA
	inOthers := func(ia addr.IA) bool {
		for _, other := range others {
			if _, ok := other[ia]; !ok {
				return false
			}
		}
		return true
	}
	for ia := range base {
		if inOthers(ia) {
			result = append(result, ia)
		}
	}
	return result
}

func joinUnique(iaLists ...[]addr.IA) []addr.IA {
	uniques := map[addr.IA]struct{}{}
	for _, ias := range iaLists {
		for _, ia := range ias {
			uniques[ia] = struct{}{}
		}
	}
	result := make([]addr.IA, 0, len(uniques))
	for ia := range uniques {
		result = append(result, ia)
	}
	return result
}
