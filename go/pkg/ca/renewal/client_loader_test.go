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

package renewal_test

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/ca/renewal"
	"github.com/scionproto/scion/go/pkg/ca/renewal/mock_renewal"
)

func TestClientLoaderClientChains(t *testing.T) {
	testCases := map[string]struct {
		prepare   func(t *testing.T, ctrl *gomock.Controller) (string, renewal.DB)
		expected  [][]*x509.Certificate
		assertErr assert.ErrorAssertionFunc
	}{
		"non-existing/empty dir": {
			prepare: func(t *testing.T, ctrl *gomock.Controller) (string, renewal.DB) {
				db := mock_renewal.NewMockDB(ctrl)
				return "not-existing-dir", db
			},
			assertErr: assert.Error,
		},
		"invalid chain": {
			prepare: func(t *testing.T, ctrl *gomock.Controller) (string, renewal.DB) {
				db := mock_renewal.NewMockDB(ctrl)
				return "testdata/common", db
			},
			assertErr: assert.NoError,
		},
		"valid single chain": {
			prepare: func(t *testing.T, ctrl *gomock.Controller) (string, renewal.DB) {
				db := mock_renewal.NewMockDB(ctrl)
				db.EXPECT().InsertClientChain(gomock.Any(), xtest.LoadChain(t,
					"testdata/common/ISD1/ASff00_0_111/crypto/as/ISD1-ASff00_0_111.pem"))
				return "testdata/common/ISD1/ASff00_0_111/crypto/as", db
			},
			assertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			dir, db := tc.prepare(t, ctrl)
			loader := renewal.ClientLoader{
				Dir:      dir,
				ClientDB: db,
			}
			err := loader.LoadClientChains(context.Background())
			tc.assertErr(t, err)
		})
	}
}
