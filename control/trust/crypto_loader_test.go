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
	"crypto/x509"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	cstrust "github.com/scionproto/scion/control/trust"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/private/trust"
	"github.com/scionproto/scion/private/trust/mock_trust"
)

func TestChainLoaderChains(t *testing.T) {
	dir := genCrypto(t)

	trc := xtest.LoadTRC(t, filepath.Join(dir, "trcs/ISD1-B1-S1.trc"))
	testCases := map[string]struct {
		prepare   func(t *testing.T, ctrl *gomock.Controller) (string, trust.DB)
		expected  [][]*x509.Certificate
		assertErr assert.ErrorAssertionFunc
	}{
		"non-existing/empty dir": {
			prepare: func(t *testing.T, ctrl *gomock.Controller) (string, trust.DB) {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().Chains(gomock.Any(), gomock.Any())
				return "not-existing-dir", db
			},
			assertErr: assert.NoError,
		},
		"invalid chain": {
			prepare: func(t *testing.T, ctrl *gomock.Controller) (string, trust.DB) {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().Chains(gomock.Any(), gomock.Any())
				return dir, db
			},
			assertErr: assert.NoError,
		},
		"valid single chain": {
			prepare: func(t *testing.T, ctrl *gomock.Controller) (string, trust.DB) {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().InsertChain(
					gomock.Any(),
					xtest.LoadChain(
						t,
						filepath.Join(dir, "ISD1/ASff00_0_111/crypto/as/ISD1-ASff00_0_111.pem"),
					),
				)
				db.EXPECT().Chains(gomock.Any(), gomock.Any())
				db.EXPECT().SignedTRC(gomock.Any(), gomock.Any()).Return(trc, nil)
				return filepath.Join(dir, "ISD1/ASff00_0_111/crypto/as"), db
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
			loader := cstrust.CryptoLoader{
				TRCDirs: []string{"./non-existing"},
				Dir:     dir,
				DB:      db,
			}
			chains, err := loader.Chains(context.Background(), trust.ChainQuery{})
			tc.assertErr(t, err)
			assert.Equal(t, tc.expected, chains)
		})
	}
}
