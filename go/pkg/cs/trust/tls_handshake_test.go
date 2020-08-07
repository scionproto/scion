// Copyright 2020 ETH Zurich

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//   http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package trust_test

import (
	"encoding/pem"
	"io/ioutil"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/xtest"
	cs_trust "github.com/scionproto/scion/go/pkg/cs/trust"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/mock_trust"
)

func TestVerifyPeerCertificate(t *testing.T) {
	trc := xtest.LoadTRC(t, "testdata/common/trcs/ISD1-B1-S1.trc")
	crt111File := "testdata/common/ISD1/ASff00_0_111/crypto/as/ISD1-ASff00_0_111.pem"

	testCases := map[string]struct {
		prepare   func(t *testing.T, ctrl *gomock.Controller) (string, trust.DB)
		assertErr assert.ErrorAssertionFunc
	}{
		"valid": {
			prepare: func(t *testing.T, ctrl *gomock.Controller) (string, trust.DB) {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().SignedTRC(gomock.Any(), gomock.Any()).Return(trc, nil)
				return crt111File, db
			},
			assertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			file, db := tc.prepare(t, ctrl)
			rawChain := loadRawChain(t, file)
			mgr := cs_trust.TLSCryptoManager{
				DB: db,
			}
			err := mgr.VerifyPeerCertificate(rawChain, nil)
			tc.assertErr(t, err)
		})
	}
}

func loadRawChain(t *testing.T, file string) [][]byte {
	var chain [][]byte
	raw, err := ioutil.ReadFile(file)
	require.NoError(t, err)
	require.NotEmpty(t, raw)
	for len(raw) > 0 {
		var b *pem.Block
		b, raw = pem.Decode(raw)
		require.NotNil(t, b)
		chain = append(chain, b.Bytes)
	}
	return chain
}
