// Copyright 2026 SCION Association
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

package signed_test

import (
	"crypto/mldsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pbcrypto "github.com/scionproto/scion/pkg/proto/crypto"
	"github.com/scionproto/scion/pkg/scrypto/signed"
)

func TestSelectSignatureAlgorithmMLDSA(t *testing.T) {
	testCases := []struct {
		name    string
		params  mldsa.Parameters
		want    signed.SignatureAlgorithm
		wantPB  pbcrypto.SignatureAlgorithm
		wantStr string
	}{
		{
			name:    "MLDSA44",
			params:  mldsa.MLDSA44(),
			want:    signed.MLDSA44,
			wantPB:  pbcrypto.SignatureAlgorithm_SIGNATURE_ALGORITHM_ML_DSA_44,
			wantStr: "ML-DSA-44",
		},
		{
			name:    "MLDSA65",
			params:  mldsa.MLDSA65(),
			want:    signed.MLDSA65,
			wantPB:  pbcrypto.SignatureAlgorithm_SIGNATURE_ALGORITHM_ML_DSA_65,
			wantStr: "ML-DSA-65",
		},
		{
			name:    "MLDSA87",
			params:  mldsa.MLDSA87(),
			want:    signed.MLDSA87,
			wantPB:  pbcrypto.SignatureAlgorithm_SIGNATURE_ALGORITHM_ML_DSA_87,
			wantStr: "ML-DSA-87",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sk, err := mldsa.GenerateKey(tc.params)
			require.NoError(t, err)
			got, err := signed.SelectSignatureAlgorithm(sk.Public())
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)

			// Protobuf round-trip: enum → PB → enum must be identity.
			pb := signed.SignatureAlgorithmToPB(tc.want)
			assert.Equal(t, tc.wantPB, pb)
			assert.Equal(t, tc.want, signed.SignatureAlgorithmFromPB(pb))

			// String() must return the IANA/spec name.
			assert.Equal(t, tc.wantStr, tc.want.String())
		})
	}
}
