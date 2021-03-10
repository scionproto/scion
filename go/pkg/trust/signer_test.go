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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/xtest"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/internal/metrics"
)

func TestSignerSign(t *testing.T) {
	testCases := map[string]struct {
		Curve elliptic.Curve
		Hash  crypto.Hash
	}{
		"P256-SHA512": {
			Curve: elliptic.P256(),
		},
		"P384-SHA512": {
			Curve: elliptic.P384(),
		},
		"P521-SHA512": {
			Curve: elliptic.P521(),
		},
	}
	metrics.Signer.Signatures.Reset()
	msg := []byte("some trustworthy message")
	t.Run("cases", func(t *testing.T) {
		for name, tc := range testCases {
			name, tc := name, tc
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				priv, err := ecdsa.GenerateKey(tc.Curve, rand.Reader)
				require.NoError(t, err)

				signer := trust.Signer{
					PrivateKey: priv,
					Algorithm:  signed.ECDSAWithSHA512,
					IA:         xtest.MustParseIA("1-ff00:0:110"),
					TRCID: cppki.TRCID{
						ISD:    1,
						Base:   1,
						Serial: 1,
					},
					SubjectKeyID: []byte{0, 1, 2, 3, 4, 5, 6, 7},
					Expiration:   time.Now().Add(2 * time.Hour),
				}
				signedMsg, err := signer.Sign(context.Background(), msg)
				require.NoError(t, err)

				hdr, err := signed.ExtractUnverifiedHeader(signedMsg)
				require.NoError(t, err)
				assert.WithinDuration(t, time.Now(), hdr.Timestamp, 5*time.Second)

				var keyID cppb.VerificationKeyID
				require.NoError(t, proto.Unmarshal(hdr.VerificationKeyID, &keyID))

				assert.Equal(t, xtest.MustParseIA("1-ff00:0:110"), addr.IAInt(keyID.IsdAs).IA())
				assert.Equal(t, []byte{0, 1, 2, 3, 4, 5, 6, 7}, keyID.SubjectKeyId)

				_, err = signed.Verify(signedMsg, signer.PrivateKey.Public())
				require.NoError(t, err)
			})
		}
	})

	t.Run("metrics", func(t *testing.T) {
		want := fmt.Sprintf(`
			# HELP %s Number of signatures created with a signer backed by the trust engine
			# TYPE %s counter
			trustengine_created_signatures_total{result="ok_success"} %d
			`, "trustengine_created_signatures_total", "trustengine_created_signatures_total", 3)
		err := testutil.CollectAndCompare(metrics.Signer.Signatures, strings.NewReader(want))
		require.NoError(t, err)
	})

	t.Run("expired fails", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		signer := trust.Signer{
			PrivateKey: priv,
			Algorithm:  signed.ECDSAWithSHA512,
			IA:         xtest.MustParseIA("1-ff00:0:110"),
			TRCID: cppki.TRCID{
				ISD:    1,
				Base:   1,
				Serial: 1,
			},
			SubjectKeyID: []byte{0, 1, 2, 3, 4, 5, 6, 7},
			Expiration:   time.Now().Add(-time.Second),
		}
		sign, err := signer.Sign(context.Background(), msg)
		assert.Error(t, err)
		assert.Nil(t, sign)
	})
}
