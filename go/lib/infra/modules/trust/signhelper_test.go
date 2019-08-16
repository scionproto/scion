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

package trust

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/proto"
)

var ia110 = xtest.MustParseIA("1-ff00:0:110")

func TestBasicVerifierVerify(t *testing.T) {
	tests := map[string]struct {
		TSDiff    time.Duration
		Assertion assert.ErrorAssertionFunc
	}{
		"valid": {
			Assertion: assert.NoError,
		},
		"timestamp slightly in future": {
			TSDiff:    500 * time.Millisecond,
			Assertion: assert.NoError,
		},
		"timestamp in future": {
			TSDiff:    time.Hour,
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			store, cancelF := initStore(t, mctrl, ia110, newMessengerMock(mctrl, nil, nil))
			defer cancelF()
			pub, priv, err := scrypto.GenKeyPair(scrypto.Ed25519)
			require.NoError(t, err)

			_, err = store.trustdb.InsertChain(context.Background(), &cert.Chain{
				Leaf: &cert.Certificate{
					Subject:        ia110,
					Issuer:         ia110,
					SignAlgorithm:  scrypto.Ed25519,
					SubjectSignKey: pub,
					Version:        1,
					Signature:      []byte("signature"),
				},
				Issuer: &cert.Certificate{
					Subject:   ia110,
					Issuer:    ia110,
					Version:   1,
					Signature: []byte("signature"),
				},
			})
			require.NoError(t, err)
			verifier := NewBasicVerifier(store)
			src := ctrl.SignSrcDef{
				IA:       ia110,
				ChainVer: 1,
				TRCVer:   1,
			}
			sign := proto.NewSignS(proto.SignType_ed25519, src.Pack())
			sign.SetTimestamp(time.Now().Add(test.TSDiff))
			msg := []byte("test msg")
			sign.Signature, err = scrypto.Sign(sign.SigInput(msg, false), priv, scrypto.Ed25519)
			require.NoError(t, err)
			test.Assertion(t, verifier.Verify(context.Background(), msg, sign))
		})
	}
}
