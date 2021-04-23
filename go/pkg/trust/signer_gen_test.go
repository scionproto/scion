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
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/internal/metrics"
	"github.com/scionproto/scion/go/pkg/trust/mock_trust"
)

func TestSignerGenGenerate(t *testing.T) {
	if *update {
		t.Skip("test crypto is being updated")
	}

	getChain := func(t *testing.T) []*x509.Certificate {
		return xtest.LoadChain(t,
			filepath.Join(goldenDir, "ISD1/ASff00_0_110/crypto/as/ISD1-ASff00_0_110.pem"))
	}

	trc := xtest.LoadTRC(t, filepath.Join(goldenDir, "ISD1/trcs/ISD1-B1-S1.trc"))
	key := loadKey(t, filepath.Join(goldenDir, "ISD1/ASff00_0_110/crypto/as/cp-as.key"))
	chain := getChain(t)

	now := time.Now()

	longer := getChain(t)
	longer[0].NotAfter = longer[0].NotAfter.Add(time.Hour)
	longer[0].SubjectKeyId = []byte("longer")

	shorter := getChain(t)
	shorter[0].NotAfter = shorter[0].NotAfter.Add(-time.Hour)
	shorter[0].SubjectKeyId = []byte("shorter")

	testCases := map[string]struct {
		keyRing    func(mctrcl *gomock.Controller) trust.KeyRing
		db         func(mctrcl *gomock.Controller) trust.DB
		assertFunc assert.ErrorAssertionFunc
		expected   trust.Signer
	}{
		"valid": {
			keyRing: func(mctrl *gomock.Controller) trust.KeyRing {
				ring := mock_trust.NewMockKeyRing(mctrl)
				ring.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return ring
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				cert := chain[0]
				db := mock_trust.NewMockDB(mctrl)
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}
				db.EXPECT().SignedTRC(ctxMatcher{}, TRCIDMatcher{ISD: 1}).Return(
					trc, nil,
				)
				db.EXPECT().Chains(ctxMatcher{}, matcher).Return(
					[][]*x509.Certificate{chain}, nil,
				)
				return db
			},
			assertFunc: assert.NoError,
			expected: trust.Signer{
				PrivateKey: key,
				Algorithm:  signed.ECDSAWithSHA256,
				IA:         xtest.MustParseIA("1-ff00:0:110"),
				TRCID: cppki.TRCID{
					ISD:    1,
					Base:   1,
					Serial: 1,
				},
				Subject:      chain[0].Subject,
				Chain:        chain,
				SubjectKeyID: chain[0].SubjectKeyId,
				Expiration:   chain[0].NotAfter,
				ChainValidity: cppki.Validity{
					NotBefore: chain[0].NotBefore,
					NotAfter:  chain[0].NotAfter,
				},
			},
		},
		"select newest": {
			keyRing: func(mctrl *gomock.Controller) trust.KeyRing {
				ring := mock_trust.NewMockKeyRing(mctrl)
				ring.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return ring
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				cert := chain[0]
				db := mock_trust.NewMockDB(mctrl)
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}

				db.EXPECT().SignedTRC(ctxMatcher{}, TRCIDMatcher{ISD: 1}).Return(
					trc, nil,
				)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(
					[][]*x509.Certificate{chain, longer, shorter}, nil,
				)
				return db
			},
			assertFunc: assert.NoError,
			expected: trust.Signer{
				PrivateKey: key,
				Algorithm:  signed.ECDSAWithSHA256,
				IA:         xtest.MustParseIA("1-ff00:0:110"),
				TRCID: cppki.TRCID{
					ISD:    1,
					Base:   1,
					Serial: 1,
				},
				Subject:      chain[0].Subject,
				Chain:        longer,
				SubjectKeyID: []byte("longer"),
				Expiration:   chain[0].NotAfter.Add(time.Hour),
				ChainValidity: cppki.Validity{
					NotBefore: chain[0].NotBefore,
					NotAfter:  chain[0].NotAfter.Add(time.Hour),
				},
			},
		},
		"select best from grace": {
			keyRing: func(mctrl *gomock.Controller) trust.KeyRing {
				ring := mock_trust.NewMockKeyRing(mctrl)
				ring.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return ring
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				cert := chain[0]
				db := mock_trust.NewMockDB(mctrl)
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}

				trc2 := xtest.LoadTRC(t, filepath.Join(goldenDir, "ISD1/trcs/ISD1-B1-S1.trc"))
				trc2.TRC.ID.Serial = 2
				trc2.TRC.Validity.NotBefore = now
				trc2.TRC.GracePeriod = 5 * time.Minute

				roots, err := trc2.TRC.RootCerts()
				require.NoError(t, err)
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				for _, root := range roots {
					root.PublicKey = key.Public()
				}
				db.EXPECT().SignedTRC(ctxMatcher{}, TRCIDMatcher{ISD: 1}).Return(
					trc2, nil,
				)
				db.EXPECT().SignedTRC(ctxMatcher{}, TRCIDMatcher{ISD: 1}).Return(
					trc, nil,
				)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(
					[][]*x509.Certificate{chain, longer, shorter}, nil,
				)
				return db
			},
			assertFunc: assert.NoError,
			expected: trust.Signer{
				PrivateKey: key,
				Algorithm:  signed.ECDSAWithSHA256,
				IA:         xtest.MustParseIA("1-ff00:0:110"),
				TRCID: cppki.TRCID{
					ISD:    1,
					Base:   1,
					Serial: 2,
				},
				Subject:      chain[0].Subject,
				Chain:        longer,
				SubjectKeyID: []byte("longer"),
				Expiration:   now.Add(5 * time.Minute),
				ChainValidity: cppki.Validity{
					NotBefore: chain[0].NotBefore,
					NotAfter:  chain[0].NotAfter.Add(time.Hour),
				},
				InGrace: true,
			},
		},
		"no keys": {
			keyRing: func(mctrl *gomock.Controller) trust.KeyRing {
				ring := mock_trust.NewMockKeyRing(mctrl)
				ring.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{}, nil,
				)
				return ring
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				return mock_trust.NewMockDB(mctrl)
			},
			assertFunc: assert.Error,
		},
		"rsa key": {
			keyRing: func(mctrl *gomock.Controller) trust.KeyRing {
				ring := mock_trust.NewMockKeyRing(mctrl)
				priv, err := rsa.GenerateKey(rand.Reader, 512)
				require.NoError(t, err)

				ring.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{priv}, nil,
				)
				return ring
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				db.EXPECT().SignedTRC(ctxMatcher{}, TRCIDMatcher{ISD: 1}).Return(
					trc, nil,
				)
				return db
			},
			assertFunc: assert.Error,
		},
		"no chain found": {
			keyRing: func(mctrl *gomock.Controller) trust.KeyRing {
				ring := mock_trust.NewMockKeyRing(mctrl)
				ring.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return ring
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				cert := chain[0]
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}
				db.EXPECT().SignedTRC(ctxMatcher{},
					TRCIDMatcher{ISD: 1}).Return(trc, nil)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(nil, nil)
				return db
			},
			assertFunc: assert.Error,
		},
		"db.SignedTRC error": {
			keyRing: func(mctrl *gomock.Controller) trust.KeyRing {
				ring := mock_trust.NewMockKeyRing(mctrl)
				ring.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return ring
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				db.EXPECT().SignedTRC(ctxMatcher{},
					TRCIDMatcher{ISD: 1}).Return(
					cppki.SignedTRC{}, serrors.New("fail"))
				return db
			},
			assertFunc: assert.Error,
		},
		"db.SignedTRC not found": {
			keyRing: func(mctrl *gomock.Controller) trust.KeyRing {
				ring := mock_trust.NewMockKeyRing(mctrl)
				ring.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return ring
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				db.EXPECT().SignedTRC(ctxMatcher{}, TRCIDMatcher{ISD: 1}).Return(
					cppki.SignedTRC{}, nil)
				return db
			},
			assertFunc: assert.Error,
		},
		"db.Chain error": {
			keyRing: func(mctrl *gomock.Controller) trust.KeyRing {
				ring := mock_trust.NewMockKeyRing(mctrl)
				ring.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return ring
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				cert := chain[0]
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}
				db.EXPECT().SignedTRC(ctxMatcher{},
					TRCIDMatcher{ISD: 1}).Return(trc, nil)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(
					nil, serrors.New("fail"),
				)
				return db
			},
			assertFunc: assert.Error,
		},
	}

	metrics.Signer.Signers.Reset()
	t.Run("cases", func(t *testing.T) {
		for name, tc := range testCases {
			name, tc := name, tc
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				mctrl := gomock.NewController(t)
				defer mctrl.Finish()

				gen := trust.SignerGen{
					IA:      xtest.MustParseIA("1-ff00:0:110"),
					DB:      tc.db(mctrl),
					KeyRing: tc.keyRing(mctrl),
				}
				signer, err := gen.Generate(context.Background())
				tc.assertFunc(t, err)
				assert.Equal(t, tc.expected, signer)
			})
		}
	})
	t.Run("metrics", func(t *testing.T) {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		// Ensure the gauge is set to the expected value.
		ring := mock_trust.NewMockKeyRing(mctrl)
		ring.EXPECT().PrivateKeys(gomock.Any()).Return([]crypto.Signer{key}, nil)
		db := mock_trust.NewMockDB(mctrl)
		db.EXPECT().SignedTRC(gomock.Any(), gomock.Any()).Return(trc, nil)
		db.EXPECT().Chains(gomock.Any(), gomock.Any()).Return(
			[][]*x509.Certificate{chain}, nil,
		)
		_, err := trust.SignerGen{
			IA:      xtest.MustParseIA("1-ff00:0:110"),
			DB:      db,
			KeyRing: ring,
		}.Generate(context.Background())
		require.NoError(t, err)

		s := "trustengine_generated_signers_total"
		want := fmt.Sprintf(`
# HELP %s Number of generated signers backed by the trust engine
# TYPE %s counter
trustengine_generated_signers_total{result="err_db"} 2
trustengine_generated_signers_total{result="err_key"} 1
trustengine_generated_signers_total{result="err_not_found"} 3
trustengine_generated_signers_total{result="ok_success"} 4
`, s, s)
		err = testutil.CollectAndCompare(metrics.Signer.Signers, strings.NewReader(want))
		require.NoError(t, err)
	})
}
