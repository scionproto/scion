// Copyright 2022 ETH Zurich
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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/trust"
	"github.com/scionproto/scion/private/trust/mock_trust"
)

func TestLoadServerKeyPair(t *testing.T) {
	dir := genCrypto(t)

	trc := xtest.LoadTRC(t, filepath.Join(dir, "trcs/ISD1-B1-S1.trc"))
	key := loadSigner(t, filepath.Join(dir, "ISD1/ASff00_0_110/crypto/as/cp-as.key"))

	chain := getChain(t, dir)
	longer := getChain(t, dir)
	longer[0].NotAfter = longer[0].NotAfter.Add(time.Hour)
	longer[0].SubjectKeyId = []byte("longer")

	shorter := getChain(t, dir)
	shorter[0].NotAfter = shorter[0].NotAfter.Add(-time.Hour)
	shorter[0].SubjectKeyId = []byte("shorter")

	longestKey := loadSigner(t, filepath.Join(dir, "ISD1/ASff00_0_111/crypto/as/cp-as.key"))
	longestChain := xtest.LoadChain(t,
		filepath.Join(dir, "ISD1/ASff00_0_111/crypto/as/ISD1-ASff00_0_111.pem"))
	longestChain[0].NotAfter = longestChain[0].NotAfter.Add(2 * time.Hour)
	longestChain[0].SubjectKeyId = []byte("longest")

	testCases := map[string]struct {
		keyLoader    func(mctrcl *gomock.Controller) trust.KeyRing
		db           func(mctrcl *gomock.Controller) trust.DB
		assertFunc   assert.ErrorAssertionFunc
		expectedCert func() *tls.Certificate
	}{
		"valid": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				cert := chain[0]
				db := mock_trust.NewMockDB(mctrl)
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}
				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1}).Return(
					trc, nil,
				)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(
					[][]*x509.Certificate{chain}, nil,
				)
				return db
			},
			assertFunc: assert.NoError,
			expectedCert: func() *tls.Certificate {
				certificate := make([][]byte, len(chain))
				for i := range chain {
					certificate[i] = chain[i].Raw
				}
				return &tls.Certificate{
					Certificate: certificate,
					PrivateKey:  key,
					Leaf:        chain[0],
				}
			},
		},
		"newest": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				cert := chain[0]
				db := mock_trust.NewMockDB(mctrl)
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}

				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1}).Return(
					trc, nil,
				)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(
					[][]*x509.Certificate{chain, longer, shorter}, nil,
				)
				return db
			},
			assertFunc: assert.NoError,
			expectedCert: func() *tls.Certificate {
				certificate := make([][]byte, len(longer))
				for i := range longer {
					certificate[i] = longer[i].Raw
				}
				return &tls.Certificate{
					Certificate: certificate,
					PrivateKey:  key,
					Leaf:        longer[0],
				}
			},
		},
		"newest multiple keys": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {

				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key, longestKey}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)

				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1}).Return(
					trc, nil,
				)
				db.EXPECT().Chains(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
					func(
						_ context.Context,
						chainQuery trust.ChainQuery,
					) ([][]*x509.Certificate, error) {
						skid, err := cppki.SubjectKeyID(longestKey.Public())
						if err != nil {
							return nil, err
						}
						if bytes.Equal(chainQuery.SubjectKeyID, skid) {
							return [][]*x509.Certificate{longestChain}, nil
						}
						return [][]*x509.Certificate{chain, longer, shorter}, nil
					},
				)
				return db
			},
			assertFunc: assert.NoError,
			expectedCert: func() *tls.Certificate {
				certificate := make([][]byte, len(longestChain))
				for i := range longer {
					certificate[i] = longestChain[i].Raw
				}
				return &tls.Certificate{
					Certificate: certificate,
					PrivateKey:  key,
					Leaf:        longestChain[0],
				}
			},
		},
		"select best from grace": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				cert := chain[0]
				db := mock_trust.NewMockDB(mctrl)
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}

				trc2 := xtest.LoadTRC(t, filepath.Join(dir, "ISD1/trcs/ISD1-B1-S1.trc"))
				trc2.TRC.ID.Serial = 2
				trc2.TRC.Validity.NotBefore = time.Now()
				trc2.TRC.GracePeriod = 5 * time.Minute

				roots, err := trc2.TRC.RootCerts()
				require.NoError(t, err)
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				for _, root := range roots {
					root.PublicKey = key.Public()
				}
				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1}).Return(
					trc2, nil,
				)
				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1, Serial: 1, Base: 1}).Return(
					trc, nil,
				)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(
					[][]*x509.Certificate{chain, longer, shorter}, nil,
				)
				return db
			},
			assertFunc: assert.NoError,
			expectedCert: func() *tls.Certificate {
				certificate := make([][]byte, len(chain))
				for i := range chain {
					certificate[i] = longer[i].Raw
				}
				return &tls.Certificate{
					Certificate: certificate,
					PrivateKey:  key,
					Leaf:        longer[0],
				}
			},
		},
		"no keys": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				return mock_trust.NewMockDB(mctrl)
			},
			assertFunc: assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
		"rsa key": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)

				priv, err := rsa.GenerateKey(rand.Reader, 512)
				require.NoError(t, err)

				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{priv}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1}).Return(
					trc, nil,
				)
				return db
			},
			assertFunc: assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
		"no chain found": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				cert := chain[0]
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}
				db.EXPECT().SignedTRC(ctxMatcher{},
					cppki.TRCID{ISD: 1}).Return(trc, nil)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(nil, nil)
				return db
			},
			assertFunc: assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
		"db.SignedTRC error": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				db.EXPECT().SignedTRC(ctxMatcher{},
					cppki.TRCID{ISD: 1}).Return(
					cppki.SignedTRC{}, serrors.New("fail"))
				return db
			},
			assertFunc: assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
		"db.SignedTRC not found": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1}).Return(
					cppki.SignedTRC{}, nil)
				return db
			},
			assertFunc: assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
		"db.Chain error": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				cert := chain[0]
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}
				db.EXPECT().SignedTRC(ctxMatcher{},
					cppki.TRCID{ISD: 1}).Return(trc, nil)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(
					nil, serrors.New("fail"),
				)
				return db
			},
			assertFunc: assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
		"correct EKU": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				invalidExtChain := getChain(t, dir)
				invalidExtChain[0].ExtKeyUsage = []x509.ExtKeyUsage{
					x509.ExtKeyUsageClientAuth,
					x509.ExtKeyUsageTimeStamping,
				}
				validExtChain := getChain(t, dir)
				validExtChain[0].ExtKeyUsage = []x509.ExtKeyUsage{
					x509.ExtKeyUsageServerAuth,
					x509.ExtKeyUsageTimeStamping,
				}
				cert := validExtChain[0]
				db := mock_trust.NewMockDB(mctrl)
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}
				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1}).Return(
					trc, nil,
				)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(
					[][]*x509.Certificate{invalidExtChain, validExtChain}, nil,
				)
				return db
			},
			assertFunc: assert.NoError,
			expectedCert: func() *tls.Certificate {
				validExtChain := getChain(t, dir)
				validExtChain[0].ExtKeyUsage = []x509.ExtKeyUsage{
					x509.ExtKeyUsageServerAuth,
					x509.ExtKeyUsageTimeStamping,
				}
				certificate := make([][]byte, len(validExtChain))
				for i := range validExtChain {
					certificate[i] = validExtChain[i].Raw
				}
				return &tls.Certificate{
					Certificate: certificate,
					PrivateKey:  key,
					Leaf:        validExtChain[0],
				}
			},
		},
		"wrong EKU": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				extChain := getChain(t, dir)
				extChain[0].ExtKeyUsage = []x509.ExtKeyUsage{
					x509.ExtKeyUsageClientAuth,
					x509.ExtKeyUsageTimeStamping,
				}
				cert := extChain[0]
				db := mock_trust.NewMockDB(mctrl)
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}
				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1}).Return(
					trc, nil,
				)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(
					[][]*x509.Certificate{extChain}, nil,
				)
				return db
			},
			assertFunc: assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()

			provider := trust.X509KeyPairProvider{
				IA:        xtest.MustParseIA("1-ff00:0:110"),
				DB:        tc.db(mctrl),
				KeyLoader: tc.keyLoader(mctrl),
			}
			tlsCert, err := provider.LoadServerKeyPair(context.Background())
			tc.assertFunc(t, err)
			if err == nil {
				assert.Equal(t, tc.expectedCert().Leaf.SubjectKeyId, tlsCert.Leaf.SubjectKeyId)
			}
		})
	}
}

func TestLoadClientKeyPair(t *testing.T) {
	dir := genCrypto(t)

	trc := xtest.LoadTRC(t, filepath.Join(dir, "trcs/ISD1-B1-S1.trc"))
	key := loadSigner(t, filepath.Join(dir, "ISD1/ASff00_0_110/crypto/as/cp-as.key"))

	chain := getChain(t, dir)
	longer := getChain(t, dir)
	longer[0].NotAfter = longer[0].NotAfter.Add(time.Hour)
	longer[0].SubjectKeyId = []byte("longer")

	shorter := getChain(t, dir)
	shorter[0].NotAfter = shorter[0].NotAfter.Add(-time.Hour)
	shorter[0].SubjectKeyId = []byte("shorter")

	longestKey := loadSigner(t, filepath.Join(dir, "ISD1/ASff00_0_111/crypto/as/cp-as.key"))
	longestChain := xtest.LoadChain(t,
		filepath.Join(dir, "ISD1/ASff00_0_111/crypto/as/ISD1-ASff00_0_111.pem"))
	longestChain[0].NotAfter = longestChain[0].NotAfter.Add(2 * time.Hour)
	longestChain[0].SubjectKeyId = []byte("longest")

	testCases := map[string]struct {
		keyLoader    func(mctrcl *gomock.Controller) trust.KeyRing
		db           func(mctrcl *gomock.Controller) trust.DB
		assertFunc   assert.ErrorAssertionFunc
		expectedCert func() *tls.Certificate
	}{
		"valid": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				cert := chain[0]
				db := mock_trust.NewMockDB(mctrl)
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}
				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1}).Return(
					trc, nil,
				)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(
					[][]*x509.Certificate{chain}, nil,
				)
				return db
			},
			assertFunc: assert.NoError,
			expectedCert: func() *tls.Certificate {
				certificate := make([][]byte, len(chain))
				for i := range chain {
					certificate[i] = chain[i].Raw
				}
				return &tls.Certificate{
					Certificate: certificate,
					PrivateKey:  key,
					Leaf:        chain[0],
				}
			},
		},
		"newest": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				cert := chain[0]
				db := mock_trust.NewMockDB(mctrl)
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}

				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1}).Return(
					trc, nil,
				)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(
					[][]*x509.Certificate{chain, longer, shorter}, nil,
				)
				return db
			},
			assertFunc: assert.NoError,
			expectedCert: func() *tls.Certificate {
				certificate := make([][]byte, len(longer))
				for i := range longer {
					certificate[i] = longer[i].Raw
				}
				return &tls.Certificate{
					Certificate: certificate,
					PrivateKey:  key,
					Leaf:        longer[0],
				}
			},
		},
		"newest multiple keys": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {

				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key, longestKey}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)

				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1}).Return(
					trc, nil,
				)
				db.EXPECT().Chains(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
					func(
						_ context.Context,
						chainQuery trust.ChainQuery,
					) ([][]*x509.Certificate, error) {
						skid, err := cppki.SubjectKeyID(longestKey.Public())
						if err != nil {
							return nil, err
						}
						if bytes.Equal(chainQuery.SubjectKeyID, skid) {
							return [][]*x509.Certificate{longestChain}, nil
						}
						return [][]*x509.Certificate{chain, longer, shorter}, nil
					},
				)
				return db
			},
			assertFunc: assert.NoError,
			expectedCert: func() *tls.Certificate {
				certificate := make([][]byte, len(longestChain))
				for i := range longer {
					certificate[i] = longestChain[i].Raw
				}
				return &tls.Certificate{
					Certificate: certificate,
					PrivateKey:  key,
					Leaf:        longestChain[0],
				}
			},
		},
		"select best from grace": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				cert := chain[0]
				db := mock_trust.NewMockDB(mctrl)
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}

				trc2 := xtest.LoadTRC(t, filepath.Join(dir, "ISD1/trcs/ISD1-B1-S1.trc"))
				trc2.TRC.ID.Serial = 2
				trc2.TRC.Validity.NotBefore = time.Now()
				trc2.TRC.GracePeriod = 5 * time.Minute

				roots, err := trc2.TRC.RootCerts()
				require.NoError(t, err)
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				for _, root := range roots {
					root.PublicKey = key.Public()
				}
				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1}).Return(
					trc2, nil,
				)
				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1, Serial: 1, Base: 1}).Return(
					trc, nil,
				)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(
					[][]*x509.Certificate{chain, longer, shorter}, nil,
				)
				return db
			},
			assertFunc: assert.NoError,
			expectedCert: func() *tls.Certificate {
				certificate := make([][]byte, len(chain))
				for i := range chain {
					certificate[i] = longer[i].Raw
				}
				return &tls.Certificate{
					Certificate: certificate,
					PrivateKey:  key,
					Leaf:        longer[0],
				}
			},
		},
		"no keys": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				return mock_trust.NewMockDB(mctrl)
			},
			assertFunc: assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
		"rsa key": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)

				priv, err := rsa.GenerateKey(rand.Reader, 512)
				require.NoError(t, err)

				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{priv}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1}).Return(
					trc, nil,
				)
				return db
			},
			assertFunc: assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
		"no chain found": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				cert := chain[0]
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}
				db.EXPECT().SignedTRC(ctxMatcher{},
					cppki.TRCID{ISD: 1}).Return(trc, nil)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(nil, nil)
				return db
			},
			assertFunc: assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
		"db.SignedTRC error": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				db.EXPECT().SignedTRC(ctxMatcher{},
					cppki.TRCID{ISD: 1}).Return(
					cppki.SignedTRC{}, serrors.New("fail"))
				return db
			},
			assertFunc: assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
		"db.SignedTRC not found": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1}).Return(
					cppki.SignedTRC{}, nil)
				return db
			},
			assertFunc: assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
		"db.Chain error": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				cert := chain[0]
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}
				db.EXPECT().SignedTRC(ctxMatcher{},
					cppki.TRCID{ISD: 1}).Return(trc, nil)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(
					nil, serrors.New("fail"),
				)
				return db
			},
			assertFunc: assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
		"correct EKU": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				invalidExtChain := getChain(t, dir)
				invalidExtChain[0].ExtKeyUsage = []x509.ExtKeyUsage{
					x509.ExtKeyUsageClientAuth,
					x509.ExtKeyUsageTimeStamping,
				}
				validExtChain := getChain(t, dir)
				validExtChain[0].ExtKeyUsage = []x509.ExtKeyUsage{
					x509.ExtKeyUsageServerAuth,
					x509.ExtKeyUsageTimeStamping,
				}
				cert := validExtChain[0]
				db := mock_trust.NewMockDB(mctrl)
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}
				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1}).Return(
					trc, nil,
				)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(
					[][]*x509.Certificate{invalidExtChain, validExtChain}, nil,
				)
				return db
			},
			assertFunc: assert.NoError,
			expectedCert: func() *tls.Certificate {
				validExtChain := getChain(t, dir)
				validExtChain[0].ExtKeyUsage = []x509.ExtKeyUsage{
					x509.ExtKeyUsageServerAuth,
					x509.ExtKeyUsageTimeStamping,
				}
				certificate := make([][]byte, len(validExtChain))
				for i := range validExtChain {
					certificate[i] = validExtChain[i].Raw
				}
				return &tls.Certificate{
					Certificate: certificate,
					PrivateKey:  key,
					Leaf:        validExtChain[0],
				}
			},
		},
		"wrong EKU": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				extChain := getChain(t, dir)
				extChain[0].ExtKeyUsage = []x509.ExtKeyUsage{
					x509.ExtKeyUsageClientAuth,
					x509.ExtKeyUsageTimeStamping,
				}
				cert := extChain[0]
				db := mock_trust.NewMockDB(mctrl)
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}
				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1}).Return(
					trc, nil,
				)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(
					[][]*x509.Certificate{extChain}, nil,
				)
				return db
			},
			assertFunc: assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()

			provider := trust.X509KeyPairProvider{
				IA:        xtest.MustParseIA("1-ff00:0:110"),
				DB:        tc.db(mctrl),
				KeyLoader: tc.keyLoader(mctrl),
			}
			tlsCert, err := provider.LoadClientKeyPair(context.Background())
			tc.assertFunc(t, err)
			if err == nil {
				assert.Equal(t, tc.expectedCert().Leaf.SubjectKeyId, tlsCert.Leaf.SubjectKeyId)
			}
		})
	}
}
func getChain(t *testing.T, dir string) []*x509.Certificate {
	return xtest.LoadChain(t,
		filepath.Join(dir, "ISD1/ASff00_0_110/crypto/as/ISD1-ASff00_0_110.pem"))
}

func loadSigner(t *testing.T, file string) crypto.Signer {
	raw, err := os.ReadFile(file)
	require.NoError(t, err)
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		panic("no valid private key block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	return key.(crypto.Signer)
}
