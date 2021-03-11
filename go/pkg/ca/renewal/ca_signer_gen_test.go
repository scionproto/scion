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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/ca/renewal"
	"github.com/scionproto/scion/go/pkg/ca/renewal/mock_renewal"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/mock_trust"
)

func TestChachingPolicyGenGenerate(t *testing.T) {
	otherValidity := time.Hour
	ca := xtest.LoadChain(t, "testdata/common/ISD1/ASff00_0_110/crypto/ca/ISD1-ASff00_0_110.ca.crt")
	cert := ca[0]

	testCases := map[string]struct {
		Interval     time.Duration
		PolicyGen    func(mctrl *gomock.Controller) renewal.PolicyGen
		FirstErr     assert.ErrorAssertionFunc
		FirstPolicy  cppki.CAPolicy
		SecondErr    assert.ErrorAssertionFunc
		SecondPolicy cppki.CAPolicy
	}{
		"valid": {
			Interval: time.Hour,
			PolicyGen: func(mctrl *gomock.Controller) renewal.PolicyGen {
				gen := mock_renewal.NewMockPolicyGen(mctrl)
				gen.EXPECT().Generate(gomock.Any()).Return(
					cppki.CAPolicy{Certificate: cert}, nil,
				)
				return gen
			},
			FirstErr:     assert.NoError,
			FirstPolicy:  cppki.CAPolicy{Certificate: cert},
			SecondErr:    assert.NoError,
			SecondPolicy: cppki.CAPolicy{Certificate: cert},
		},
		"valid, regenerate after interval": {
			Interval: 0,
			PolicyGen: func(mctrl *gomock.Controller) renewal.PolicyGen {
				gen := mock_renewal.NewMockPolicyGen(mctrl)
				gen.EXPECT().Generate(gomock.Any()).Return(
					cppki.CAPolicy{Certificate: cert}, nil,
				)
				gen.EXPECT().Generate(gomock.Any()).Return(
					cppki.CAPolicy{Certificate: cert, Validity: otherValidity}, nil,
				)
				return gen
			},
			FirstErr:     assert.NoError,
			FirstPolicy:  cppki.CAPolicy{Certificate: cert},
			SecondErr:    assert.NoError,
			SecondPolicy: cppki.CAPolicy{Certificate: cert, Validity: otherValidity},
		},
		"first fails, second cached": {
			Interval: time.Hour,
			PolicyGen: func(mctrl *gomock.Controller) renewal.PolicyGen {
				gen := mock_renewal.NewMockPolicyGen(mctrl)
				gen.EXPECT().Generate(gomock.Any()).Return(
					cppki.CAPolicy{}, serrors.New("internal"),
				)
				return gen
			},
			FirstErr:  assert.Error,
			SecondErr: assert.Error,
		},
		"first fails, second succeeds": {
			Interval: 0,
			PolicyGen: func(mctrl *gomock.Controller) renewal.PolicyGen {
				gen := mock_renewal.NewMockPolicyGen(mctrl)
				gen.EXPECT().Generate(gomock.Any()).Return(
					cppki.CAPolicy{}, serrors.New("internal"),
				)
				gen.EXPECT().Generate(gomock.Any()).Return(
					cppki.CAPolicy{Certificate: cert}, nil,
				)
				return gen
			},
			FirstErr:     assert.Error,
			SecondErr:    assert.NoError,
			SecondPolicy: cppki.CAPolicy{Certificate: cert},
		},
		"second fails, do not serve cached": {
			Interval: 0,
			PolicyGen: func(mctrl *gomock.Controller) renewal.PolicyGen {
				gen := mock_renewal.NewMockPolicyGen(mctrl)
				gen.EXPECT().Generate(gomock.Any()).Return(
					cppki.CAPolicy{Certificate: cert}, nil,
				)
				gen.EXPECT().Generate(gomock.Any()).Return(
					cppki.CAPolicy{}, serrors.New("internal"),
				)
				return gen
			},
			FirstErr:    assert.NoError,
			FirstPolicy: cppki.CAPolicy{Certificate: cert},
			SecondErr:   assert.Error,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mctrl := gomock.NewController(t)
			gen := renewal.CachingPolicyGen{
				Interval:  tc.Interval,
				PolicyGen: tc.PolicyGen(mctrl),
			}
			policy, err := gen.Generate(context.Background())
			if tc.FirstErr(t, err) {
				assert.Equal(t, tc.FirstPolicy, policy)
			}
			policy, err = gen.Generate(context.Background())
			if tc.SecondErr(t, err) {
				assert.Equal(t, tc.SecondPolicy, policy)
			}
		})
	}
}

func TestLoadingPolicyGenGenerate(t *testing.T) {
	ca := xtest.LoadChain(t, "testdata/common/ISD1/ASff00_0_110/crypto/ca/ISD1-ASff00_0_110.ca.crt")
	key := loadKey(t, "testdata/common/ISD1/ASff00_0_110/crypto/ca/cp-ca.key")

	testCases := map[string]struct {
		CertProvider func(*testing.T, *gomock.Controller) renewal.CACertProvider
		KeyRing      func(*testing.T, *gomock.Controller) trust.KeyRing
		ErrAssertion assert.ErrorAssertionFunc
	}{
		"valid": {
			CertProvider: func(t *testing.T, mctrl *gomock.Controller) renewal.CACertProvider {
				p := mock_renewal.NewMockCACertProvider(mctrl)
				p.EXPECT().CACerts(gomock.Any()).Return(ca, nil)
				return p
			},
			KeyRing: func(t *testing.T, mctrl *gomock.Controller) trust.KeyRing {
				k := mock_trust.NewMockKeyRing(mctrl)
				k.EXPECT().PrivateKeys(gomock.Any()).Return([]crypto.Signer{key}, nil)
				return k
			},
			ErrAssertion: assert.NoError,
		},
		"multi": {
			CertProvider: func(t *testing.T, mctrl *gomock.Controller) renewal.CACertProvider {
				p := mock_renewal.NewMockCACertProvider(mctrl)
				shorter := xtest.LoadChain(t,
					"testdata/common/ISD1/ASff00_0_110/crypto/ca/ISD1-ASff00_0_110.ca.crt")
				shorter[0].NotAfter = ca[0].NotAfter.Add(-time.Minute)
				longer := xtest.LoadChain(t,
					"testdata/common/ISD1/ASff00_0_110/crypto/ca/ISD1-ASff00_0_110.ca.crt")
				longer[0].NotAfter = ca[0].NotAfter.Add(time.Minute)
				longer[0].SubjectKeyId[0] ^= 0xFF

				p.EXPECT().CACerts(gomock.Any()).Return(
					[]*x509.Certificate{ca[0], shorter[0], longer[0]}, nil,
				)
				return p
			},
			KeyRing: func(t *testing.T, mctrl *gomock.Controller) trust.KeyRing {
				k := mock_trust.NewMockKeyRing(mctrl)
				other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				k.EXPECT().PrivateKeys(gomock.Any()).Return([]crypto.Signer{key, other}, nil)
				return k
			},
			ErrAssertion: assert.NoError,
		},
		"err cert provider": {
			CertProvider: func(t *testing.T, mctrl *gomock.Controller) renewal.CACertProvider {
				p := mock_renewal.NewMockCACertProvider(mctrl)
				p.EXPECT().CACerts(gomock.Any()).Return(nil, serrors.New("internal"))
				return p
			},
			KeyRing: func(t *testing.T, mctrl *gomock.Controller) trust.KeyRing {
				k := mock_trust.NewMockKeyRing(mctrl)
				k.EXPECT().PrivateKeys(gomock.Any()).Return([]crypto.Signer{key}, nil)
				return k
			},
			ErrAssertion: assert.Error,
		},
		"no cert": {
			CertProvider: func(t *testing.T, mctrl *gomock.Controller) renewal.CACertProvider {
				p := mock_renewal.NewMockCACertProvider(mctrl)
				p.EXPECT().CACerts(gomock.Any()).Return(nil, nil)
				return p
			},
			KeyRing: func(t *testing.T, mctrl *gomock.Controller) trust.KeyRing {
				k := mock_trust.NewMockKeyRing(mctrl)
				k.EXPECT().PrivateKeys(gomock.Any()).Return([]crypto.Signer{key}, nil)
				return k
			},
			ErrAssertion: assert.Error,
		},
		"err key ring": {
			CertProvider: func(t *testing.T, mctrl *gomock.Controller) renewal.CACertProvider {
				return mock_renewal.NewMockCACertProvider(mctrl)
			},
			KeyRing: func(t *testing.T, mctrl *gomock.Controller) trust.KeyRing {
				k := mock_trust.NewMockKeyRing(mctrl)
				k.EXPECT().PrivateKeys(gomock.Any()).Return(nil, serrors.New("internal"))
				return k
			},
			ErrAssertion: assert.Error,
		},
		"no key": {
			CertProvider: func(t *testing.T, mctrl *gomock.Controller) renewal.CACertProvider {
				return mock_renewal.NewMockCACertProvider(mctrl)
			},
			KeyRing: func(t *testing.T, mctrl *gomock.Controller) trust.KeyRing {
				k := mock_trust.NewMockKeyRing(mctrl)
				k.EXPECT().PrivateKeys(gomock.Any()).Return(nil, nil)
				return k
			},
			ErrAssertion: assert.Error,
		},
		"no matching key": {
			CertProvider: func(t *testing.T, mctrl *gomock.Controller) renewal.CACertProvider {
				p := mock_renewal.NewMockCACertProvider(mctrl)
				p.EXPECT().CACerts(gomock.Any()).Return(ca, nil)
				return p
			},
			KeyRing: func(t *testing.T, mctrl *gomock.Controller) trust.KeyRing {
				k := mock_trust.NewMockKeyRing(mctrl)
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				k.EXPECT().PrivateKeys(gomock.Any()).Return([]crypto.Signer{priv}, nil)
				return k
			},
			ErrAssertion: assert.Error,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			g := renewal.LoadingPolicyGen{
				Validity:     time.Hour,
				CertProvider: tc.CertProvider(t, mctrl),
				KeyRing:      tc.KeyRing(t, mctrl),
			}
			p, err := g.Generate(context.Background())
			tc.ErrAssertion(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, time.Hour, p.Validity)
			assert.Equal(t, key, p.Signer)
			assert.Equal(t, ca[0], p.Certificate)

		})
	}

}

func TestCACertLoaderCACerts(t *testing.T) {
	trc := xtest.LoadTRC(t, "testdata/common/trcs/ISD1-B1-S1.trc")
	testCases := map[string]struct {
		prepare   func(t *testing.T, ctrl *gomock.Controller) (string, trust.DB)
		expected  []*x509.Certificate
		assertErr assert.ErrorAssertionFunc
	}{
		"non-existing/empty dir": {
			prepare: func(t *testing.T, ctrl *gomock.Controller) (string, trust.DB) {
				db := mock_trust.NewMockDB(ctrl)
				return "not-existing-dir", db
			},
			assertErr: assert.Error,
		},
		"invalid chain": {
			prepare: func(t *testing.T, ctrl *gomock.Controller) (string, trust.DB) {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().SignedTRC(gomock.Any(), cppki.TRCID{ISD: 1}).Return(trc, nil)
				return "testdata/common", db
			},
			assertErr: assert.NoError,
		},
		"valid single CA cert": {
			prepare: func(t *testing.T, ctrl *gomock.Controller) (string, trust.DB) {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().SignedTRC(gomock.Any(), cppki.TRCID{ISD: 1}).Return(trc, nil)
				return "testdata/common/ISD1/ASff00_0_110/crypto/ca", db
			},
			expected: xtest.LoadChain(t,
				"testdata/common/ISD1/ASff00_0_110/crypto/ca/ISD1-ASff00_0_110.ca.crt"),
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
			loader := renewal.CACertLoader{
				IA:  xtest.MustParseIA("1-ff00:0:110"),
				Dir: dir,
				DB:  db,
			}
			chains, err := loader.CACerts(context.Background())
			tc.assertErr(t, err)
			assert.Equal(t, tc.expected, chains)
		})
	}
}
