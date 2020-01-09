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

package trust_test

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/mock_trust"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
)

func TestNewSigner(t *testing.T) {
	orig := trust.SignerConf{
		ChainVer: 1,
		TRCVer:   1,
		Validity: scrypto.Validity{
			NotBefore: util.UnixTime{Time: time.Now()},
			NotAfter:  util.UnixTime{Time: time.Now().Add(time.Hour)},
		},
		Key: keyconf.Key{
			ID: keyconf.ID{
				Usage:   keyconf.ASSigningKey,
				IA:      ia110,
				Version: 2,
			},
			Type:      keyconf.PrivateKey,
			Algorithm: scrypto.Ed25519,
			Bytes:     make([]byte, ed25519.PrivateKeySize),
		},
	}

	tests := map[string]struct {
		Modify       func(orig trust.SignerConf) trust.SignerConf
		ErrAssertion assert.ErrorAssertionFunc
	}{
		"chain version is latest": {
			Modify: func(orig trust.SignerConf) trust.SignerConf {
				orig.ChainVer = scrypto.LatestVer
				return orig
			},
			ErrAssertion: assert.Error,
		},
		"trc version is latest": {
			Modify: func(orig trust.SignerConf) trust.SignerConf {
				orig.TRCVer = scrypto.LatestVer
				return orig
			},
			ErrAssertion: assert.Error,
		},
		"wildcard IA": {
			Modify: func(orig trust.SignerConf) trust.SignerConf {
				orig.Key.IA.A = 0
				return orig
			},
			ErrAssertion: assert.Error,
		},
		"public key": {
			Modify: func(orig trust.SignerConf) trust.SignerConf {
				orig.Key.Type = keyconf.PublicKey
				return orig
			},
			ErrAssertion: assert.Error,
		},
		"unknown algorithm": {
			Modify: func(orig trust.SignerConf) trust.SignerConf {
				orig.Key.Algorithm = "unknown"
				return orig
			},
			ErrAssertion: assert.Error,
		},
		"valid": {
			Modify:       func(orig trust.SignerConf) trust.SignerConf { return orig },
			ErrAssertion: assert.NoError,
		},
	}
	for n, tc := range tests {
		name, test := n, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := trust.NewSigner(test.Modify(orig))
			test.ErrAssertion(t, err)
		})
	}

}

func TestSignerSign(t *testing.T) {
	pub, priv, err := scrypto.GenKeyPair(scrypto.Ed25519)
	require.NoError(t, err)
	cfg := trust.SignerConf{
		ChainVer: 1,
		TRCVer:   1,
		Validity: scrypto.Validity{
			NotBefore: util.UnixTime{Time: time.Now()},
			NotAfter:  util.UnixTime{Time: time.Now().Add(time.Hour)},
		},
		Key: keyconf.Key{
			ID: keyconf.ID{
				Usage:   keyconf.ASSigningKey,
				IA:      ia110,
				Version: 2,
			},
			Type:      keyconf.PrivateKey,
			Algorithm: scrypto.Ed25519,
			Bytes:     priv,
		},
	}
	t.Run("valid", func(t *testing.T) {
		signer, err := trust.NewSigner(cfg)
		require.NoError(t, err)
		sign, err := signer.Sign([]byte("wasn't me"))
		require.NoError(t, err)

		input := sign.SigInput([]byte("wasn't me"), false)
		assert.NoError(t, scrypto.Verify(input, sign.Signature, pub, scrypto.Ed25519))
	})
	t.Run("fail", func(t *testing.T) {
		mcfg := cfg
		mcfg.Key.Bytes = []byte("garbage key")
		signer, err := trust.NewSigner(mcfg)
		require.NoError(t, err)
		_, err = signer.Sign(nil)
		assert.Error(t, err)
	})

}

func TestSignerMeta(t *testing.T) {
	cfg := trust.SignerConf{
		ChainVer: 1,
		TRCVer:   2,
		Validity: scrypto.Validity{
			NotBefore: util.UnixTime{Time: time.Now()},
			NotAfter:  util.UnixTime{Time: time.Now().Add(time.Hour)},
		},
		Key: keyconf.Key{
			ID: keyconf.ID{
				Usage:   keyconf.ASSigningKey,
				IA:      ia110,
				Version: 2,
			},
			Type:      keyconf.PrivateKey,
			Algorithm: scrypto.Ed25519,
			Bytes:     []byte("some key"),
		},
	}
	signer, err := trust.NewSigner(cfg)
	require.NoError(t, err)
	meta := signer.Meta()
	exp := infra.SignerMeta{
		Src: ctrl.SignSrcDef{
			IA:       ia110,
			ChainVer: 1,
			TRCVer:   2,
		},
		ExpTime: cfg.Validity.NotAfter.Time,
		Algo:    scrypto.Ed25519,
	}
	assert.Equal(t, exp, meta)
}

func TestSignerGenSigner(t *testing.T) {
	internal := serrors.New("internal")
	tests := map[string]struct {
		Provider     func(t *testing.T, ctrl *gomock.Controller) trust.CryptoProvider
		KeyRing      func(t *testing.T, ctrl *gomock.Controller) trust.KeyRing
		ErrAssertion assert.ErrorAssertionFunc
	}{
		"chain lookup fails": {
			Provider: func(t *testing.T, ctrl *gomock.Controller) trust.CryptoProvider {
				p := mock_trust.NewMockCryptoProvider(ctrl)
				p.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.LatestVer},
					infra.ChainOpts{}).Return(nil, internal)
				return p
			},
			KeyRing: func(t *testing.T, ctrl *gomock.Controller) trust.KeyRing {
				return mock_trust.NewMockKeyRing(ctrl)
			},
			ErrAssertion: assert.Error,
		},
		"garbage chain": {
			Provider: func(t *testing.T, ctrl *gomock.Controller) trust.CryptoProvider {
				p := mock_trust.NewMockCryptoProvider(ctrl)
				p.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.LatestVer},
					infra.ChainOpts{}).Return([]byte("garbage"), nil)
				return p
			},
			KeyRing: func(t *testing.T, ctrl *gomock.Controller) trust.KeyRing {
				return mock_trust.NewMockKeyRing(ctrl)
			},
			ErrAssertion: assert.Error,
		},
		"key not found": {
			Provider: func(t *testing.T, ctrl *gomock.Controller) trust.CryptoProvider {
				p := mock_trust.NewMockCryptoProvider(ctrl)
				p.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.LatestVer},
					infra.ChainOpts{}).Return(loadChain(t, chain110v1).Raw, nil)
				return p
			},
			KeyRing: func(t *testing.T, ctrl *gomock.Controller) trust.KeyRing {
				r := mock_trust.NewMockKeyRing(ctrl)
				r.EXPECT().PrivateKey(gomock.Any(), gomock.Any()).Return(keyconf.Key{}, internal)
				return r
			},
			ErrAssertion: assert.Error,
		},
		"garbage private key": {
			Provider: func(t *testing.T, ctrl *gomock.Controller) trust.CryptoProvider {
				p := mock_trust.NewMockCryptoProvider(ctrl)
				p.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.LatestVer},
					infra.ChainOpts{}).Return(loadChain(t, chain110v1).Raw, nil)
				return p
			},
			KeyRing: func(t *testing.T, ctrl *gomock.Controller) trust.KeyRing {
				r := mock_trust.NewMockKeyRing(ctrl)
				id := keyconf.ID{IA: ia110, Usage: keyconf.ASSigningKey, Version: 1}
				key := loadPrivateKey(t, id)
				key.Bytes = []byte("garbage key")
				r.EXPECT().PrivateKey(gomock.Any(), gomock.Any()).Return(key, nil)
				return r
			},
			ErrAssertion: assert.Error,
		},
		"differing key": {
			Provider: func(t *testing.T, ctrl *gomock.Controller) trust.CryptoProvider {
				p := mock_trust.NewMockCryptoProvider(ctrl)
				p.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.LatestVer},
					infra.ChainOpts{}).Return(loadChain(t, chain110v1).Raw, nil)
				return p
			},
			KeyRing: func(t *testing.T, ctrl *gomock.Controller) trust.KeyRing {
				r := mock_trust.NewMockKeyRing(ctrl)
				id := keyconf.ID{IA: ia110, Usage: keyconf.ASSigningKey, Version: 1}
				key := loadPrivateKey(t, id)
				key.Bytes[0] ^= 0xFF
				r.EXPECT().PrivateKey(gomock.Any(), gomock.Any()).Return(key, nil)
				return r
			},
			ErrAssertion: assert.Error,
		},
		"getting TRC fails": {
			Provider: func(t *testing.T, ctrl *gomock.Controller) trust.CryptoProvider {
				p := mock_trust.NewMockCryptoProvider(ctrl)
				p.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.LatestVer},
					infra.ChainOpts{}).Return(loadChain(t, chain110v1).Raw, nil)
				p.EXPECT().GetTRC(gomock.Any(),
					trust.TRCID{ia110.I, scrypto.LatestVer}, infra.TRCOpts{}).Return(
					nil, internal,
				)
				return p
			},
			KeyRing: func(t *testing.T, ctrl *gomock.Controller) trust.KeyRing {
				r := mock_trust.NewMockKeyRing(ctrl)
				id := keyconf.ID{IA: ia110, Usage: keyconf.ASSigningKey, Version: 1}
				r.EXPECT().PrivateKey(gomock.Any(), gomock.Any()).Return(loadPrivateKey(t, id), nil)
				return r
			},
			ErrAssertion: assert.Error,
		},
		"invalid IA": {
			Provider: func(t *testing.T, ctrl *gomock.Controller) trust.CryptoProvider {
				p := mock_trust.NewMockCryptoProvider(ctrl)
				p.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.LatestVer},
					infra.ChainOpts{}).Return(loadChain(t, chain110v1).Raw, nil)
				p.EXPECT().GetTRC(gomock.Any(),
					trust.TRCID{ISD: ia110.I, Version: scrypto.LatestVer}, infra.TRCOpts{}).Return(
					loadTRC(t, trc1v1).TRC, nil,
				)
				return p
			},
			KeyRing: func(t *testing.T, ctrl *gomock.Controller) trust.KeyRing {
				r := mock_trust.NewMockKeyRing(ctrl)
				id := keyconf.ID{IA: ia110, Usage: keyconf.ASSigningKey, Version: 1}
				key := loadPrivateKey(t, id)
				key.IA = addr.IA{}
				r.EXPECT().PrivateKey(gomock.Any(), gomock.Any()).Return(key, nil)
				return r
			},
			ErrAssertion: assert.Error,
		},
		"valid": {
			Provider: func(t *testing.T, ctrl *gomock.Controller) trust.CryptoProvider {
				p := mock_trust.NewMockCryptoProvider(ctrl)
				p.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.LatestVer},
					infra.ChainOpts{}).Return(loadChain(t, chain110v1).Raw, nil)
				p.EXPECT().GetTRC(gomock.Any(),
					trust.TRCID{ISD: ia110.I, Version: scrypto.LatestVer}, infra.TRCOpts{}).Return(
					loadTRC(t, trc1v1).TRC, nil,
				)
				return p
			},
			KeyRing: func(t *testing.T, ctrl *gomock.Controller) trust.KeyRing {
				r := mock_trust.NewMockKeyRing(ctrl)
				id := keyconf.ID{IA: ia110, Usage: keyconf.ASSigningKey, Version: 1}
				r.EXPECT().PrivateKey(gomock.Any(), gomock.Any()).Return(loadPrivateKey(t, id), nil)
				return r
			},
			ErrAssertion: assert.NoError,
		},
	}

	for n, tc := range tests {
		name, test := n, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			g := trust.SignerGen{
				IA:       ia110,
				KeyRing:  test.KeyRing(t, ctrl),
				Provider: test.Provider(t, ctrl),
			}
			signer, err := g.Signer(context.Background())
			test.ErrAssertion(t, err)
			if signer == nil {
				return
			}
			sign, err := signer.Sign([]byte("wasn't me"))
			require.NoError(t, err)

			meta := loadChain(t, chain110v1).AS.Keys[cert.SigningKey]
			input := sign.SigInput([]byte("wasn't me"), false)
			assert.NoError(t, scrypto.Verify(input, sign.Signature, meta.Key, meta.Algorithm))

		})
	}
}
