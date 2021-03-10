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
	"crypto/ecdsa"
	"crypto/x509"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/mock_trust"
)

func TestVerify(t *testing.T) {
	if *update {
		t.Skip("test crypto is being updated")
	}

	msg := []byte("random")
	chains := [][]*x509.Certificate{xtest.LoadChain(t,
		filepath.Join(goldenDir, "ISD1/ASff00_0_110/crypto/as/ISD1-ASff00_0_110.pem"))}
	key := loadKey(t, filepath.Join(goldenDir,
		"ISD1/ASff00_0_110/crypto/as/cp-as.key"))
	sign := validSignS(t, msg, "1-ff00:0:110", key)
	forgedSign := validSignS(t, msg, "1-ff00:0:110", key)
	forgedSign.Signature[30] ^= 0xFF

	testCases := map[string]struct {
		provider    func(mctrl *gomock.Controller) trust.Provider
		sign        *cryptopb.SignedMessage
		boundIA     addr.IA
		boundServer net.Addr
		assertFunc  assert.ErrorAssertionFunc
	}{
		"valid": {
			provider: func(mctrl *gomock.Controller) trust.Provider {
				p := mock_trust.NewMockProvider(mctrl)
				p.EXPECT().NotifyTRC(
					gomock.Any(),
					cppki.TRCID{ISD: 1, Base: 1, Serial: 1},
					trust.OptionsMatcher{},
				).Return(nil)

				p.EXPECT().GetChains(ctxMatcher{},
					chainQueryMatcher{
						ia:   xtest.MustParseIA("1-ff00:0:110"),
						skid: []byte("subject-key-id"),
					},
					trust.OptionsMatcher{},
				).Return(chains, nil).Times(1)
				return p
			},
			sign:       sign,
			assertFunc: assert.NoError,
		},
		"valid with bound server": {
			provider: func(mctrl *gomock.Controller) trust.Provider {
				p := mock_trust.NewMockProvider(mctrl)
				opts := trust.OptionsMatcher{Server: &net.UnixAddr{Name: "test"}}
				p.EXPECT().NotifyTRC(
					gomock.Any(),
					cppki.TRCID{ISD: 1, Base: 1, Serial: 1},
					opts,
				).Return(nil)

				p.EXPECT().GetChains(ctxMatcher{},
					chainQueryMatcher{
						ia:   xtest.MustParseIA("1-ff00:0:110"),
						skid: []byte("subject-key-id"),
					},
					opts,
				).Times(1).Return(chains, nil)
				return p
			},
			sign:        sign,
			boundServer: &net.UnixAddr{Name: "test"},
			assertFunc:  assert.NoError,
		},
		"invalid signature": {
			provider:   func(mctrl *gomock.Controller) trust.Provider { return nil },
			assertFunc: assert.Error,
		},

		"invalid boundIA missmatch": {
			provider:   func(mctrl *gomock.Controller) trust.Provider { return nil },
			sign:       sign,
			boundIA:    xtest.MustParseIA("1-ff00:0:210"),
			assertFunc: assert.Error,
		},
		"invalid provider nil": {
			provider:   func(mctrl *gomock.Controller) trust.Provider { return nil },
			sign:       sign,
			assertFunc: assert.Error,
		},
		"invalid provider errors on TRC notify": {
			provider: func(mctrl *gomock.Controller) trust.Provider {
				p := mock_trust.NewMockProvider(mctrl)
				opts := trust.OptionsMatcher{}
				id := cppki.TRCID{ISD: 1, Base: 1, Serial: 1}
				p.EXPECT().NotifyTRC(gomock.Any(), id, opts).Times(1).Return(
					serrors.New("internal"),
				)
				return p
			},
			sign:       sign,
			assertFunc: assert.Error,
		},
		"invalid provider errors": {
			provider: func(mctrl *gomock.Controller) trust.Provider {
				p := mock_trust.NewMockProvider(mctrl)
				opts := trust.OptionsMatcher{}
				p.EXPECT().NotifyTRC(gomock.Any(), gomock.Any(), opts).AnyTimes().Return(nil)
				p.EXPECT().GetChains(ctxMatcher{}, gomock.Any(), opts).Times(1).Return(
					nil, serrors.New("internal"),
				)
				return p
			},
			sign:       sign,
			assertFunc: assert.Error,
		},
		"invalid engine, gives zero chains": {
			provider: func(mctrl *gomock.Controller) trust.Provider {
				p := mock_trust.NewMockProvider(mctrl)
				opts := trust.OptionsMatcher{}
				p.EXPECT().NotifyTRC(gomock.Any(), gomock.Any(), opts).AnyTimes().Return(nil)
				p.EXPECT().GetChains(gomock.Any(), gomock.Any(), opts).Times(1).Return(
					nil, nil,
				)
				return p
			},
			sign:       sign,
			assertFunc: assert.Error,
		},
		"reject forged signature": {
			provider: func(mctrl *gomock.Controller) trust.Provider {
				p := mock_trust.NewMockProvider(mctrl)
				p.EXPECT().NotifyTRC(
					gomock.Any(),
					cppki.TRCID{ISD: 1, Base: 1, Serial: 1},
					trust.OptionsMatcher{},
				).Return(nil)

				p.EXPECT().GetChains(ctxMatcher{},
					chainQueryMatcher{
						ia:   xtest.MustParseIA("1-ff00:0:110"),
						skid: []byte("subject-key-id"),
					},
					trust.OptionsMatcher{},
				).Return(chains, nil).Times(1)
				return p
			},
			sign:       forgedSign,
			assertFunc: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()

			v := &trust.Verifier{
				BoundIA:     tc.boundIA,
				BoundServer: tc.boundServer,
				Engine:      tc.provider(mctrl),
			}
			signedMsg, err := v.Verify(context.Background(), tc.sign)
			tc.assertFunc(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, msg, signedMsg.Body)
		})
	}
}

func validSignS(t *testing.T, msg []byte, rawIA string,
	key *ecdsa.PrivateKey) *cryptopb.SignedMessage {

	ia, _ := addr.IAFromString(rawIA)
	signer := trust.Signer{
		PrivateKey: key,
		Algorithm:  signed.ECDSAWithSHA512,
		IA:         ia,
		TRCID: cppki.TRCID{
			ISD:    1,
			Base:   1,
			Serial: 1,
		},
		SubjectKeyID: []byte("subject-key-id"),
		Expiration:   time.Now().Add(2 * time.Hour),
	}
	meta, err := signer.Sign(context.Background(), msg)
	require.NoError(t, err)
	return meta
}
