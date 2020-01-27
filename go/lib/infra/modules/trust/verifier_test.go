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
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/mock_trust"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/proto"
)

var public, priv, _ = scrypto.GenKeyPair(scrypto.Ed25519)

func TestNewVerifier(t *testing.T) {
	_, ok := trust.NewVerifier(nil).(infra.Verifier)
	assert.True(t, ok)
}

func TestVerifyPld(t *testing.T) {
	testcases := map[string]struct {
		v       *trust.Verifier
		spld    *ctrl.SignedPld
		wantErr assert.ErrorAssertionFunc
	}{
		"invalid payload": {
			v: &trust.Verifier{},
			spld: &ctrl.SignedPld{
				Blob: []byte("msg"),
				Sign: validSignS("msg", "1-ff00:0:110"),
			},
			wantErr: assert.Error,
		},
	}
	for tn, tc := range testcases {
		t.Run(tn, func(t *testing.T) {
			_, err := tc.v.VerifyPld(context.Background(), tc.spld)
			tc.wantErr(t, err)
		})
	}
}

func TestVerify(t *testing.T) {
	errorcases := map[string]struct {
		v    *trust.Verifier
		msg  []byte
		sign *proto.SignS
	}{
		"invalid signature": {
			v: &trust.Verifier{},
		},
		"invalid signature source": {
			v:    &trust.Verifier{},
			msg:  []byte("random"),
			sign: invalidSignS("random", "1-ff00:0:110"),
		},
		"invalid bound IA": {
			v: &trust.Verifier{
				BoundIA: xtest.MustParseIA("1-ff00:0:111"),
			},
			msg:  []byte("random"),
			sign: validSignS("random", "1-ff00:0:110"),
		},
		"invalid bound SRC": {
			v: &trust.Verifier{
				BoundSrc: &ctrl.SignSrcDef{},
			},
			msg:  []byte("random"),
			sign: validSignS("random", "1-ff00:0:110"),
		},
	}
	for tn, tc := range errorcases {
		t.Run(tn, func(t *testing.T) {
			err := tc.v.Verify(context.Background(), tc.msg, tc.sign)
			assert.Error(t, err)
		})
	}

	t.Run("happy path", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		p := mock_trust.NewMockCryptoProvider(ctrl)
		p.EXPECT().AnnounceTRC(gomock.Any(), trust.TRCID{ISD: 1, Version: 2}, gomock.Any()).Return(
			nil,
		)
		p.EXPECT().GetASKey(gomock.Any(), gomock.Any(), gomock.Any()).Return(
			scrypto.KeyMeta{Key: public, Algorithm: scrypto.Ed25519}, nil,
		)

		v := &trust.Verifier{
			Store: p,
		}

		msg, sign := []byte("random"), validSignS("random", "1-ff00:0:110")
		err := v.Verify(context.Background(), msg, sign)
		assert.NoError(t, err)
	})
}

func TestVerifierWithIA(t *testing.T) {
	ia := xtest.MustParseIA("1-ff00:0:110")
	x := &trust.Verifier{}
	assert.NotNil(t, x)
	y := x.WithIA(ia).(*trust.Verifier)
	assert.Equal(t, y.BoundIA, ia)
}

func validSignS(msg, rawIA string) *proto.SignS {
	ia, _ := addr.IAFromString(rawIA)
	src := ctrl.SignSrcDef{
		IA:       ia,
		ChainVer: 1,
		TRCVer:   2,
	}
	sign := proto.NewSignS(proto.SignType_ed25519, src.Pack())
	sign.SetTimestamp(time.Now())
	sign.Signature, _ = scrypto.Sign(sign.SigInput([]byte(msg), false), priv, scrypto.Ed25519)
	return sign
}

func invalidSignS(msg, ia string) *proto.SignS {
	ret := validSignS(msg, ia)
	ret.Src = []byte("wrongcontent")
	return ret
}
