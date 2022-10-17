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
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	cstrust "github.com/scionproto/scion/control/trust"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/trust"
	"github.com/scionproto/scion/private/trust/mock_trust"
)

func TestChachingSignerGen(t *testing.T) {
	exp := time.Now()
	otherExp := time.Now().Add(time.Hour)

	testCases := map[string]struct {
		Interval     time.Duration
		SignerGen    func(mctrl *gomock.Controller) trust.SignerGenerator
		FirstErr     assert.ErrorAssertionFunc
		FirstSigner  trust.Signer
		SecondErr    assert.ErrorAssertionFunc
		SecondSigner trust.Signer
	}{
		"valid": {
			Interval: time.Hour,
			SignerGen: func(mctrl *gomock.Controller) trust.SignerGenerator {
				gen := mock_trust.NewMockSignerGenerator(mctrl)
				gen.EXPECT().Generate(gomock.Any()).Return(
					trust.Signer{Expiration: exp}, nil,
				)
				return gen
			},
			FirstErr:     assert.NoError,
			FirstSigner:  trust.Signer{Expiration: exp},
			SecondErr:    assert.NoError,
			SecondSigner: trust.Signer{Expiration: exp},
		},
		"valid, regenerate after interval": {
			Interval: 0,
			SignerGen: func(mctrl *gomock.Controller) trust.SignerGenerator {
				gen := mock_trust.NewMockSignerGenerator(mctrl)
				gen.EXPECT().Generate(gomock.Any()).Return(
					trust.Signer{Expiration: exp}, nil,
				)
				gen.EXPECT().Generate(gomock.Any()).Return(
					trust.Signer{Expiration: otherExp}, nil,
				)
				return gen
			},
			FirstErr:     assert.NoError,
			FirstSigner:  trust.Signer{Expiration: exp},
			SecondErr:    assert.NoError,
			SecondSigner: trust.Signer{Expiration: otherExp},
		},
		"first fails, second cached": {
			Interval: time.Hour,
			SignerGen: func(mctrl *gomock.Controller) trust.SignerGenerator {
				gen := mock_trust.NewMockSignerGenerator(mctrl)
				gen.EXPECT().Generate(gomock.Any()).Return(
					trust.Signer{}, serrors.New("internal"),
				)
				return gen
			},
			FirstErr:     assert.Error,
			FirstSigner:  trust.Signer{},
			SecondErr:    assert.Error,
			SecondSigner: trust.Signer{},
		},
		"first fails, second succeeds": {
			Interval: 0,
			SignerGen: func(mctrl *gomock.Controller) trust.SignerGenerator {
				gen := mock_trust.NewMockSignerGenerator(mctrl)
				gen.EXPECT().Generate(gomock.Any()).Return(
					trust.Signer{}, serrors.New("internal"),
				)
				gen.EXPECT().Generate(gomock.Any()).Return(
					trust.Signer{Expiration: exp}, nil,
				)
				return gen
			},
			FirstErr:     assert.Error,
			FirstSigner:  trust.Signer{},
			SecondErr:    assert.NoError,
			SecondSigner: trust.Signer{Expiration: exp},
		},
		"second fails, serve cached": {
			Interval: 0,
			SignerGen: func(mctrl *gomock.Controller) trust.SignerGenerator {
				gen := mock_trust.NewMockSignerGenerator(mctrl)
				gen.EXPECT().Generate(gomock.Any()).Return(
					trust.Signer{Expiration: exp}, nil,
				)
				gen.EXPECT().Generate(gomock.Any()).Return(
					trust.Signer{}, serrors.New("internal"),
				)
				return gen
			},
			FirstErr:     assert.NoError,
			FirstSigner:  trust.Signer{Expiration: exp},
			SecondErr:    assert.NoError,
			SecondSigner: trust.Signer{Expiration: exp},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mctrl := gomock.NewController(t)
			gen := cstrust.CachingSignerGen{
				SignerGen: tc.SignerGen(mctrl),
				Interval:  tc.Interval,
			}
			signer, err := gen.Generate(context.Background())
			tc.FirstErr(t, err)
			assert.Equal(t, tc.FirstSigner, signer)
			signer, err = gen.Generate(context.Background())
			tc.SecondErr(t, err)
			assert.Equal(t, tc.SecondSigner, signer)
		})
	}
}
