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

package segfetcher_test

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher/mock_segfetcher"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	isd1 = xtest.MustParseIA("1-0")
	isd2 = xtest.MustParseIA("2-0")

	core_110 = xtest.MustParseIA("1-ff00:0:110")
	core_120 = xtest.MustParseIA("1-ff00:0:120")
	core_130 = xtest.MustParseIA("1-ff00:0:130")
	core_210 = xtest.MustParseIA("2-ff00:0:210")

	non_core_111 = xtest.MustParseIA("1-ff00:0:111")
	non_core_112 = xtest.MustParseIA("1-ff00:0:112")
	non_core_211 = xtest.MustParseIA("2-ff00:0:211")

	trc1Mock = &trc.TRC{
		CoreASes: trc.CoreASMap{
			core_110: nil,
			core_120: nil,
			core_130: nil,
		},
	}
	trc2Mock = &trc.TRC{
		CoreASes: trc.CoreASMap{
			core_210: nil,
		},
	}
)

func TestRequestSplitter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	trcProvider := mock_segfetcher.NewMockTRCProvider(ctrl)
	trcProvider.EXPECT().GetTRC(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, isd addr.ISD, _ uint64) (*trc.TRC, error) {
			switch isd {
			case 1:
				return trc1Mock, nil
			case 2:
				return trc2Mock, nil
			default:
				return nil, errors.New("TRC Not found")
			}
		}).AnyTimes()
	tests := map[string]struct {
		LocalIA        addr.IA
		Request        segfetcher.Request
		ExpectedSet    segfetcher.RequestSet
		ExpectedErrMsg string
	}{
		"Up": {
			LocalIA: non_core_111,
			Request: segfetcher.Request{Src: non_core_111, Dst: core_110},
			ExpectedSet: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_111, Dst: isd1},
				Cores: []segfetcher.Request{{Src: isd1, Dst: core_110}},
			},
		},
		"Up wildcard": {
			LocalIA: non_core_111,
			Request: segfetcher.Request{Src: non_core_111, Dst: isd1},
			ExpectedSet: segfetcher.RequestSet{
				Up: segfetcher.Request{Src: non_core_111, Dst: isd1},
			},
		},
		"Up core non-local": {
			LocalIA: non_core_111,
			Request: segfetcher.Request{Src: non_core_111, Dst: core_210},
			ExpectedSet: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_111, Dst: isd1},
				Cores: []segfetcher.Request{{Src: isd1, Dst: core_210}},
			},
		},
		"Up Core non-local wildcard": {
			LocalIA: non_core_111,
			Request: segfetcher.Request{Src: non_core_111, Dst: isd2},
			ExpectedSet: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_111, Dst: isd1},
				Cores: []segfetcher.Request{{Src: isd1, Dst: isd2}},
			},
		},
		"Down local": {
			LocalIA: core_110,
			Request: segfetcher.Request{Dst: non_core_111},
			ExpectedSet: segfetcher.RequestSet{
				Cores: []segfetcher.Request{{Src: core_110, Dst: isd1}},
				Down:  segfetcher.Request{Src: isd1, Dst: non_core_111},
			},
		},
		"Down non-local": {
			LocalIA: core_110,
			Request: segfetcher.Request{Dst: non_core_211},
			ExpectedSet: segfetcher.RequestSet{
				Cores: []segfetcher.Request{{Src: core_110, Dst: isd2}},
				Down:  segfetcher.Request{Src: isd2, Dst: non_core_211},
			},
		},
		"Core local": {
			LocalIA: core_110,
			Request: segfetcher.Request{Dst: core_130},
			ExpectedSet: segfetcher.RequestSet{
				Cores: []segfetcher.Request{{Src: core_110, Dst: core_130}},
			},
		},
		"Core non-local": {
			LocalIA: core_110,
			Request: segfetcher.Request{Dst: core_210},
			ExpectedSet: segfetcher.RequestSet{
				Cores: []segfetcher.Request{{Src: core_110, Dst: core_210}},
			},
		},
		"Core non-local wildcard": {
			LocalIA: core_110,
			Request: segfetcher.Request{Dst: isd2},
			ExpectedSet: segfetcher.RequestSet{
				Cores: []segfetcher.Request{{Src: core_110, Dst: isd2}},
			},
		},
		"Up down local": {
			LocalIA: non_core_111,
			Request: segfetcher.Request{Src: non_core_111, Dst: non_core_112},
			ExpectedSet: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_111, Dst: isd1},
				Cores: []segfetcher.Request{{Src: isd1, Dst: isd1}},
				Down:  segfetcher.Request{Src: isd1, Dst: non_core_112},
			},
		},
		"Up down non-local": {
			LocalIA: non_core_111,
			Request: segfetcher.Request{Src: non_core_111, Dst: non_core_211},
			ExpectedSet: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_111, Dst: isd1},
				Cores: []segfetcher.Request{{Src: isd1, Dst: isd2}},
				Down:  segfetcher.Request{Src: isd2, Dst: non_core_211},
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			splitter, err := segfetcher.NewRequestSplitter(test.LocalIA, trcProvider)
			xtest.FailOnErr(t, err)
			requests, err := splitter.Split(context.Background(), test.Request)
			if test.ExpectedErrMsg != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedErrMsg)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.ExpectedSet, requests)
			}
		})
	}
}
