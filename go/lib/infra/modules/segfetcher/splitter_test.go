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
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
)

var (
	cores = map[addr.IA]struct{}{
		core_110: {},
		core_120: {},
		core_130: {},
		core_210: {},
	}
)

func TestRequestSplitter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	inspector := mock_infra.NewMockASInspector(ctrl)
	opts := infra.ASInspectorOpts{
		RequiredAttributes: []infra.Attribute{infra.Core},
	}
	inspector.EXPECT().HasAttributes(gomock.Any(), gomock.Any(), opts).DoAndReturn(
		func(_ context.Context, ia addr.IA, _ infra.ASInspectorOpts) (bool, error) {
			_, ok := cores[ia]
			return ok, nil
		},
	).AnyTimes()
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
		"Up down non-local passes state": {
			LocalIA: non_core_111,
			Request: segfetcher.Request{
				State: segfetcher.Fetch,
				Src:   non_core_111,
				Dst:   non_core_211,
			},
			ExpectedSet: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_111, Dst: isd1},
				Cores: []segfetcher.Request{{Src: isd1, Dst: isd2}},
				Down:  segfetcher.Request{Src: isd2, Dst: non_core_211},
				Fetch: true,
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			splitter := segfetcher.MultiSegmentSplitter{
				Local:     test.LocalIA,
				Inspector: inspector,
			}
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
