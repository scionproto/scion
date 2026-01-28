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

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/private/segment/segfetcher"
	"github.com/scionproto/scion/private/trust"
	"github.com/scionproto/scion/private/trust/mock_trust"
)

func TestRequestSplitter(t *testing.T) {
	ctrl := gomock.NewController(t)

	t.Run("multi-cores", func(t *testing.T) {
		cores := map[addr.IA]struct{}{
			core_110: {},
			core_120: {},
			core_130: {},
			core_210: {},
		}
		inspector := mock_trust.NewMockInspector(ctrl)
		inspector.EXPECT().HasAttributes(gomock.Any(), gomock.Any(), trust.Core).DoAndReturn(
			func(_ context.Context, ia addr.IA, _ trust.Attribute) (bool, error) {
				_, ok := cores[ia]
				return ok, nil
			},
		).AnyTimes()
		inspector.EXPECT().ByAttributes(gomock.Any(), gomock.Any(), trust.Core).DoAndReturn(
			func(_ context.Context, isd addr.ISD, _ trust.Attribute) ([]addr.IA, error) {
				var result []addr.IA
				for ia := range cores {
					if ia.ISD() == isd {
						result = append(result, ia)
					}
				}
				return result, nil
			},
		).AnyTimes()
		tests := map[string]struct {
			LocalIA        addr.IA
			Dst            addr.IA
			ExpectedSet    segfetcher.Requests
			ExpectedErrMsg string
		}{
			"Up": {
				LocalIA: non_core_111,
				Dst:     core_110,
				ExpectedSet: segfetcher.Requests{
					segfetcher.Request{SegType: Up, Src: non_core_111, Dst: isd1},
					segfetcher.Request{SegType: Core, Src: isd1, Dst: core_110},
					// One-hop requests for peering
					segfetcher.Request{SegType: Down, Src: core_110, Dst: core_110},
					segfetcher.Request{SegType: Up, Src: core_110, Dst: core_110},
					segfetcher.Request{SegType: Up, Src: core_120, Dst: core_120},
					segfetcher.Request{SegType: Up, Src: core_130, Dst: core_130},
				},
			},
			"Up wildcard": {
				LocalIA: non_core_111,
				Dst:     isd1,
				ExpectedSet: segfetcher.Requests{
					segfetcher.Request{SegType: Up, Src: non_core_111, Dst: isd1},
				},
			},
			"Up core non-local": {
				LocalIA: non_core_111,
				Dst:     core_210,
				ExpectedSet: segfetcher.Requests{
					segfetcher.Request{SegType: Up, Src: non_core_111, Dst: isd1},
					segfetcher.Request{SegType: Core, Src: isd1, Dst: core_210},
					// One-hop requests for peering
					segfetcher.Request{SegType: Down, Src: core_210, Dst: core_210},
					segfetcher.Request{SegType: Up, Src: core_110, Dst: core_110},
					segfetcher.Request{SegType: Up, Src: core_120, Dst: core_120},
					segfetcher.Request{SegType: Up, Src: core_130, Dst: core_130},
				},
			},
			"Up Core non-local wildcard": {
				// Wildcards are considered "core" by isCore(), so dstCore=true
				LocalIA: non_core_111,
				Dst:     isd2,
				ExpectedSet: segfetcher.Requests{
					segfetcher.Request{SegType: Up, Src: non_core_111, Dst: isd1},
					segfetcher.Request{SegType: Core, Src: isd1, Dst: isd2},
					// One-hop requests for peering (!srcCore && dstCore adds dst->dst Down and srcCores Up)
					segfetcher.Request{SegType: Down, Src: isd2, Dst: isd2},
					segfetcher.Request{SegType: Up, Src: core_110, Dst: core_110},
					segfetcher.Request{SegType: Up, Src: core_120, Dst: core_120},
					segfetcher.Request{SegType: Up, Src: core_130, Dst: core_130},
				},
			},
			"Down local": {
				LocalIA: core_110,
				Dst:     non_core_111,
				ExpectedSet: segfetcher.Requests{
					segfetcher.Request{SegType: Core, Src: core_110, Dst: isd1},
					segfetcher.Request{SegType: Down, Src: isd1, Dst: non_core_111},
					// One-hop requests for peering
					segfetcher.Request{SegType: Up, Src: core_110, Dst: core_110},
					segfetcher.Request{SegType: Down, Src: core_110, Dst: core_110},
					segfetcher.Request{SegType: Down, Src: core_120, Dst: core_120},
					segfetcher.Request{SegType: Down, Src: core_130, Dst: core_130},
				},
			},
			"Down non-local": {
				LocalIA: core_110,
				Dst:     non_core_211,
				ExpectedSet: segfetcher.Requests{
					segfetcher.Request{SegType: Core, Src: core_110, Dst: isd2},
					segfetcher.Request{SegType: Down, Src: isd2, Dst: non_core_211},
					// One-hop requests for peering
					segfetcher.Request{SegType: Up, Src: core_110, Dst: core_110},
					segfetcher.Request{SegType: Down, Src: core_210, Dst: core_210},
				},
			},
			"Core local": {
				LocalIA: core_110,
				Dst:     core_130,
				ExpectedSet: segfetcher.Requests{
					segfetcher.Request{SegType: Core, Src: core_110, Dst: core_130},
					// One-hop requests for peering
					segfetcher.Request{SegType: Up, Src: core_110, Dst: core_110},
					segfetcher.Request{SegType: Down, Src: core_130, Dst: core_130},
				},
			},
			"Core non-local": {
				LocalIA: core_110,
				Dst:     core_210,
				ExpectedSet: segfetcher.Requests{
					segfetcher.Request{SegType: Core, Src: core_110, Dst: core_210},
					// One-hop requests for peering
					segfetcher.Request{SegType: Up, Src: core_110, Dst: core_110},
					segfetcher.Request{SegType: Down, Src: core_210, Dst: core_210},
				},
			},
			"Core non-local wildcard": {
				// Wildcards are considered "core" by isCore(), so this goes to default case
				LocalIA: core_110,
				Dst:     isd2,
				ExpectedSet: segfetcher.Requests{
					segfetcher.Request{SegType: Core, Src: core_110, Dst: isd2},
					// One-hop requests for peering (default case adds dst->dst Down)
					segfetcher.Request{SegType: Up, Src: core_110, Dst: core_110},
					segfetcher.Request{SegType: Down, Src: isd2, Dst: isd2},
				},
			},
			"Up down local": {
				LocalIA: non_core_111,
				Dst:     non_core_112,
				ExpectedSet: segfetcher.Requests{
					segfetcher.Request{SegType: Up, Src: non_core_111, Dst: isd1},
					segfetcher.Request{SegType: Core, Src: isd1, Dst: isd1},
					segfetcher.Request{SegType: Down, Src: isd1, Dst: non_core_112},
					// One-hop requests for peering (same ISD, no cross-ISD)
					segfetcher.Request{SegType: Up, Src: core_110, Dst: core_110},
					segfetcher.Request{SegType: Up, Src: core_120, Dst: core_120},
					segfetcher.Request{SegType: Up, Src: core_130, Dst: core_130},
				},
			},
			"Up down non-local": {
				LocalIA: non_core_111,
				Dst:     non_core_211,
				ExpectedSet: segfetcher.Requests{
					segfetcher.Request{SegType: Up, Src: non_core_111, Dst: isd1},
					segfetcher.Request{SegType: Core, Src: isd1, Dst: isd2},
					segfetcher.Request{SegType: Down, Src: isd2, Dst: non_core_211},
					// One-hop requests for peering
					segfetcher.Request{SegType: Up, Src: core_110, Dst: core_110},
					segfetcher.Request{SegType: Up, Src: core_120, Dst: core_120},
					segfetcher.Request{SegType: Up, Src: core_130, Dst: core_130},
					segfetcher.Request{SegType: Down, Src: core_210, Dst: core_210},
				},
			},
		}
		for name, test := range tests {
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				_, core := cores[test.LocalIA]
				splitter := segfetcher.MultiSegmentSplitter{
					LocalIA:   test.LocalIA,
					Inspector: inspector,
					Core:      core,
				}
				requests, err := splitter.Split(context.Background(), test.Dst)
				if test.ExpectedErrMsg != "" {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), test.ExpectedErrMsg)
				} else {
					assert.NoError(t, err)
					assert.ElementsMatch(t, test.ExpectedSet, requests)
				}
			})
		}
	})
	t.Run("single core", func(t *testing.T) {
		cores := map[addr.IA]struct{}{
			core_110: {},
			core_210: {},
		}
		inspector := mock_trust.NewMockInspector(ctrl)
		inspector.EXPECT().HasAttributes(gomock.Any(), gomock.Any(), trust.Core).DoAndReturn(
			func(_ context.Context, ia addr.IA, _ trust.Attribute) (bool, error) {
				_, ok := cores[ia]
				return ok, nil
			},
		).AnyTimes()
		inspector.EXPECT().ByAttributes(gomock.Any(), gomock.Any(), trust.Core).DoAndReturn(
			func(_ context.Context, isd addr.ISD, _ trust.Attribute) ([]addr.IA, error) {
				var result []addr.IA
				for ia := range cores {
					if ia.ISD() == isd {
						result = append(result, ia)
					}
				}
				return result, nil
			},
		).AnyTimes()
		tests := map[string]struct {
			LocalIA        addr.IA
			Dst            addr.IA
			ExpectedSet    segfetcher.Requests
			ExpectedErrMsg string
		}{
			"Up": {
				// Single core in ISD1, returns early via singleCore path
				LocalIA: non_core_111,
				Dst:     core_110,
				ExpectedSet: segfetcher.Requests{
					segfetcher.Request{SegType: Up, Src: non_core_111, Dst: core_110},
				},
			},
			"Up wildcard": {
				LocalIA: non_core_111,
				Dst:     isd1,
				ExpectedSet: segfetcher.Requests{
					segfetcher.Request{SegType: Up, Src: non_core_111, Dst: isd1},
				},
			},
			"Up core non-local": {
				LocalIA: non_core_111,
				Dst:     core_210,
				ExpectedSet: segfetcher.Requests{
					segfetcher.Request{SegType: Up, Src: non_core_111, Dst: isd1},
					segfetcher.Request{SegType: Core, Src: isd1, Dst: core_210},
					// One-hop requests for peering
					segfetcher.Request{SegType: Down, Src: core_210, Dst: core_210},
					segfetcher.Request{SegType: Up, Src: core_110, Dst: core_110},
				},
			},
			"Up Core non-local wildcard": {
				// Wildcards are considered "core" by isCore(), so dstCore=true
				LocalIA: non_core_111,
				Dst:     isd2,
				ExpectedSet: segfetcher.Requests{
					segfetcher.Request{SegType: Up, Src: non_core_111, Dst: isd1},
					segfetcher.Request{SegType: Core, Src: isd1, Dst: isd2},
					// One-hop requests for peering (!srcCore && dstCore adds dst->dst Down and srcCores Up)
					segfetcher.Request{SegType: Down, Src: isd2, Dst: isd2},
					segfetcher.Request{SegType: Up, Src: core_110, Dst: core_110},
				},
			},
			"Down local": {
				// Single core in ISD1, returns early via singleCore path
				LocalIA: core_110,
				Dst:     non_core_111,
				ExpectedSet: segfetcher.Requests{
					segfetcher.Request{SegType: Down, Src: core_110, Dst: non_core_111},
				},
			},
			"Down non-local": {
				LocalIA: core_110,
				Dst:     non_core_211,
				ExpectedSet: segfetcher.Requests{
					segfetcher.Request{SegType: Core, Src: core_110, Dst: isd2},
					segfetcher.Request{SegType: Down, Src: isd2, Dst: non_core_211},
					// One-hop requests for peering
					segfetcher.Request{SegType: Up, Src: core_110, Dst: core_110},
					segfetcher.Request{SegType: Down, Src: core_210, Dst: core_210},
				},
			},
			"Core non-local": {
				LocalIA: core_110,
				Dst:     core_210,
				ExpectedSet: segfetcher.Requests{
					segfetcher.Request{SegType: Core, Src: core_110, Dst: core_210},
					// One-hop requests for peering
					segfetcher.Request{SegType: Up, Src: core_110, Dst: core_110},
					segfetcher.Request{SegType: Down, Src: core_210, Dst: core_210},
				},
			},
			"Core non-local wildcard": {
				// Wildcards are considered "core" by isCore(), so this goes to default case
				LocalIA: core_110,
				Dst:     isd2,
				ExpectedSet: segfetcher.Requests{
					segfetcher.Request{SegType: Core, Src: core_110, Dst: isd2},
					// One-hop requests for peering (default case adds dst->dst Down)
					segfetcher.Request{SegType: Up, Src: core_110, Dst: core_110},
					segfetcher.Request{SegType: Down, Src: isd2, Dst: isd2},
				},
			},
			"Up down local": {
				// Single core in ISD1, returns early via singleCore path
				LocalIA: non_core_111,
				Dst:     non_core_112,
				ExpectedSet: segfetcher.Requests{
					segfetcher.Request{SegType: Up, Src: non_core_111, Dst: core_110},
					segfetcher.Request{SegType: Down, Src: core_110, Dst: non_core_112},
				},
			},
			"Up down non-local": {
				LocalIA: non_core_111,
				Dst:     non_core_211,
				ExpectedSet: segfetcher.Requests{
					segfetcher.Request{SegType: Up, Src: non_core_111, Dst: isd1},
					segfetcher.Request{SegType: Core, Src: isd1, Dst: isd2},
					segfetcher.Request{SegType: Down, Src: isd2, Dst: non_core_211},
					// One-hop requests for peering
					segfetcher.Request{SegType: Up, Src: core_110, Dst: core_110},
					segfetcher.Request{SegType: Down, Src: core_210, Dst: core_210},
				},
			},
		}
		for name, test := range tests {
			t.Run(name, func(t *testing.T) {
				_, core := cores[test.LocalIA]
				splitter := segfetcher.MultiSegmentSplitter{
					LocalIA:   test.LocalIA,
					Inspector: inspector,
					Core:      core,
				}
				requests, err := splitter.Split(context.Background(), test.Dst)
				if test.ExpectedErrMsg != "" {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), test.ExpectedErrMsg)
				} else {
					assert.NoError(t, err)
					assert.ElementsMatch(t, test.ExpectedSet, requests)
				}
			})
		}
	})
}
