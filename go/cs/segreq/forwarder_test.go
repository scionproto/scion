// Copyright 2020 ETH Zurich
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

package segreq

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/proto"
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
	non_core_212 = xtest.MustParseIA("2-ff00:0:212")

	cores = map[addr.IA]struct{}{
		core_110: {},
		core_120: {},
		core_130: {},
		core_210: {},
	}
)

// newMockCoreChecker creates a CoreChecker with a mock ASInspector that checks the IAs
// in the cores map above.
func newMockCoreChecker(ctrl *gomock.Controller) CoreChecker {

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
	return CoreChecker{Inspector: inspector}
}

func TestForwarderClassify(t *testing.T) {
	type request struct {
		Src addr.IA
		Dst addr.IA
	}
	tests := map[string]struct {
		LocalIA         addr.IA
		Request         request
		ErrorAssertion  require.ErrorAssertionFunc
		ExpectedSegType proto.PathSegType
	}{
		"Invalid Src": {
			LocalIA: non_core_111,
			Request: request{
				Src: addr.IA{I: 0, A: non_core_111.A},
				Dst: core_110,
			},
			ErrorAssertion: require.Error,
		},
		"Invalid Dst": {
			LocalIA: non_core_111,
			Request: request{
				Src: non_core_111,
				Dst: addr.IA{I: 0, A: 0},
			},
			ErrorAssertion: require.Error,
		},
		"Core Wildcards Src & Dst": {
			LocalIA: non_core_111,
			Request: request{
				Src: addr.IA{I: 1, A: 0},
				Dst: addr.IA{I: 2, A: 0},
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: proto.PathSegType_core,
		},
		"Core Wildcard Src": {
			LocalIA: non_core_111,
			Request: request{
				Src: addr.IA{I: 1, A: 0},
				Dst: core_210,
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: proto.PathSegType_core,
		},
		"Core Wildcard Dst": {
			LocalIA: non_core_111,
			Request: request{
				Src: core_110,
				Dst: addr.IA{I: 2, A: 0},
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: proto.PathSegType_core,
		},
		"Core Invalid Src": {
			LocalIA: non_core_111,
			Request: request{
				Src: core_210, // Src not in local ISD
				Dst: core_110,
			},
			ErrorAssertion: require.Error,
		},
		"Down": {
			LocalIA: non_core_111,
			Request: request{
				Src: core_110,
				Dst: non_core_112,
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: proto.PathSegType_down,
		},
		"Down Wildcard": {
			LocalIA: non_core_111,
			Request: request{
				Src: addr.IA{I: 1, A: 0},
				Dst: non_core_112,
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: proto.PathSegType_down,
		},
		"Down Remote ISD": {
			LocalIA: non_core_111,
			Request: request{
				Src: core_210,
				Dst: non_core_212,
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: proto.PathSegType_down,
		},
		"Down Remote ISD Wildcard": {
			LocalIA: non_core_111,
			Request: request{
				Src: addr.IA{I: 2, A: 0},
				Dst: non_core_212,
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: proto.PathSegType_down,
		},
		"Down wrong ISD": {
			LocalIA: non_core_111,
			Request: request{
				Src: core_110,
				Dst: non_core_211,
			},
			ErrorAssertion: require.Error,
		},
		"Down Invalid Dst Local": {
			LocalIA: non_core_111,
			Request: request{
				Src: core_110,
				Dst: non_core_111,
			},
			ErrorAssertion: require.Error,
		},
		"Up": {
			LocalIA: non_core_111,
			Request: request{
				Src: non_core_111,
				Dst: core_110,
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: proto.PathSegType_up,
		},
		"Up Wildcard": {
			LocalIA: non_core_111,
			Request: request{
				Src: non_core_111,
				Dst: addr.IA{I: 1, A: 0},
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: proto.PathSegType_up,
		},
		"Up Invalid Src": {
			LocalIA: non_core_111,
			Request: request{
				Src: non_core_112,
				Dst: addr.IA{I: 1, A: 0},
			},
			ErrorAssertion: require.Error,
		},
		"Invalid Non-Core to Non-Core": {
			LocalIA: non_core_111,
			Request: request{
				Src: non_core_111,
				Dst: non_core_112,
			},
			ErrorAssertion: require.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			f := &forwarder{localIA: test.LocalIA, coreChecker: newMockCoreChecker(ctrl)}
			segType, err := f.classify(context.Background(), test.Request.Src, test.Request.Dst)
			test.ErrorAssertion(t, err)
			assert.Equal(t, test.ExpectedSegType, segType)
		})
	}
}
