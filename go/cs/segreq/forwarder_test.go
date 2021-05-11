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
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/mock_trust"
)

var (
	core110 = xtest.MustParseIA("1-ff00:0:110")
	core120 = xtest.MustParseIA("1-ff00:0:120")
	core130 = xtest.MustParseIA("1-ff00:0:130")
	core210 = xtest.MustParseIA("2-ff00:0:210")

	nonCore111 = xtest.MustParseIA("1-ff00:0:111")
	nonCore112 = xtest.MustParseIA("1-ff00:0:112")
	nonCore211 = xtest.MustParseIA("2-ff00:0:211")
	nonCore212 = xtest.MustParseIA("2-ff00:0:212")

	cores = map[addr.IA]struct{}{
		core110: {},
		core120: {},
		core130: {},
		core210: {},
	}
)

// newMockCoreChecker creates a CoreChecker with a mock ASInspector that checks the IAs
// in the cores map above.
func newMockCoreChecker(ctrl *gomock.Controller) CoreChecker {

	inspector := mock_trust.NewMockInspector(ctrl)
	inspector.EXPECT().HasAttributes(gomock.Any(), gomock.Any(), trust.Core).DoAndReturn(
		func(_ context.Context, ia addr.IA, _ trust.Attribute) (bool, error) {
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
		ExpectedSegType seg.Type
	}{
		"Invalid Src": {
			LocalIA: nonCore111,
			Request: request{
				Src: addr.IA{I: 0, A: nonCore111.A},
				Dst: core110,
			},
			ErrorAssertion: require.Error,
		},
		"Invalid Dst": {
			LocalIA: nonCore111,
			Request: request{
				Src: nonCore111,
				Dst: addr.IA{I: 0, A: 0},
			},
			ErrorAssertion: require.Error,
		},
		"Core Wildcards Src & Dst": {
			LocalIA: nonCore111,
			Request: request{
				Src: addr.IA{I: 1, A: 0},
				Dst: addr.IA{I: 2, A: 0},
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: seg.TypeCore,
		},
		"Core Wildcard Src": {
			LocalIA: nonCore111,
			Request: request{
				Src: addr.IA{I: 1, A: 0},
				Dst: core210,
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: seg.TypeCore,
		},
		"Core Wildcard Dst": {
			LocalIA: nonCore111,
			Request: request{
				Src: core110,
				Dst: addr.IA{I: 2, A: 0},
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: seg.TypeCore,
		},
		"Core Invalid Src": {
			LocalIA: nonCore111,
			Request: request{
				Src: core210, // Src not in local ISD
				Dst: core110,
			},
			ErrorAssertion: require.Error,
		},
		"Down": {
			LocalIA: nonCore111,
			Request: request{
				Src: core110,
				Dst: nonCore112,
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: seg.TypeDown,
		},
		"Down Wildcard": {
			LocalIA: nonCore111,
			Request: request{
				Src: addr.IA{I: 1, A: 0},
				Dst: nonCore112,
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: seg.TypeDown,
		},
		"Down Remote ISD": {
			LocalIA: nonCore111,
			Request: request{
				Src: core210,
				Dst: nonCore212,
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: seg.TypeDown,
		},
		"Down Remote ISD Wildcard": {
			LocalIA: nonCore111,
			Request: request{
				Src: addr.IA{I: 2, A: 0},
				Dst: nonCore212,
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: seg.TypeDown,
		},
		"Down wrong ISD": {
			LocalIA: nonCore111,
			Request: request{
				Src: core110,
				Dst: nonCore211,
			},
			ErrorAssertion: require.Error,
		},
		"Down Invalid Dst Local": {
			LocalIA: nonCore111,
			Request: request{
				Src: core110,
				Dst: nonCore111,
			},
			ErrorAssertion: require.Error,
		},
		"Up": {
			LocalIA: nonCore111,
			Request: request{
				Src: nonCore111,
				Dst: core110,
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: seg.TypeUp,
		},
		"Up Wildcard": {
			LocalIA: nonCore111,
			Request: request{
				Src: nonCore111,
				Dst: addr.IA{I: 1, A: 0},
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: seg.TypeUp,
		},
		"Up Invalid Src": {
			LocalIA: nonCore111,
			Request: request{
				Src: nonCore112,
				Dst: addr.IA{I: 1, A: 0},
			},
			ErrorAssertion: require.Error,
		},
		"Invalid Non-Core to Non-Core": {
			LocalIA: nonCore111,
			Request: request{
				Src: nonCore111,
				Dst: nonCore112,
			},
			ErrorAssertion: require.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			f := ForwardingLookup{LocalIA: test.LocalIA, CoreChecker: newMockCoreChecker(ctrl)}
			segType, err := f.classify(context.Background(), test.Request.Src, test.Request.Dst)
			test.ErrorAssertion(t, err)
			assert.Equal(t, test.ExpectedSegType, segType)
		})
	}
}
