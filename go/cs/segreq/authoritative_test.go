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
)

func TestAuthoritativeClassify(t *testing.T) {
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
			LocalIA: core110,
			Request: request{
				Src: core210,
				Dst: core110,
			},
			ErrorAssertion: require.Error,
		},
		"Invalid Src Wildcard": {
			LocalIA: core110,
			Request: request{
				Src: addr.IA{I: 1, A: 0},
				Dst: core210,
			},
			ErrorAssertion: require.Error,
		},
		"Invalid Dst": {
			LocalIA: core110,
			Request: request{
				Src: core110,
				Dst: addr.IA{I: 0, A: 0},
			},
			ErrorAssertion: require.Error,
		},
		"Core Local ISD": {
			LocalIA: core110,
			Request: request{
				Src: core110,
				Dst: core120,
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: seg.TypeCore,
		},
		"Core Remote ISD": {
			LocalIA: core110,
			Request: request{
				Src: core110,
				Dst: core210,
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: seg.TypeCore,
		},
		"Core Wildcard Local ISD": {
			LocalIA: core110,
			Request: request{
				Src: core110,
				Dst: addr.IA{I: 1, A: 0},
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: seg.TypeCore,
		},
		"Core Wildcard Remote ISD": {
			LocalIA: core110,
			Request: request{
				Src: core110,
				Dst: addr.IA{I: 2, A: 0},
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: seg.TypeCore,
		},
		"Core Remote ISD Non-Core ": {
			LocalIA: core110,
			Request: request{
				Src: core110,
				Dst: nonCore211,
			},
			// core/non-core dst in remote ISD unchecked! Returning an error would be ok too...
			ErrorAssertion:  require.NoError,
			ExpectedSegType: seg.TypeCore,
		},
		"Down": {
			LocalIA: core110,
			Request: request{
				Src: core110,
				Dst: nonCore111,
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: seg.TypeDown,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			p := AuthoritativeLookup{
				LocalIA:     test.LocalIA,
				CoreChecker: newMockCoreChecker(ctrl),
			}
			segType, err := p.classify(context.Background(), test.Request.Src, test.Request.Dst)
			test.ErrorAssertion(t, err)
			assert.Equal(t, test.ExpectedSegType, segType)
		})
	}
}
