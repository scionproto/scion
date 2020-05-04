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
	"github.com/scionproto/scion/go/proto"
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
		ExpectedSegType proto.PathSegType
	}{
		"Invalid Src": {
			LocalIA: core_110,
			Request: request{
				Src: core_210,
				Dst: core_110,
			},
			ErrorAssertion: require.Error,
		},
		"Invalid Src Wildcard": {
			LocalIA: core_110,
			Request: request{
				Src: addr.IA{I: 1, A: 0},
				Dst: core_210,
			},
			ErrorAssertion: require.Error,
		},
		"Invalid Dst": {
			LocalIA: core_110,
			Request: request{
				Src: core_110,
				Dst: addr.IA{I: 0, A: 0},
			},
			ErrorAssertion: require.Error,
		},
		"Core Local ISD": {
			LocalIA: core_110,
			Request: request{
				Src: core_110,
				Dst: core_120,
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: proto.PathSegType_core,
		},
		"Core Remote ISD": {
			LocalIA: core_110,
			Request: request{
				Src: core_110,
				Dst: core_210,
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: proto.PathSegType_core,
		},
		"Core Wildcard Local ISD": {
			LocalIA: core_110,
			Request: request{
				Src: core_110,
				Dst: addr.IA{I: 1, A: 0},
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: proto.PathSegType_core,
		},
		"Core Wildcard Remote ISD": {
			LocalIA: core_110,
			Request: request{
				Src: core_110,
				Dst: addr.IA{I: 2, A: 0},
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: proto.PathSegType_core,
		},
		"Core Remote ISD Non-Core ": {
			LocalIA: core_110,
			Request: request{
				Src: core_110,
				Dst: non_core_211,
			},
			// core/non-core dst in remote ISD unchecked! Could also be an error...
			ErrorAssertion:  require.NoError,
			ExpectedSegType: proto.PathSegType_core,
		},
		"Down": {
			LocalIA: core_110,
			Request: request{
				Src: core_110,
				Dst: non_core_111,
			},
			ErrorAssertion:  require.NoError,
			ExpectedSegType: proto.PathSegType_down,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			p := &authoritativeProcessor{
				localIA:     test.LocalIA,
				coreChecker: newMockCoreChecker(ctrl),
			}
			segType, err := p.classify(context.Background(), test.Request.Src, test.Request.Dst)
			test.ErrorAssertion(t, err)
			assert.Equal(t, test.ExpectedSegType, segType)
		})
	}
}
