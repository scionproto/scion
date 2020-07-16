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

package slayers_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/slayers"
)

func TestTypeSCMPCodeString(t *testing.T) {
	testCases := map[string]struct {
		c    slayers.SCMPTypeCode
		want string
	}{
		"unknown type": {
			c:    slayers.CreateSCMPTypeCode(0, 0),
			want: "0(0)",
		},
		"known type known code": {
			c:    slayers.CreateSCMPTypeCode(4, 0),
			want: "ParameterProblem(ErroneousHeaderField)",
		},
		"known type unknown code": {
			c:    slayers.CreateSCMPTypeCode(4, 100),
			want: "ParameterProblem(Code: 100)",
		},
		"known type without code": {
			c:    slayers.CreateSCMPTypeCode(5, 0),
			want: "ExternalInterfaceDown",
		},
		"known type unknown code no mapping": {
			c:    slayers.CreateSCMPTypeCode(128, 1),
			want: "EchoRequest(Code: 1)",
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := tc.c.String()
			assert.Equal(t, tc.want, got)
		})
	}
}
