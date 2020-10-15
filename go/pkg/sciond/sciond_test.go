// Copyright 2030 Anapaya Systems
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

package sciond_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/pkg/sciond"
)

func TestAPIAddress(t *testing.T) {
	testCases := map[string]struct {
		Input    string
		Expected string
	}{
		"valid": {
			Input:    "127.0.0.1:8081",
			Expected: "127.0.0.1:8081",
		},
		"valid, no port": {
			Input:    "127.0.0.1",
			Expected: "127.0.0.1:30255",
		},
		"valid, empty port": {
			Input:    "[::]:",
			Expected: "[::]:30255",
		},
		"hostname, zero port": {
			Input:    "daemon:0",
			Expected: "daemon:30255",
		},
		"garbage": {
			Input:    "127.0.0.1::1:1]::1:1",
			Expected: "[127.0.0.1::1:1]::1:1]:30255",
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			addr := sciond.APIAddress(tc.Input)
			assert.Equal(t, tc.Expected, addr)
		})
	}
}
