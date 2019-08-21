// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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
package sciond

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPathInterface(t *testing.T) {
	tests := map[string]struct {
		In  string
		PI  PathInterface
		Err assert.ErrorAssertionFunc
	}{
		"AS, IF wildcard omitted": {
			In:  "1",
			Err: assert.Error,
		},
		"IF wildcard omitted": {
			In:  "1-0",
			Err: assert.Error,
		},
		"basic wildcard": {
			In:  "1-0#0",
			PI:  mustPathInterface(t, "1-0#0"),
			Err: assert.NoError,
		},
		"AS wildcard, interface set": {
			In:  "1-0#1",
			PI:  mustPathInterface(t, "1-0#1"),
			Err: assert.NoError,
		},
		"ISD wildcard, AS set": {
			In:  "0-1#0",
			PI:  mustPathInterface(t, "0-1#0"),
			Err: assert.NoError,
		},
		"ISD wildcard, AS set, interface set": {
			In:  "0-1#1",
			PI:  mustPathInterface(t, "0-1#1"),
			Err: assert.NoError,
		},
		"ISD wildcard, AS set and interface omitted": {
			In:  "0-1",
			Err: assert.Error,
		},
		"IF wildcard omitted, AS set": {
			In:  "1-1",
			Err: assert.Error,
		},
		"bad -": {
			In:  "1-1-0",
			Err: assert.Error,
		},
		"bad #": {
			In:  "1-1#0#",
			Err: assert.Error,
		},
		"bad IF": {
			In:  "1-1#e",
			Err: assert.Error,
		},
		"bad AS": {
			In:  "1-12323433243534#0",
			Err: assert.Error,
		},
		"bad ISD": {
			In:  "1123212-23#0",
			Err: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			pi, err := NewPathInterface(test.In)
			test.Err(t, err)
			assert.Equal(t, test.PI, pi)
		})
	}
}
func mustPathInterface(t *testing.T, str string) PathInterface {
	t.Helper()
	pi, err := NewPathInterface(str)
	require.NoError(t, err)
	return pi
}
