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

package scrypto_test

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/scrypto"
)

func TestVersionUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Input     []byte
		Expected  scrypto.Version
		Assertion assert.ErrorAssertionFunc
	}{
		"Valid": {
			Input:     []byte("1"),
			Expected:  1,
			Assertion: assert.NoError,
		},
		"Reserved": {
			Input:     []byte(strconv.FormatUint(scrypto.LatestVer, 10)),
			Assertion: assert.Error,
		},
		"String": {
			Input:     []byte(`"1"`),
			Assertion: assert.Error,
		},
		"Garbage": {
			Input:     []byte(`"Garbage"`),
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var v scrypto.Version
			test.Assertion(t, json.Unmarshal(test.Input, &v))
			assert.Equal(t, test.Expected, v)
		})
	}
}

func TestVersionMarshalJSON(t *testing.T) {
	type mockObj struct {
		Version scrypto.Version
	}
	tests := map[string]struct {
		// Use a struct to simulate value type marshaling. Pointer vs value receiver.
		Input     mockObj
		Expected  []byte
		Assertion assert.ErrorAssertionFunc
	}{
		"Valid": {
			Input:     mockObj{Version: 1},
			Expected:  []byte(`{"Version":1}`),
			Assertion: assert.NoError,
		},
		"Reserved": {
			Input:     mockObj{Version: scrypto.Version(scrypto.LatestVer)},
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			b, err := json.Marshal(test.Input)
			test.Assertion(t, err)
			assert.Equal(t, test.Expected, b)
		})
	}
}
