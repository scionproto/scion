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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/scrypto"
)

func TestCheckCrit(t *testing.T) {
	crit := []string{"type", "certificate_version", "ia"}
	tests := map[string]struct {
		Input     []byte
		Assertion assert.ErrorAssertionFunc
	}{
		"Valid": {
			Input:     []byte(`["type", "certificate_version", "ia"]`),
			Assertion: assert.NoError,
		},
		"Out of order": {
			Input:     []byte(`["type", "ia", "certificate_version"]`),
			Assertion: assert.Error,
		},
		"Length mismatch": {
			Input:     []byte(`["type", "certificate_version"]`),
			Assertion: assert.Error,
		},
		"Invalid json": {
			Input:     []byte(`{"crit":10}`),
			Assertion: assert.Error,
		},
		"Unknown Entry": {
			Input:     []byte(`["type", "certificate_version", "Garbage", "ia"]`),
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Assertion(t, scrypto.CheckCrit(test.Input, crit))
		})
	}
}
