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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestKeyMetaUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Input          string
		Meta           scrypto.KeyMeta
		ExpectedErrMsg string
	}{
		"Valid": {
			Input: `
			{
				"KeyVersion": 1,
				"Algorithm": "ed25519",
				"Key": "YW5hcGF5YSDinaQgIHNjaW9u"
			}`,
			Meta: scrypto.KeyMeta{
				KeyVersion: 1,
				Algorithm:  scrypto.Ed25519,
				Key:        xtest.MustParseHexString("616e617061796120e29da420207363696f6e"),
			},
		},
		"KeyVersion not set": {
			Input: `
			{
				"Algorithm": "ed25519",
				"Key": "YW5hcGF5YSDinaQgIHNjaW9u"
			}`,
			ExpectedErrMsg: scrypto.ErrKeyVersionNotSet.Error(),
		},
		"Algorithm not set": {
			Input: `
			{
				"KeyVersion": 1,
				"Key": "YW5hcGF5YSDinaQgIHNjaW9u"
			}`,
			ExpectedErrMsg: scrypto.ErrAlgorithmNotSet.Error(),
		},
		"Key not set": {
			Input: `
			{
				"KeyVersion": 1,
				"Algorithm": "ed25519"
			}`,
			ExpectedErrMsg: scrypto.ErrKeyNotSet.Error(),
		},
		"Unknown field": {
			Input: `
			{
				"UnknownField": "UNKNOWN"
			}`,
			ExpectedErrMsg: `json: unknown field "UnknownField"`,
		},
		"invalid json": {
			Input: `
			{
				"KeyVersion": 1,
				"Algorithm": "ed25519"
			`,
			ExpectedErrMsg: "unexpected end of JSON input",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var meta scrypto.KeyMeta
			err := json.Unmarshal([]byte(test.Input), &meta)
			if test.ExpectedErrMsg == "" {
				require.NoError(t, err)
				assert.Equal(t, test.Meta, meta)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedErrMsg)
			}
		})
	}
}
