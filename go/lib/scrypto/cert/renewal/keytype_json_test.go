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

package renewal_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/cert/renewal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyTypeUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Input     string
		Assertion assert.ErrorAssertionFunc
		Expected  renewal.KeyType
	}{
		"Garbage": {
			Input:     `"test"`,
			Assertion: assert.Error,
		},
		"Integer": {
			Input:     `42`,
			Assertion: assert.Error,
		},
		"Wrong case": {
			Input:     `"Signing"`,
			Assertion: assert.Error,
		},
		"SigningKey": {
			Input:     `"signing"`,
			Assertion: assert.NoError,
			Expected:  renewal.SigningKey,
		},
		"EncryptionKey": {
			Input:     `"encryption"`,
			Assertion: assert.Error,
		},
		"IssuingKey": {
			Input:     `"issuing"`,
			Assertion: assert.Error,
		},
		"RevocationKey": {
			Input:     `"revocation"`,
			Assertion: assert.NoError,
			Expected:  renewal.RevocationKey,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var keyType renewal.KeyType
			test.Assertion(t, json.Unmarshal([]byte(test.Input), &keyType))
			assert.Equal(t, test.Expected, keyType)
		})
	}
}

func TestKeyTypeUnmarshalJSONMapKey(t *testing.T) {
	tests := map[string]struct {
		Input     string
		Assertion assert.ErrorAssertionFunc
	}{
		"Invalid KeyType": {
			Input: `
			{
				"unknown": "key"
			}`,
			Assertion: assert.Error,
		},
		"Valid": {
			Input: `
			{
				"signing": "key"
			}`,
			Assertion: assert.NoError,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var m map[renewal.KeyType]string
			test.Assertion(t, json.Unmarshal([]byte(test.Input), &m))
		})
	}
}

func TestKeyTypeMarshal(t *testing.T) {
	tests := map[string]struct {
		KeyType  renewal.KeyType
		Expected string
	}{
		"SigningKey": {
			KeyType:  renewal.SigningKey,
			Expected: cert.SigningKeyJSON,
		},
		"RevocationKey": {
			KeyType:  renewal.RevocationKey,
			Expected: cert.RevocationKeyJSON,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			b, err := json.Marshal(test.KeyType)
			require.NoError(t, err)
			assert.Equal(t, test.Expected, strings.Trim(string(b), `"`))
		})
	}
	t.Run("Invalid value", func(t *testing.T) {
		_, err := json.Marshal(renewal.KeyType(100))
		assert.Error(t, err)
	})
}
