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

package renewal_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/scrypto/cert/renewal"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestKeyTypeValidate(t *testing.T) {
	tests := map[string]struct {
		KeyType renewal.KeyType
		Error   error
	}{
		"valid signing":    {KeyType: renewal.SigningKey},
		"valid revocation": {KeyType: renewal.RevocationKey},
		"invalid encryption": {
			KeyType: renewal.KeyType("encryption"),
			Error:   renewal.ErrInvalidKeyType,
		},
		"invalid garbage": {
			KeyType: renewal.KeyType("garbage"),
			Error:   renewal.ErrInvalidKeyType,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			xtest.AssertErrorsIs(t, test.KeyType.Validate(), test.Error)
		})
	}
}

func TestKeyTypeUnmarshal(t *testing.T) {
	tests := map[string]struct {
		Input     string
		Expected  renewal.KeyType
		Assertion assert.ErrorAssertionFunc
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

func TestKeyTypeMarshal(t *testing.T) {
	tests := map[string]struct {
		KeyType renewal.KeyType
		Error   error
	}{
		"valid signing":    {KeyType: renewal.SigningKey},
		"valid revocation": {KeyType: renewal.RevocationKey},
		"invalid encryption": {
			KeyType: renewal.KeyType("encryption"),
			Error:   renewal.ErrInvalidKeyType,
		},
		"invalid garbage": {
			KeyType: renewal.KeyType("garbage"),
			Error:   renewal.ErrInvalidKeyType,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			b, err := json.Marshal(test.KeyType)
			xtest.AssertErrorsIs(t, err, test.Error)
			if test.Error == nil {
				assert.Equal(t, string(test.KeyType), strings.Trim(string(b), `"`))
			}
		})
	}
}
