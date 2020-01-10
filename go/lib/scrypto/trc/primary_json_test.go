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

package trc_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestPrimaryASUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Input          string
		Primary        trc.PrimaryAS
		ExpectedErrMsg string
	}{
		"Valid": {
			Input: `
			{
				"attributes": ["issuing", "core"],
				"keys": {
					"issuing_grant": {
						"key_version": 1,
    					"algorithm": "ed25519",
    					"key": "YW5hcGF5YSDinaQgIHNjaW9u"
					}
				}
			}`,
			Primary: trc.PrimaryAS{
				Attributes: trc.Attributes{"issuing", "core"},
				Keys: map[trc.KeyType]scrypto.KeyMeta{
					trc.IssuingGrantKey: {
						KeyVersion: 1,
						Algorithm:  scrypto.Ed25519,
						Key: xtest.MustParseHexString("616e617061796120e2" +
							"9da420207363696f6e"),
					},
				},
			},
		},
		"Attributes not set": {
			Input: `
			{
				"keys": {
					"issuing_grant": {
						"key_version": 1,
						"algorithm": "ed25519",
						"key": "YW5hcGF5YSDinaQgIHNjaW9u"
					}
				}
			}`,
			ExpectedErrMsg: trc.ErrAttributesNotSet.Error(),
		},
		"Keys not set": {
			Input: `
			{
				"attributes": ["issuing", "core"]
			}`,
			ExpectedErrMsg: trc.ErrKeysNotSet.Error(),
		},
		"Invalid key meta": {
			Input: `
			{
				"attributes": ["issuing", "core"],
				"keys": {
					"issuing_grant": {
						"algorithm": "ed25519",
						"key": "YW5hcGF5YSDinaQgIHNjaW9u"
					}
				}
			}`,
			ExpectedErrMsg: scrypto.ErrKeyVersionNotSet.Error(),
		},
		"Unknown key": {
			Input: `
			{
				"attributes": ["core"],
				"keys": {
					"signing": {
						"key_version": 1,
						"algorithm": "ed25519",
						"key": "YW5hcGF5YSDinaQgIHNjaW9u"
					}
				}
			}`,
			ExpectedErrMsg: trc.ErrInvalidKeyType.Error(),
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var primary trc.PrimaryAS
			err := json.Unmarshal([]byte(test.Input), &primary)
			if test.ExpectedErrMsg == "" {
				require.NoError(t, err)
				assert.Equal(t, test.Primary, primary)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedErrMsg)
			}
		})
	}
}

func TestAttributesUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Input     string
		Assertion assert.ErrorAssertionFunc
		Expected  trc.Attributes
	}{
		"Garbage": {
			Input:     `"test"`,
			Assertion: assert.Error,
		},
		"Empty": {
			Input:     `[]`,
			Assertion: assert.Error,
		},
		"Non-Core and Authoritative": {
			Input:     `["authoritative"]`,
			Assertion: assert.Error,
		},
		"Duplication": {
			Input:     `["core", "core"]`,
			Assertion: assert.Error,
		},
		"Authoritative, core, issuing and voting": {
			Input:     `["authoritative", "issuing", "core", "voting"]`,
			Assertion: assert.NoError,
			Expected:  trc.Attributes{trc.Authoritative, trc.Issuing, trc.Voting, trc.Core},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var attrs trc.Attributes
			test.Assertion(t, json.Unmarshal([]byte(test.Input), &attrs))
			if test.Expected != nil {
				assert.ElementsMatch(t, test.Expected, attrs)
			}
		})
	}
}

func TestAttributesMarshalJSON(t *testing.T) {
	type mockPrimaryAS struct {
		Attributes trc.Attributes `json:"attributes"`
	}
	tests := map[string]struct {
		Attrs     trc.Attributes
		Expected  []byte
		Assertion assert.ErrorAssertionFunc
	}{
		"Duplication": {
			Attrs:     trc.Attributes{trc.Core, trc.Core},
			Assertion: assert.Error,
		},
		"Non-Core and authoritative": {
			Attrs:     trc.Attributes{trc.Authoritative},
			Assertion: assert.Error,
		},
		"Core and voting": {
			Attrs:     trc.Attributes{trc.Voting, trc.Core},
			Expected:  []byte(`{"attributes":["voting","core"]}`),
			Assertion: assert.NoError,
		},
		"Authoritative, core, voting and issuing": {
			Attrs:     trc.Attributes{trc.Authoritative, trc.Issuing, trc.Voting, trc.Core},
			Expected:  []byte(`{"attributes":["authoritative","issuing","voting","core"]}`),
			Assertion: assert.NoError,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			b, err := json.Marshal(mockPrimaryAS{Attributes: test.Attrs})
			test.Assertion(t, err)
			assert.Equal(t, test.Expected, b)
		})
	}
}

func TestAttributeUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Input     string
		Assertion assert.ErrorAssertionFunc
		Expected  trc.Attribute
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
			Input:     `"Voting"`,
			Assertion: assert.Error,
		},
		"Authoritative": {
			Input:     `"authoritative"`,
			Assertion: assert.NoError,
			Expected:  trc.Authoritative,
		},
		"Core": {
			Input:     `"core"`,
			Assertion: assert.NoError,
			Expected:  trc.Core,
		},
		"Issuing": {
			Input:     `"issuing"`,
			Assertion: assert.NoError,
			Expected:  trc.Issuing,
		},
		"Voting": {
			Input:     `"voting"`,
			Assertion: assert.NoError,
			Expected:  trc.Voting,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var attr trc.Attribute
			test.Assertion(t, json.Unmarshal([]byte(test.Input), &attr))
			assert.Equal(t, test.Expected, attr)
		})
	}
}

func TestKeyTypeUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Input     string
		Assertion assert.ErrorAssertionFunc
		Expected  trc.KeyType
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
			Input:     `"Voting_offline"`,
			Assertion: assert.Error,
		},
		"OfflineKey": {
			Input:     `"voting_offline"`,
			Assertion: assert.NoError,
			Expected:  trc.VotingOfflineKey,
		},
		"OnlineKey": {
			Input:     `"voting_online"`,
			Assertion: assert.NoError,
			Expected:  trc.VotingOnlineKey,
		},
		"IssuingKey": {
			Input:     `"issuing_grant"`,
			Assertion: assert.NoError,
			Expected:  trc.IssuingGrantKey,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var attr trc.KeyType
			test.Assertion(t, json.Unmarshal([]byte(test.Input), &attr))
			assert.Equal(t, test.Expected, attr)
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
				"issuing_grant": "key"
			}`,
			Assertion: assert.NoError,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var m map[trc.KeyType]string
			test.Assertion(t, json.Unmarshal([]byte(test.Input), &m))
		})
	}
}

func TestKeyTypeMarshal(t *testing.T) {
	tests := map[string]struct {
		KeyType  trc.KeyType
		Expected string
	}{
		"OfflineKey": {
			KeyType:  trc.VotingOfflineKey,
			Expected: trc.VotingOfflineKeyJSON,
		},
		"OnlineKey": {
			KeyType:  trc.VotingOnlineKey,
			Expected: trc.VotingOnlineKeyJSON,
		},
		"IssuingKey": {
			KeyType:  trc.IssuingGrantKey,
			Expected: trc.IssuingGrantKeyJSON,
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
		_, err := json.Marshal(trc.KeyType(100))
		assert.Error(t, err)
	})
}
