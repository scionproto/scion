// Copyright 2021 Anapaya Systems
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

package env_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/private/app/env"
)

func TestSCION(t *testing.T) {
	testCases := map[string]struct {
		Input           string
		parseError      assert.ErrorAssertionFunc
		validationError assert.ErrorAssertionFunc
	}{
		"valid": {
			Input: `
				{
					"general": {
						"default_isd_as": "1-ff00:0:1"
					},
					"ases": {
						"1-ff00:0:1": {
							"daemon_address": "localhost:30256"
						}
					}
				}
			`,
			parseError:      assert.NoError,
			validationError: assert.NoError,
		},
		"parse error": {
			Input: `
				{
					"general": {
						"default_isd_as": "1-ff00:0:1"
					},
					"ases": {
						"invalid-ia": {
							"daemon_address": "localhost:30256"
						}
					}
				}
			`,
			parseError:      assert.Error,
			validationError: assert.NoError,
		},
		"validation error - general": {
			Input: `
				{
					"general": {
						"default_isd_as": "1-0"
					},
					"ases": {
						"1-ff00:0:1": {
							"daemon_address": "localhost:30256"
						}
					}
				}
			`,
			parseError:      assert.NoError,
			validationError: assert.Error,
		},
		"validation error - ases": {
			Input: `
				{
					"general": {
						"default_isd_as": "1-ff00:0:1"
					},
					"ases": {
						"1-ff00:0:1": {
							"daemon_address": "0.0.0.0:30256"
						}
					}
				}
			`,
			parseError:      assert.NoError,
			validationError: assert.Error,
		},
		// Fine-grained validation errors are covered in the tests for the individual sections.
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var s env.SCION
			err := json.Unmarshal([]byte(tc.Input), &s)
			tc.parseError(t, err)
			if err == nil {
				tc.validationError(t, s.Validate())
			}
		})
	}
}

func TestGeneral(t *testing.T) {
	testCases := map[string]struct {
		Input           string
		parseError      assert.ErrorAssertionFunc
		validationError assert.ErrorAssertionFunc
	}{
		"valid": {
			Input: `
				{
					"default_isd_as": "1-ff00:0:1"
				}
			`,
			parseError:      assert.NoError,
			validationError: assert.NoError,
		},
		"parse error": {
			Input: `
				{
					"default_isd_as": "invalid"
				}
			`,
			parseError:      assert.Error,
			validationError: assert.NoError,
		},
		"validation error": {
			Input: `
				{
					"default_isd_as": "1-0"
				}
			`,
			parseError:      assert.NoError,
			validationError: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var g env.General
			err := json.Unmarshal([]byte(tc.Input), &g)
			tc.parseError(t, err)
			if err == nil {
				tc.validationError(t, g.Validate())
			}
		})
	}
}

func TestAS(t *testing.T) {
	testCases := map[string]struct {
		Input           string
		parseError      assert.ErrorAssertionFunc
		validationError assert.ErrorAssertionFunc
	}{
		"valid": {
			Input: `
				{
					"daemon_address": "localhost:30256"
				}
			`,
			parseError:      assert.NoError,
			validationError: assert.NoError,
		},
		"parse error": {
			Input: `
				{
					"daemon_address": 1234
				}
			`,
			parseError:      assert.Error,
			validationError: assert.NoError,
		},
		"invalid host:port string": {
			Input: `
				{
					"daemon_address": "localhost:30256:"
				}
			`,
			parseError:      assert.NoError,
			validationError: assert.Error,
		},
		"wildcard ip": {
			Input: `
				{
					"daemon_address": "[::]:30256"
				}
			`,
			parseError:      assert.NoError,
			validationError: assert.Error,
		},
		"port too large": {
			Input: `
				{
					"daemon_address": "192.168.1.1:302560"
				}
			`,
			parseError:      assert.NoError,
			validationError: assert.Error,
		},
		"port 0": {
			Input: `
				{
					"daemon_address": "scion.net:0"
				}
			`,
			parseError:      assert.NoError,
			validationError: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var as env.AS
			err := json.Unmarshal([]byte(tc.Input), &as)
			tc.parseError(t, err)
			if err == nil {
				tc.validationError(t, as.Validate())
			}
		})
	}
}
