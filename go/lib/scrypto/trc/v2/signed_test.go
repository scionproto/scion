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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	trc "github.com/scionproto/scion/go/lib/scrypto/trc/v2"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestEncode(t *testing.T) {
	tests := map[string]struct {
		Modify    func(base *trc.TRC)
		Assertion assert.ErrorAssertionFunc
	}{
		"No modification": {
			Modify:    func(*trc.TRC) {},
			Assertion: assert.NoError,
		},
		"Invalid Version": {
			Modify: func(base *trc.TRC) {
				base.Version = trc.Version(scrypto.LatestVer)
			},
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			base := newBaseTRC()
			test.Modify(base)
			packed, err := trc.Encode(base)
			test.Assertion(t, err)
			if err != nil {
				return
			}
			unpacked, err := packed.Decode()
			require.NoError(t, err)
			assert.Equal(t, base, unpacked)
		})
	}
}

func TestEncodedDecode(t *testing.T) {
	valid, err := trc.Encode(newBaseTRC())
	require.NoError(t, err)

	tests := map[string]struct {
		Input     trc.Encoded
		Assertion assert.ErrorAssertionFunc
	}{
		"Valid": {
			Input:     valid,
			Assertion: assert.NoError,
		},
		"Invalid Base 64": {
			Input:     []byte("invalid/base64"),
			Assertion: assert.Error,
		},
		"Garbage TRC": {
			Input:     []byte(scrypto.Base64.EncodeToString(valid[:len(valid)/2])),
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := test.Input.Decode()
			test.Assertion(t, err)
		})
	}
}

func TestEncodeProtected(t *testing.T) {
	tests := map[string]struct {
		Modify    func(base *trc.Protected)
		Assertion assert.ErrorAssertionFunc
	}{
		"No modification": {
			Modify:    func(*trc.Protected) {},
			Assertion: assert.NoError,
		},
		"Invalid AS": {
			Modify: func(base *trc.Protected) {
				base.AS = addr.MaxAS + 1
			},
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			base := newBaseProtected()
			test.Modify(&base)
			packed, err := trc.EncodeProtected(base)
			test.Assertion(t, err)
			if err != nil {
				return
			}
			unpacked, err := packed.Decode()
			require.NoError(t, err)
			assert.Equal(t, base, unpacked)
		})
	}
}

func TestEncodedProtectedDecode(t *testing.T) {
	valid, err := trc.EncodeProtected(newBaseProtected())
	require.NoError(t, err)

	tests := map[string]struct {
		Input     trc.EncodedProtected
		Assertion assert.ErrorAssertionFunc
	}{
		"Valid": {
			Input:     valid,
			Assertion: assert.NoError,
		},
		"Invalid Base 64": {
			Input:     []byte("invalid/base64"),
			Assertion: assert.Error,
		},
		"Invalid utf-8": {
			Input:     []byte(scrypto.Base64.EncodeToString([]byte{0xfe})),
			Assertion: assert.Error,
		},
		"Garbage JSON": {
			Input:     []byte(scrypto.Base64.EncodeToString(valid[:len(valid)/2])),
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := test.Input.Decode()
			test.Assertion(t, err)
		})
	}
}

func TestCritUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Input     []byte
		Expected  time.Duration
		Assertion assert.ErrorAssertionFunc
	}{
		"Type, KeyType, KeyVersion, AS": {
			Input:     []byte(`{"crit": ["Type", "KeyType", "KeyVersion", "AS"]}`),
			Assertion: assert.NoError,
		},
		"AS, KeyType, KeyVersion, Type": {
			Input:     []byte(`{"crit": ["AS", "KeyType", "KeyVersion", "Type"]}`),
			Assertion: assert.NoError,
		},
		"Duplication length 4": {
			Input:     []byte(`{"crit": ["AS", "AS", "KeyVersion", "Type"]}`),
			Assertion: assert.Error,
		},
		"Duplication length 5": {
			Input:     []byte(`{"crit": ["AS", "AS", "KeyType", "KeyVersion", "Type"]}`),
			Assertion: assert.Error,
		},
		"Missing KeyType": {
			Input:     []byte(`{"crit": ["AS", "Type", "KeyVersion"]}`),
			Assertion: assert.Error,
		},
		"Missing AS": {
			Input:     []byte(`{"crit": ["Type", "KeyType", "KeyVersion"]}`),
			Assertion: assert.Error,
		},
		"Missing Type": {
			Input:     []byte(`{"crit": ["AS", "KeyType", "KeyVersion"]}`),
			Assertion: assert.Error,
		},
		"Missing KeyVersion": {
			Input:     []byte(`{"crit": ["AS", "KeyType", "Type"]}`),
			Assertion: assert.Error,
		},
		"Invalid json": {
			Input:     []byte(`{"crit":10}`),
			Assertion: assert.Error,
		},
		"Unknown Entry": {
			Input:     []byte(`{"crit": ["AS", "KeyType", "Garbage", "Type"]}`),
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var protected trc.Protected
			test.Assertion(t, json.Unmarshal(test.Input, &protected))
		})
	}
}

func TestCritMarshalJSON(t *testing.T) {
	b, err := json.Marshal(trc.Protected{})
	require.NoError(t, err)
	var protected struct {
		Crit []string `json:"crit"`
	}
	require.NoError(t, json.Unmarshal(b, &protected))
	assert.ElementsMatch(t, []string{"Type", "KeyType", "KeyVersion", "AS"}, protected.Crit)
}

func newBaseProtected() trc.Protected {
	return trc.Protected{
		Algorithm:  scrypto.Ed25519,
		Type:       trc.OnlineKey,
		KeyVersion: 1,
		AS:         xtest.MustParseAS("ff00:0:111"),
	}
}
