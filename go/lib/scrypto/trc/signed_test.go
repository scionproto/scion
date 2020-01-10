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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
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
				base.Version = scrypto.LatestVer
			},
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			base := newBaseTRC(time.Now())
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
	valid, err := trc.Encode(newBaseTRC(time.Now()))
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
			Input:     "invalid/base64",
			Assertion: assert.Error,
		},
		"Garbage TRC": {
			Input:     trc.Encoded(encode("some_garbage")),
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
			Input:     "invalid/base64",
			Assertion: assert.Error,
		},
		"Invalid utf-8": {
			Input:     trc.EncodedProtected(scrypto.Base64.EncodeToString([]byte{0xfe})),
			Assertion: assert.Error,
		},
		"Garbage JSON": {
			Input:     trc.EncodedProtected(encode("some_garbage")),
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

func encode(input string) string {
	return scrypto.Base64.EncodeToString([]byte(input))
}

func newBaseProtected() trc.Protected {
	return trc.Protected{
		Algorithm:  scrypto.Ed25519,
		Type:       trc.VoteSignature,
		KeyType:    trc.VotingOnlineKey,
		KeyVersion: 1,
		AS:         xtest.MustParseAS("ff00:0:111"),
	}
}
