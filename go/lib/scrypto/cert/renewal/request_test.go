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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert/renewal"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestEncodeRequest(t *testing.T) {
	tests := map[string]struct {
		Modify    func(base *renewal.Request)
		Assertion assert.ErrorAssertionFunc
	}{
		"Valid": {
			Modify:    func(*renewal.Request) {},
			Assertion: assert.NoError,
		},
		"Valid no POP": {
			Modify: func(base *renewal.Request) {
				base.POPs = nil
			},
			Assertion: assert.NoError,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			base := renewal.Request{
				Encoded: "request",
				POPs: []renewal.POP{{
					Protected: "protected",
					Signature: []byte("sig"),
				}},
			}
			test.Modify(&base)
			packed, err := renewal.EncodeRequest(&base)
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

func TestEncodedRequestDecode(t *testing.T) {
	base := renewal.Request{
		Encoded: "request",
		POPs: []renewal.POP{{
			Protected: "protected",
			Signature: []byte("sig"),
		}},
	}
	valid, err := renewal.EncodeRequest(&base)
	require.NoError(t, err)

	tests := map[string]struct {
		Input     renewal.EncodedRequest
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
		"Garbage request": {
			Input:     renewal.EncodedRequest(encode("some_garbage")),
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

func TestEncodeRequestInfo(t *testing.T) {
	tests := map[string]struct {
		Modify    func(base *renewal.RequestInfo)
		Assertion assert.ErrorAssertionFunc
	}{
		"Valid": {
			Modify:    func(*renewal.RequestInfo) {},
			Assertion: assert.NoError,
		},
		"Invalid version": {
			Modify: func(base *renewal.RequestInfo) {
				base.Version = scrypto.LatestVer
			},
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			base := newRequestInfo(time.Now())
			test.Modify(&base)
			packed, err := renewal.EncodeRequestInfo(&base)
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

func TestEncodedRequestInfoDecode(t *testing.T) {
	base := newRequestInfo(time.Now())
	valid, err := renewal.EncodeRequestInfo(&base)
	require.NoError(t, err)

	tests := map[string]struct {
		Input     renewal.EncodedRequestInfo
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
		"Garbage cert": {
			Input:     renewal.EncodedRequestInfo(encode("some_garbage")),
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
		Modify    func(base *renewal.Protected)
		Assertion assert.ErrorAssertionFunc
	}{
		"No modification": {
			Modify:    func(*renewal.Protected) {},
			Assertion: assert.NoError,
		},
		"Invalid KeyType": {
			Modify: func(base *renewal.Protected) {
				base.KeyType = renewal.KeyType("not found")
			},
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			base := renewal.Protected{
				Algorithm:  scrypto.Ed25519,
				KeyType:    renewal.SigningKey,
				KeyVersion: 2,
			}
			test.Modify(&base)
			packed, err := renewal.EncodeProtected(base)
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
	valid, err := renewal.EncodeProtected(renewal.Protected{
		Algorithm:  scrypto.Ed25519,
		KeyType:    renewal.SigningKey,
		KeyVersion: 2,
	})
	require.NoError(t, err)
	tests := map[string]struct {
		Input     renewal.EncodedProtected
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
			Input:     renewal.EncodedProtected(scrypto.Base64.EncodeToString([]byte{0xfe})),
			Assertion: assert.Error,
		},
		"Garbage JSON": {
			Input:     renewal.EncodedProtected(encode("some_garbage")),
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

func newRequestInfo(now time.Time) renewal.RequestInfo {
	now = now.Truncate(time.Second)
	return renewal.RequestInfo{
		Subject:       xtest.MustParseIA("1-ff00:0:111"),
		Version:       2,
		FormatVersion: 1,
		Description:   "This is a base request",
		Validity: &scrypto.Validity{
			NotBefore: util.UnixTime{Time: now},
			NotAfter:  util.UnixTime{Time: now.Add(8760 * time.Hour)},
		},
		Keys: renewal.Keys{
			Signing:    renewal.KeyMeta{Key: []byte("signKey1")},
			Revocation: renewal.KeyMeta{Key: []byte("revKey1")},
		},
		Issuer:      xtest.MustParseIA("1-ff00:0:110"),
		RequestTime: util.UnixTime{Time: now},
	}
}
