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

package reissuance_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cert_srv/internal/reissuance"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert/v2"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestEncodeRequest(t *testing.T) {
	tests := map[string]struct {
		Modify    func(base *reissuance.Request)
		Assertion assert.ErrorAssertionFunc
	}{
		"Valid": {
			Modify:    func(*reissuance.Request) {},
			Assertion: assert.NoError,
		},
		"Valid no POP": {
			Modify: func(base *reissuance.Request) {
				base.POPs = []reissuance.POP{}
			},
			Assertion: assert.NoError,
		},
		"Invalid version": {
			Modify: func(base *reissuance.Request) {
				base.Version = scrypto.LatestVer
			},
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			base := reissuance.Request{
				BaseRequest: newBaseRequest(time.Now()),
				POPs: []reissuance.POP{{
					Encoded:          []byte("encoded"),
					EncodedProtected: "protected",
					Signature:        []byte("sig"),
				}},
			}
			test.Modify(&base)
			packed, err := reissuance.EncodeRequest(&base)
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
	base := reissuance.Request{
		BaseRequest: newBaseRequest(time.Now()),
		POPs: []reissuance.POP{{
			Encoded:          []byte("encoded"),
			EncodedProtected: "protected",
			Signature:        []byte("sig"),
		}},
	}
	valid, err := reissuance.EncodeRequest(&base)
	require.NoError(t, err)

	tests := map[string]struct {
		Input     reissuance.EncodedRequest
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
			Input:     valid[:len(valid)/2],
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

func TestEncodeBaseRequest(t *testing.T) {
	tests := map[string]struct {
		Modify    func(base *reissuance.BaseRequest)
		Assertion assert.ErrorAssertionFunc
	}{
		"Valid": {
			Modify:    func(*reissuance.BaseRequest) {},
			Assertion: assert.NoError,
		},
		"Invalid version": {
			Modify: func(base *reissuance.BaseRequest) {
				base.Version = scrypto.LatestVer
			},
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			base := newBaseRequest(time.Now())
			test.Modify(&base)
			packed, err := reissuance.EncodeBaseRequest(&base)
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

func TestEncodedBaseRequestDecode(t *testing.T) {
	base := newBaseRequest(time.Now())
	valid, err := reissuance.EncodeBaseRequest(&base)
	require.NoError(t, err)

	tests := map[string]struct {
		Input     reissuance.EncodedBaseRequest
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
		"Garbage cert": {
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
		Modify    func(base *reissuance.Protected)
		Assertion assert.ErrorAssertionFunc
	}{
		"No modification": {
			Modify:    func(*reissuance.Protected) {},
			Assertion: assert.NoError,
		},
		"Invalid KeyType": {
			Modify: func(base *reissuance.Protected) {
				base.KeyType = cert.KeyType(404)
			},
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			base := reissuance.Protected{
				Algorithm:  scrypto.Ed25519,
				KeyType:    cert.SigningKey,
				KeyVersion: 2,
			}
			test.Modify(&base)
			packed, err := reissuance.EncodeProtected(base)
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
	valid, err := reissuance.EncodeProtected(reissuance.Protected{
		Algorithm:  scrypto.Ed25519,
		KeyType:    cert.SigningKey,
		KeyVersion: 2,
	})
	require.NoError(t, err)
	tests := map[string]struct {
		Input     reissuance.EncodedProtected
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
			Input:     reissuance.EncodedProtected(scrypto.Base64.EncodeToString([]byte{0xfe})),
			Assertion: assert.Error,
		},
		"Garbage JSON": {
			Input:     valid[:len(valid)/2],
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

func newBaseRequest(now time.Time) reissuance.BaseRequest {
	now = now.Truncate(time.Second)
	return reissuance.BaseRequest{
		Base: cert.Base{
			Subject:       xtest.MustParseIA("1-ff00:0:111"),
			Version:       1,
			FormatVersion: 1,
			Description:   "This is a base request",
			Validity: &scrypto.Validity{
				NotBefore: util.UnixTime{Time: now},
				NotAfter:  util.UnixTime{Time: now.Add(8760 * time.Hour)},
			},
		},
		Issuer:      xtest.MustParseIA("1-ff00:0:110"),
		RequestTime: util.UnixTime{Time: now},
	}
}
