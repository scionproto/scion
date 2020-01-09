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

package cert_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
)

func TestEncodeIssuer(t *testing.T) {
	tests := map[string]struct {
		Modify    func(base *cert.Issuer)
		Assertion assert.ErrorAssertionFunc
	}{
		"No modification": {
			Modify:    func(*cert.Issuer) {},
			Assertion: assert.NoError,
		},
		"Invalid Version": {
			Modify: func(base *cert.Issuer) {
				base.Version = scrypto.LatestVer
			},
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			base := newIssuerCert(time.Now())
			test.Modify(&base)
			packed, err := cert.EncodeIssuer(&base)
			test.Assertion(t, err)
			if err != nil {
				return
			}
			unpacked, err := packed.Decode()
			require.NoError(t, err)
			assert.Equal(t, base, *unpacked)
		})
	}
}

func TestEncodedIssuerDecode(t *testing.T) {
	base := newIssuerCert(time.Now())
	valid, err := cert.EncodeIssuer(&base)
	require.NoError(t, err)

	tests := map[string]struct {
		Input     cert.EncodedIssuer
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
			Input:     cert.EncodedIssuer(encode("some_garbage")),
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

func TestEncodeProtectedIssuer(t *testing.T) {
	tests := map[string]struct {
		Modify    func(base *cert.ProtectedIssuer)
		Assertion assert.ErrorAssertionFunc
	}{
		"No modification": {
			Modify:    func(*cert.ProtectedIssuer) {},
			Assertion: assert.NoError,
		},
		"Invalid TRCVersion": {
			Modify: func(base *cert.ProtectedIssuer) {
				base.TRCVersion = 0
			},
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			base := newBaseProtectedIssuer()
			test.Modify(&base)
			packed, err := cert.EncodeProtectedIssuer(base)
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

func TestEncodedProtectedIssuerDecode(t *testing.T) {
	valid, err := cert.EncodeProtectedIssuer(newBaseProtectedIssuer())
	require.NoError(t, err)

	tests := map[string]struct {
		Input     cert.EncodedProtectedIssuer
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
			Input:     cert.EncodedProtectedIssuer(scrypto.Base64.EncodeToString([]byte{0xfe})),
			Assertion: assert.Error,
		},
		"Garbage JSON": {
			Input:     cert.EncodedProtectedIssuer(encode("some_garbage")),
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

func newBaseProtectedIssuer() cert.ProtectedIssuer {
	return cert.ProtectedIssuer{
		Algorithm:  scrypto.Ed25519,
		TRCVersion: 4,
	}
}
