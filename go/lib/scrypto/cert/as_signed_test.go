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

func TestEncodeAS(t *testing.T) {
	tests := map[string]struct {
		Modify    func(base *cert.AS)
		Assertion assert.ErrorAssertionFunc
	}{
		"No modification": {
			Modify:    func(*cert.AS) {},
			Assertion: assert.NoError,
		},
		"Invalid Version": {
			Modify: func(base *cert.AS) {
				base.Version = scrypto.LatestVer
			},
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			base := newASCert(time.Now())
			test.Modify(&base)
			packed, err := cert.EncodeAS(&base)
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

func TestEncodedASDecode(t *testing.T) {
	base := newASCert(time.Now())
	valid, err := cert.EncodeAS(&base)
	require.NoError(t, err)

	tests := map[string]struct {
		Input     cert.EncodedAS
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
			Input:     cert.EncodedAS(encode("some_garbage")),
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

func TestEncodeProtectedAS(t *testing.T) {
	tests := map[string]struct {
		Modify    func(base *cert.ProtectedAS)
		Assertion assert.ErrorAssertionFunc
	}{
		"No modification": {
			Modify:    func(*cert.ProtectedAS) {},
			Assertion: assert.NoError,
		},
		"Invalid CertificateVersion": {
			Modify: func(base *cert.ProtectedAS) {
				base.CertificateVersion = 0
			},
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			base := newBaseProtectedAS()
			test.Modify(&base)
			packed, err := cert.EncodeProtectedAS(base)
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

func TestEncodedProtectedASDecode(t *testing.T) {
	valid, err := cert.EncodeProtectedAS(newBaseProtectedAS())
	require.NoError(t, err)

	tests := map[string]struct {
		Input     cert.EncodedProtectedAS
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
			Input:     cert.EncodedProtectedAS(scrypto.Base64.EncodeToString([]byte{0xfe})),
			Assertion: assert.Error,
		},
		"Garbage JSON": {
			Input:     cert.EncodedProtectedAS(encode("some_garbage")),
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

func newBaseProtectedAS() cert.ProtectedAS {
	return cert.ProtectedAS{
		Algorithm:          scrypto.Ed25519,
		CertificateVersion: 2,
		IA:                 ia110,
	}
}
