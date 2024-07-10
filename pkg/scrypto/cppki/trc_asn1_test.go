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

package cppki_test

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// TestDecodeEncodedPayload checks that the decoding the encoded payload
// results in the same payload. This is only a basic sanity check.
func TestDecodeEncodedTRC(t *testing.T) {
	regularCrt := loadCert(t, "./testdata/regular-voting.crt")
	trc := cppki.TRC{
		Version: 1,
		ID: cppki.TRCID{
			ISD:    1,
			Base:   3,
			Serial: 4,
		},
		Validity: cppki.Validity{
			NotBefore: regularCrt.NotBefore.Add(time.Hour),
			NotAfter:  regularCrt.NotAfter.Add(-time.Hour),
		},
		GracePeriod:  10 * time.Hour,
		NoTrustReset: false,
		Votes:        []int{1, 2, 4},
		Quorum:       1,
		CoreASes: []addr.AS{
			addr.MustParseAS("ff00:0:110"),
			addr.MustParseAS("ff00:0:120"),
		},
		AuthoritativeASes: []addr.AS{addr.MustParseAS("ff00:0:110")},
		Description:       "This is a testing ISD",
		Certificates: []*x509.Certificate{
			loadCert(t, "./testdata/sensitive-voting.crt"),
			regularCrt,
		},
	}
	raw, err := trc.Encode()
	require.NoError(t, err)
	dec, err := cppki.DecodeTRC(raw)
	require.NoError(t, err)

	dec.Raw = nil
	assert.Equal(t, trc, dec)
}

func loadCert(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(name)
	require.NoError(t, err)
	block, _ := pem.Decode(raw)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}
