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

package xtest

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
)

// LoadChain loads a certificate chain from a file. The file must be PEM encoded.
func LoadChain(t *testing.T, file string) []*x509.Certificate {
	t.Helper()
	chain, err := cppki.ReadPEMCerts(file)
	require.NoError(t, err)
	return chain
}

// LoadTRC loads a signed TRC from a file.
func LoadTRC(t *testing.T, file string) cppki.SignedTRC {
	t.Helper()
	raw, err := ioutil.ReadFile(file)
	require.NoError(t, err)
	if block, _ := pem.Decode(raw); block != nil {
		raw = block.Bytes
	}
	trc, err := cppki.DecodeSignedTRC(raw)
	require.NoError(t, err)
	return trc
}

// MustExtractIA extracts the IA from the cert's subject and verifies it is
// non-nil. It is the callers responsibility to make sure that this is a cert
// that always contains an IA.
func MustExtractIA(t *testing.T, cert *x509.Certificate) addr.IA {
	ia, err := cppki.ExtractIA(cert.Subject)
	require.NoError(t, err)
	require.NotNil(t, ia)
	return ia
}
