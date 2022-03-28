// Copyright 2022 ETH Zurich
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

package certs

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

func TestValidate(t *testing.T) {
	testCases := map[string]struct {
		Validation func(t *testing.T)
	}{
		"matching ca cert type": {
			Validation: func(*testing.T) {
				certs, err := cppki.ReadPEMCerts("./testdata/inspect/sample_certificate.pem")
				require.NoError(t, err)
				_, err = validateCert([]*x509.Certificate{certs[1]}, cppki.CA, true)
				require.NoError(t, err)
			},
		},
		"mismatching ca cert type": {
			Validation: func(*testing.T) {
				certs, err := cppki.ReadPEMCerts("./testdata/inspect/sample_certificate.pem")
				require.NoError(t, err)
				_, err = validateCert([]*x509.Certificate{certs[1]}, cppki.Root, true)
				require.Error(t, err)
			},
		},
		"matching AS cert type": {
			Validation: func(*testing.T) {
				certs, err := cppki.ReadPEMCerts("./testdata/inspect/sample_certificate.pem")
				require.NoError(t, err)
				_, err = validateCert([]*x509.Certificate{certs[0]}, cppki.AS, true)
				require.NoError(t, err)
			},
		},
		"mismatching AS cert type": {
			Validation: func(*testing.T) {
				certs, err := cppki.ReadPEMCerts("./testdata/inspect/sample_certificate.pem")
				require.NoError(t, err)
				_, err = validateCert([]*x509.Certificate{certs[0]}, cppki.Root, true)
				require.Error(t, err)
			},
		},
	}
	t.Parallel()
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			tc.Validation(t)
		})
	}
}
