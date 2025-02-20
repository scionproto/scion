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

package renewal_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/scion-pki/testcrypto"
)

func genCrypto(t *testing.T) string {
	dir := t.TempDir()

	var buf bytes.Buffer
	cmd := testcrypto.Cmd(command.StringPather(""))
	cmd.SetArgs([]string{
		"-t", "testdata/golden.topo",
		"-o", dir,
	})
	cmd.SetOutput(&buf)
	err := cmd.Execute()
	require.NoError(t, err)

	buf.Reset()
	cmd.SetArgs([]string{"update", "-o", dir})
	err = cmd.Execute()
	require.NoError(t, err, buf.String())

	// Generate 1-ff00:0:110
	{
		tmpl := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:         "1-ff00:0:110 AS Certificate",
				Country:            []string{"CH"},
				Province:           []string{"Bern"},
				Locality:           []string{"Bern"},
				Organization:       []string{"1-ff00:0:110"},
				OrganizationalUnit: []string{"1-ff00:0:110 InfoSec Squad"},
				ExtraNames: []pkix.AttributeTypeAndValue{
					{
						Type:  cppki.OIDNameIA,
						Value: "1-ff00:0:110",
					},
				},
			},
		}

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		writeKey(t, filepath.Join(dir, "ASff00_0_110/crypto/as/cp-as1.key"), key)

		csr, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
		require.NoError(t, err)
		writeCSR(t, filepath.Join(dir, "ASff00_0_110/crypto/as/cp-as1.csr"), csr)
	}

	// Generate 1-ff00:0:111
	{
		tmpl := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:         "1-ff00:0:111 AS Certificate",
				Country:            []string{"CH"},
				Province:           []string{"Geneva"},
				Locality:           []string{"Geneva"},
				Organization:       []string{"1-ff00:0:111"},
				OrganizationalUnit: []string{"1-ff00:0:111 InfoSec Squad"},
				ExtraNames: []pkix.AttributeTypeAndValue{
					{
						Type:  cppki.OIDNameIA,
						Value: "1-ff00:0:111",
					},
				},
			},
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		writeKey(t, filepath.Join(dir, "ASff00_0_111/crypto/as/cp-as1.key"), key)

		csr, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
		require.NoError(t, err)
		writeCSR(t, filepath.Join(dir, "ASff00_0_111/crypto/as/cp-as1.csr"), csr)
	}
	return dir
}

func writeKey(t *testing.T, file string, key any) {
	t.Helper()
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: raw,
		},
	)
	require.NoError(t, os.WriteFile(file, keyPEM, 0644))
}

func writeCSR(t *testing.T, file string, csr []byte) {
	t.Helper()
	csrPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csr,
		},
	)
	require.NoError(t, os.WriteFile(file, csrPEM, 0644))
}

func loadKey(t *testing.T, file string) crypto.Signer {
	t.Helper()
	raw, err := os.ReadFile(file)
	require.NoError(t, err)
	block, _ := pem.Decode(raw)
	require.Equal(t, "PRIVATE KEY", block.Type, "Wrong block type %s", block.Type)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	return key.(crypto.Signer)
}
