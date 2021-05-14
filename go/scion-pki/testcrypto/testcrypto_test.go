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

package testcrypto_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/scion-pki/testcrypto"
	"github.com/scionproto/scion/go/scion-pki/trcs"
)

func TestCmd(t *testing.T) {
	if _, bazel := os.LookupEnv("TEST_UNDECLARED_OUTPUTS_DIR"); bazel {
		t.Skip("Test can't run through bazel because of symlinks and docker not playing nice")
	}
	outDir, cleanF := xtest.MustTempDir("", "testcrypto")
	topo := "./testdata/test.topo"
	cryptoLib := "../../../scripts/cryptoplayground/crypto_lib.sh"
	err := testcrypto.Testcrypto(topo, cryptoLib, outDir, false, false, asValidity)
	require.NoError(t, err)

	allASes := []addr.IA{
		xtest.MustParseIA("1-ff00:0:110"),
		xtest.MustParseIA("1-ff00:0:120"),
		xtest.MustParseIA("1-ff00:0:130"),
		xtest.MustParseIA("1-ff00:0:111"),
		xtest.MustParseIA("1-ff00:0:131"),
		xtest.MustParseIA("2-ff00:0:210"),
		xtest.MustParseIA("2-ff00:0:220"),
	}
	for _, as := range allASes {
		checkAS(t, outDir, as)
	}
	issuers := []addr.IA{
		xtest.MustParseIA("1-ff00:0:110"),
		xtest.MustParseIA("1-ff00:0:111"),
		xtest.MustParseIA("2-ff00:0:210"),
	}
	for _, issuer := range issuers {
		checkIssuer(t, outDir, issuer)
	}
	voters := []addr.IA{
		xtest.MustParseIA("1-ff00:0:120"),
		xtest.MustParseIA("1-ff00:0:111"),
		xtest.MustParseIA("1-ff00:0:131"),
		xtest.MustParseIA("2-ff00:0:210"),
		xtest.MustParseIA("2-ff00:0:220"),
	}
	for _, voter := range voters {
		checkVoter(t, outDir, voter)
	}
	checkISD(t, outDir, 1)
	checkISD(t, outDir, 2)
	cleanF()
}

func checkISD(t *testing.T, outDir string, isd addr.ISD) {
	isdDir := filepath.Join(outDir, fmt.Sprintf("ISD%d", isd))
	trcFile := filepath.Join(isdDir, "trcs", fmt.Sprintf("ISD%d-B1-S1.trc", isd))
	assert.NoError(t, trcs.RunVerify([]string{trcFile}, trcFile))
}

func checkAS(t *testing.T, outDir string, ia addr.IA) {
	d := testcrypto.CryptoASDir(ia, testcrypto.NewOut(outDir))
	checkFileExists(t, filepath.Join(d, "cp-as.key"))
	validateChain(t, filepath.Join(d, fmt.Sprintf("%s.pem", ia.FileFmt(true))))
}

func checkIssuer(t *testing.T, outDir string, ia addr.IA) {
	d := testcrypto.CryptoCADir(ia, testcrypto.NewOut(outDir))
	checkFileExists(t, filepath.Join(d, "cp-ca.key"))
	checkFileExists(t, filepath.Join(d, "cp-root.key"))
	certName := fmt.Sprintf("%s.root.crt", ia.FileFmt(true))
	validateCert(t, filepath.Join(d, certName), cppki.Root)
	certName = fmt.Sprintf("%s.ca.crt", ia.FileFmt(true))
	validateCert(t, filepath.Join(d, certName), cppki.CA)
}

func checkVoter(t *testing.T, outDir string, ia addr.IA) {
	d := testcrypto.CryptoVotingDir(ia, testcrypto.NewOut(outDir))
	checkFileExists(t, filepath.Join(d, "sensitive-voting.key"))
	checkFileExists(t, filepath.Join(d, "regular-voting.key"))
	sensitiveName := fmt.Sprintf("%s.sensitive.crt", ia.FileFmt(true))
	validateCert(t, filepath.Join(d, sensitiveName), cppki.Sensitive)
	regularName := fmt.Sprintf("%s.regular.crt", ia.FileFmt(true))
	validateCert(t, filepath.Join(d, regularName), cppki.Regular)
}

func checkFileExists(t *testing.T, file string) {
	t.Helper()
	_, err := os.Stat(file)
	require.NoError(t, err, "File %s must exist", file)
}

func validateChain(t *testing.T, file string) {
	t.Helper()
	certs, err := cppki.ReadPEMCerts(file)
	require.NoError(t, err, "Cert %s should exist", file)
	require.Len(t, certs, 2, "Cert %s should contain 2 certs", file)
	act, err := cppki.ValidateCert(certs[0])
	assert.NoError(t, err, "Cert[0] of %s should be valid", file)
	assert.Equal(t, cppki.AS, act, "Cert[0] of %s should be of AS type", file)
	act, err = cppki.ValidateCert(certs[1])
	assert.NoError(t, err, "Cert[1] of %s should be valid", file)
	assert.Equal(t, cppki.CA, act, "Cert[1] of %s should be of CA type", file)
}

func validateCert(t *testing.T, file string, ct cppki.CertType) {
	t.Helper()

	certs, err := cppki.ReadPEMCerts(file)
	require.NoError(t, err, "Cert %s should exist", file)
	require.Len(t, certs, 1, "Cert %s should contain 1 certs", file)
	act, err := cppki.ValidateCert(certs[0])
	assert.NoError(t, err, "Cert %s should be valid", file)
	assert.Equal(t, ct, act, "Cert %s should be of %s type", file, ct)
}
