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

package certs

import (
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

func TestVerifierRun(t *testing.T) {
	tmpDir, cleanF := xtest.MustTempDir("", "test-certs-verifier")
	defer cleanF()
	isdDir := filepath.Join(tmpDir, "ISD1")
	err := exec.Command("cp", "-r", "./testdata/ISD1", isdDir).Run()
	require.NoError(t, err)

	forged := filepath.Join(tmpDir, "forged")
	err = os.MkdirAll(Dir(forged, ia110), 0777)
	require.NoError(t, err)

	raw, err := ioutil.ReadFile(IssuerFile("./testdata", ia110, 1))
	require.NoError(t, err)
	iss, err := cert.ParseSignedIssuer(raw)
	require.NoError(t, err)
	iss.Signature[0] ^= 0xFF
	raw, err = cert.EncodeSignedIssuer(iss)
	require.NoError(t, err)
	forgedIss := IssuerFile(forged, ia110, 1)
	err = ioutil.WriteFile(forgedIss, raw, 0644)
	require.NoError(t, err)

	raw, err = ioutil.ReadFile(ASFile("./testdata", ia111, 1))
	require.NoError(t, err)
	chain, err := cert.ParseChain(raw)
	require.NoError(t, err)
	chain.AS.Signature[0] ^= 0xFF
	raw, err = chain.MarshalJSON()
	require.NoError(t, err)
	forgedAS := ASFile(forged, ia110, 1)
	err = ioutil.WriteFile(forgedAS, raw, 0644)
	require.NoError(t, err)

	tests := map[string]struct {
		Files     []string
		Assertion assert.ErrorAssertionFunc
	}{
		"issuer": {
			Files:     []string{IssuerFile(tmpDir, ia110, 1)},
			Assertion: assert.NoError,
		},
		"chain": {
			Files:     []string{ASFile(tmpDir, ia111, 1)},
			Assertion: assert.NoError,
		},
		"all": {
			Files:     []string{IssuerFile(tmpDir, ia110, 1), ASFile(tmpDir, ia111, 1)},
			Assertion: assert.NoError,
		},
		"forged": {
			Files: []string{IssuerFile("fake", ia110, 1), ASFile("fake", ia111, 1),
				forgedAS, forgedIss},
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			v := verifier{Dirs: pkicmn.Dirs{Root: "./testdata", Out: tmpDir}}
			err := v.Run(test.Files)
			test.Assertion(t, err)
		})
	}
}
