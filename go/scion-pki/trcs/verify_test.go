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

package trcs

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/xtest"
)

func TestVerify(t *testing.T) {
	// prepare certificate bundle
	dir, clean := xtest.MustTempDir("", "scion-pki-trcs-verify")
	defer clean()

	testCases := map[string]struct {
		Files        []string
		Anchor       string
		Prepare      func(t *testing.T)
		ErrAssertion require.ErrorAssertionFunc
	}{
		"base-trc-anchor": {
			Files:        []string{"./testdata/admin/ISD1-B1-S1.trc"},
			Anchor:       "./testdata/admin/ISD1-B1-S1.trc",
			Prepare:      func(*testing.T) {},
			ErrAssertion: require.NoError,
		},
		"base-bundle-anchor": {
			Files:  []string{"./testdata/admin/ISD1-B1-S1.trc"},
			Anchor: filepath.Join(dir, "base.pem"),
			Prepare: func(*testing.T) {
				out := filepath.Join(dir, "base.pem")
				require.NoError(t, runExtractCertificates("./testdata/admin/ISD1-B1-S1.trc", out))
			},
			ErrAssertion: require.NoError,
		},
		"base-bundle-missing": {
			Files:  []string{"./testdata/admin/ISD1-B1-S1.trc"},
			Anchor: filepath.Join(dir, "base-missing.pem"),
			Prepare: func(*testing.T) {
				signed, err := DecodeFromFile("./testdata/admin/ISD1-B1-S1.trc")
				require.NoError(t, err)
				out := filepath.Join(dir, "base-missing.pem")
				require.NoError(t, writeBundle(out, signed.TRC.Certificates[:1]))
			},
			ErrAssertion: require.Error,
		},
		"base-invalid-signature": {
			Files:  []string{filepath.Join(dir, "base-invalid-signature.der")},
			Anchor: "./testdata/admin/ISD1-B1-S1.trc",
			Prepare: func(*testing.T) {
				signed, err := DecodeFromFile("./testdata/admin/ISD1-B1-S1.trc")
				require.NoError(t, err)
				out := filepath.Join(dir, "base-invalid-signature.der")
				// Mangle the signature.
				sig := signed.SignerInfos[0].Signature
				sig[len(sig)-1] ^= 0xFF
				raw, err := signed.Encode()
				require.NoError(t, err)
				require.NoError(t, ioutil.WriteFile(out, raw, 0666))
			},
			ErrAssertion: require.Error,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			tc.Prepare(t)
			err := RunVerify(tc.Files, tc.Anchor)
			tc.ErrAssertion(t, err)
		})
	}
}
