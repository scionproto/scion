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

package trcs

import (
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

func TestSignatureGen(t *testing.T) {
	if *update {
		create := func(v scrypto.Version) error {
			force := pkicmn.Force
			pkicmn.Force = true
			defer func() { pkicmn.Force = force }()
			g := signatureGen{Dirs: pkicmn.Dirs{Root: "./testdata", Out: "./testdata"}, Version: v}
			return g.Run(testASMap)
		}
		require.NoError(t, create(1))
		require.NoError(t, create(2))
		require.NoError(t, create(3))
	}
	tests := map[string]struct {
		Version scrypto.Version
		Signers []addr.IA
	}{
		"v1": {Version: 1, Signers: []addr.IA{ia110, ia120, ia130}},
		"v2": {Version: 2, Signers: []addr.IA{ia110, ia120}},
		"v3": {Version: 3, Signers: []addr.IA{ia120, ia130}},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tmpDir, cleanF := xtest.MustTempDir("", "test-trcs-sign")
			defer cleanF()

			// Setup file structure in temporary directory.
			isdDir := filepath.Join(tmpDir, "ISD1")
			require.NoError(t, os.MkdirAll(isdDir, 0777))
			err := exec.Command("cp", "-r",
				"./testdata/ISD1/ASff00_0_110",
				"./testdata/ISD1/ASff00_0_120",
				"./testdata/ISD1/ASff00_0_130",
				isdDir).Run()
			require.NoError(t, err)
			partsDir := PartsDir(tmpDir, 1, test.Version)
			require.NoError(t, os.MkdirAll(PartsDir(tmpDir, 1, test.Version), 0777))
			err = exec.Command("cp", ProtoFile("./testdata", 1, test.Version), partsDir).Run()
			require.NoError(t, err)
			if test.Version != 1 {
				err = exec.Command("cp", SignedFile("./testdata", 1, test.Version-1),
					Dir(tmpDir, 1)).Run()
				require.NoError(t, err)
			}

			// Run signatureGen generator and compare golden files.
			g := signatureGen{
				Dirs:    pkicmn.Dirs{Root: "./testdata", Out: tmpDir},
				Version: test.Version,
			}
			err = g.Run(testASMap)
			require.NoError(t, err)
			for _, signer := range test.Signers {
				golden, err := ioutil.ReadFile(PartsFile("./testdata", signer, test.Version))
				require.NoError(t, err)
				result, err := ioutil.ReadFile(PartsFile(tmpDir, signer, test.Version))
				require.NoError(t, err)
				assert.Equal(t, golden, result)
			}
		})
	}
}
