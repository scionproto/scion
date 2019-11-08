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

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

func TestCombiner(t *testing.T) {
	if *update {
		create := func(v scrypto.Version) error {
			force := pkicmn.Force
			pkicmn.Force = true
			defer func() { pkicmn.Force = force }()
			g := combiner{Dirs: pkicmn.Dirs{Root: "./testdata", Out: "./testdata"}, Version: v}
			return g.Run(testASMap)
		}
		require.NoError(t, create(1))
		require.NoError(t, create(2))
		require.NoError(t, create(3))
	}
	tests := map[string]struct {
		Version scrypto.Version
	}{
		"v1": {Version: 1},
		"v2": {Version: 2},
		"v3": {Version: 3},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tmpDir, cleanF := xtest.MustTempDir("", "test-trcs-combine")
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
			trcsDir := filepath.Join(isdDir, "trcs")
			require.NoError(t, os.MkdirAll(trcsDir, 0777))
			err = exec.Command("cp", "-r",
				"./testdata/ISD1/trcs/ISD1-V1.parts",
				"./testdata/ISD1/trcs/ISD1-V2.parts",
				"./testdata/ISD1/trcs/ISD1-V3.parts",
				trcsDir).Run()
			require.NoError(t, err)
			if test.Version > 1 {
				err = exec.Command("cp", SignedFile("./testdata", 1, test.Version-1),
					SignedFile(tmpDir, 1, test.Version-1)).Run()
				require.NoError(t, err)
			}

			// Run combiner and compare golden files.
			g := combiner{
				Dirs:    pkicmn.Dirs{Root: "./testdata", Out: tmpDir},
				Version: test.Version,
			}
			err = g.Run(testASMap)
			require.NoError(t, err)

			golden, err := ioutil.ReadFile(SignedFile("./testdata", 1, test.Version))
			require.NoError(t, err)
			result, err := ioutil.ReadFile(SignedFile(tmpDir, 1, test.Version))
			require.NoError(t, err)
			assert.Equal(t, golden, result)
		})
	}
}
