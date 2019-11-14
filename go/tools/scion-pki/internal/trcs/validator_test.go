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
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

func TestValidatorRun(t *testing.T) {
	tmpDir, cleanF := xtest.MustTempDir("", "test-trcs-validator")
	defer cleanF()
	isdDir := filepath.Join(tmpDir, "ISD1")
	err := exec.Command("cp", "-r", "./testdata/ISD1", isdDir).Run()
	require.NoError(t, err)

	dec, err := loadTRC(SignedFile("./testdata", 1, 3))
	require.NoError(t, err)
	dec.Signed.Signatures[0].Signature[0] ^= 0xFF
	raw, err := trc.EncodeSigned(dec.Signed)
	require.NoError(t, err)
	forged := filepath.Join(Dir(tmpDir, 1), "forged.trc")
	err = ioutil.WriteFile(forged, raw, 0644)
	require.NoError(t, err)

	v1, v2, v3 := SignedFile(tmpDir, 1, 1), SignedFile(tmpDir, 1, 2), SignedFile(tmpDir, 1, 3)
	tests := map[string]struct {
		Files     []string
		Assertion assert.ErrorAssertionFunc
	}{
		"v1": {
			Files:     []string{v1},
			Assertion: assert.NoError,
		},
		"v2": {
			Files:     []string{v2},
			Assertion: assert.NoError,
		},
		"all": {
			Files:     []string{v1, v2, v3},
			Assertion: assert.NoError,
		},
		"forged": {
			Files:     []string{"./some/fake/path", forged},
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			v := validator{Dirs: pkicmn.Dirs{Root: "./testdata", Out: tmpDir}}
			err := v.Run(test.Files)
			test.Assertion(t, err)
		})
	}
}
