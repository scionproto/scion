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

	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

var (
	ia110    = xtest.MustParseIA("1-ff00:0:110")
	issASMap = pkicmn.ASMap{1: {ia110}}
)

func TestIssuerGenRun(t *testing.T) {
	tmpDir, cleanF := xtest.MustTempDir("", "test-certs-issuer")
	defer cleanF()

	isdDir := filepath.Join(tmpDir, "ISD1")
	require.NoError(t, os.MkdirAll(isdDir, 0777))
	err := exec.Command("cp", "-r",
		"./testdata/ISD1/trcs",
		"./testdata/ISD1/trc-v1.toml",
		isdDir).Run()
	require.NoError(t, err)

	asDir := filepath.Join(isdDir, "ASff00_0_110")
	require.NoError(t, os.MkdirAll(asDir, 0777))
	err = exec.Command("cp", "-r",
		"./testdata/ISD1/ASff00_0_110/keys",
		"./testdata/ISD1/ASff00_0_110/issuer-v1.toml",
		asDir).Run()
	require.NoError(t, err)

	g := issGen{
		Dirs: pkicmn.Dirs{Root: "./testdata", Out: tmpDir},
	}
	err = g.Run(issASMap)
	require.NoError(t, err)

	golden, err := ioutil.ReadFile(IssuerFile("./testdata", ia110, 1))
	require.NoError(t, err)
	result, err := ioutil.ReadFile(IssuerFile(tmpDir, ia110, 1))
	require.NoError(t, err)
	assert.Equal(t, golden, result)
}

// TestUpdateGoldenIssuer provides an easy way to update the golden file after
// the format has changed.
func TestUpdateGoldenIssuer(t *testing.T) {
	if *update {
		force := pkicmn.Force
		pkicmn.Force = true
		defer func() { pkicmn.Force = force }()
		g := issGen{Dirs: pkicmn.Dirs{Root: "./testdata", Out: "./testdata"}, Version: 1}
		err := g.Run(issASMap)
		require.NoError(t, err)
	}
}
