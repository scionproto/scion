// Copyright 2026 Anapaya Systems
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

package e2e_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/testing/clab/e2e"
)

func TestLoadASes(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "as_list.yml"), []byte(`Core:
    - 1-ff00:0:110
Non-core:
    - 1-ff00:0:111
`), 0o644))
	// cs config in go-toml format (single-quoted address).
	writeCS := func(asFile, addr string) {
		d := filepath.Join(dir, "AS"+asFile)
		require.NoError(t, os.MkdirAll(d, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(d, "cs"+asFile+"-1.toml"),
			[]byte("[api]\naddr = '"+addr+"'\n"), 0o644))
	}
	writeCS("ff00_0_110", "10.0.1.1:30452")
	writeCS("ff00_0_111", "[fd00:f00d:cafe:2::1]:30452")

	ases, err := e2e.LoadASes(dir)
	require.NoError(t, err)
	require.Len(t, ases, 2)

	assert.Equal(t, "1-ff00:0:110", ases[0].IA)
	assert.True(t, ases[0].Core)
	assert.Equal(t, "http://10.0.1.1:30452/api/v1/segments", ases[0].SegmentsURL)

	assert.Equal(t, "1-ff00:0:111", ases[1].IA)
	assert.False(t, ases[1].Core)
	assert.Equal(t, "http://[fd00:f00d:cafe:2::1]:30452/api/v1/segments", ases[1].SegmentsURL)
}

func TestLoadASesMissingControlConfig(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "as_list.yml"),
		[]byte("Core:\n    - 1-ff00:0:110\nNon-core:\n"), 0o644))
	_, err := e2e.LoadASes(dir)
	assert.Error(t, err)
}
