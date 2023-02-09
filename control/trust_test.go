// Copyright 2021 Anapaya Systems
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

package control_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	cs "github.com/scionproto/scion/control"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/private/storage/trust/sqlite"
	"github.com/scionproto/scion/scion-pki/testcrypto"
)

func TestNewSigner(t *testing.T) {
	dir := testCrypto(t)

	db, err := sqlite.New("file::memory:")
	require.NoError(t, err)

	signer := cs.NewSigner(
		xtest.MustParseIA("1-ff00:0:110"),
		db,
		filepath.Join(dir, "/ISD1/ASff00_0_110"),
	)

	_, err = signer.Sign(context.Background(), []byte("message"))
	require.NoError(t, err)
}

func testCrypto(t *testing.T) string {
	dir := t.TempDir()

	cmd := testcrypto.Cmd(command.StringPather(""))
	cmd.SetArgs([]string{
		"-t", "testdata/test.topo",
		"-o", dir,
		"--isd-dir",
	})
	err := cmd.Execute()
	require.NoError(t, err)

	raw, err := os.ReadFile(filepath.Join(dir, "trcs/ISD1-B1-S1.trc"))
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(dir, "ISD1/ASff00_0_110/certs/ISD1-B1-S1.trc"), raw, 0666)
	require.NoError(t, err)
	return dir
}
