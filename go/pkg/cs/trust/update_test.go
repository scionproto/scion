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

package trust_test

import (
	"flag"
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/command"
	"github.com/scionproto/scion/go/scion-pki/testcrypto"
)

// update is a cmd line flag that enables golden file updates. To update the
// golden files simply run 'go test -update ./...'.
var update = flag.Bool("update", false, "set to true to regenerate golden files")

func TestUpdate(t *testing.T) {
	if !(*update) {
		t.Skip("Specify -update to update certs")
		return
	}
	dir, cleanF := xtest.MustTempDir("", "tmp")
	defer cleanF()

	cmd := testcrypto.Cmd(command.StringPather(""))
	cmd.SetArgs([]string{
		"-t", "testdata/golden.topo",
		"-l", "../../../../scripts/cryptoplayground/crypto_lib.sh",
		"-o", dir,
		"--isd-dir",
		"--as-validity", "1y",
	})
	err := cmd.Execute()
	require.NoError(t, err)

	err = ioutil.WriteFile(filepath.Join(dir, "dummy.pem"), []byte{}, 0666)
	require.NoError(t, err)

	err = ioutil.WriteFile(filepath.Join(dir, "dummy.crt"), []byte{}, 0666)
	require.NoError(t, err)

	out, err := exec.Command("rm", "-rf", "testdata/common").CombinedOutput()
	require.NoError(t, err, string(out))

	out, err = exec.Command("mv", dir, "testdata/common").CombinedOutput()
	require.NoError(t, err, string(out))
}
