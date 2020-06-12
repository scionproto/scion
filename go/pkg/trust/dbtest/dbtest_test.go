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

package dbtest_test

import (
	"flag"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/xtest"
)

var update = flag.Bool("update", false, "Update all the testdata crypto")

func TestUpdateCrypto(t *testing.T) {
	if !(*update) {
		t.Skip("Only runs if -update is specified")
	}

	dir, cleanF := xtest.MustTempDir("", "trustdbtest")
	defer cleanF()

	testdata, err := filepath.Abs("./testdata")
	require.NoError(t, err)
	root, err := filepath.Abs("../../../../")
	require.NoError(t, err)
	playground, err := filepath.Abs(filepath.Join(root, "scripts", "cryptoplayground"))
	require.NoError(t, err)
	cmd := exec.Command("sh", "-c", filepath.Join("testdata", "update_certs.sh"))
	cmd.Env = []string{
		"SCION_ROOT=" + root,
		"PLAYGROUND=" + playground,
		"SAFEDIR=" + dir,
		"TESTDATA=" + testdata,
		"STARTDATE=20200624120000Z",
		"ENDDATE=20210624120000Z",
	}
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}
