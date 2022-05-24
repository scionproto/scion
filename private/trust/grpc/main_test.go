// Copyright 2022 Anapaya Systems
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

package grpc_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/scion-pki/testcrypto"
)

func genCrypto(t testing.TB) string {
	dir := t.TempDir()

	var buf bytes.Buffer
	cmd := testcrypto.Cmd(command.StringPather(""))
	cmd.SetArgs([]string{
		"-t", "testdata/golden.topo",
		"-o", dir,
		"--isd-dir",
		"--as-validity", "1y",
	})
	cmd.SetOutput(&buf)
	err := cmd.Execute()
	require.NoError(t, err, buf.String())

	buf.Reset()
	cmd.SetArgs([]string{"update", "-o", dir})
	err = cmd.Execute()
	require.NoError(t, err, buf.String())

	return dir
}
