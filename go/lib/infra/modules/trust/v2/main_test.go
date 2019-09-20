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

package trust_test

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/xtest"
)

// tmpDir contains the generated crypto material.
var tmpDir string

func TestMain(m *testing.M) {
	var cleanF func()
	tmpDir, cleanF = xtest.MustTempDir("", "test-trust")
	defer cleanF()
	cmd := exec.Command("tar", "-x", "-f", "testdata/crypto.tar", "-C", tmpDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(string(out))
		fmt.Println(err)
		os.Exit(1)
	}
	log.Root().SetHandler(log.DiscardHandler())
	os.Exit(m.Run())
}
