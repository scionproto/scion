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
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2/internal/decoded"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc/v2"
	"github.com/scionproto/scion/go/lib/xtest"
)

const help = "Make sure you have generated crypto material: " +
	"'./go/lib/infra/modules/trust/v2/testdata/gen_crypto_tar.sh'"

// tmpDir contains the generated crypto material.
var tmpDir string

type TRCDesc struct {
	ISD     addr.ISD
	Version scrypto.Version
}

func (desc TRCDesc) File() string {
	return fmt.Sprintf("ISD%d/trcs/ISD%d-V%d.trc", desc.ISD, desc.ISD, desc.Version)
}

var (
	trc1v1 = TRCDesc{ISD: 1, Version: 1}
	trc1v2 = TRCDesc{ISD: 1, Version: 2}
	trc1v3 = TRCDesc{ISD: 1, Version: 3}
	trc1v4 = TRCDesc{ISD: 1, Version: 4}

	// primary ASes
	ia110 = xtest.MustParseIA("1-ff00:0:110")
	ia120 = xtest.MustParseIA("1-ff00:0:120")
	ia130 = xtest.MustParseIA("1-ff00:0:130")
)

var (
	trc2v1 = TRCDesc{ISD: 2, Version: 1}

	// primary ASes
	ia210 = xtest.MustParseIA("2-ff00:0:210")

	// non-primary ASes
	ia122 = xtest.MustParseIA("1-ff00:0:122")
)

func TestMain(m *testing.M) {
	var cleanF func()
	tmpDir, cleanF = xtest.MustTempDir("", "test-trust")
	defer cleanF()
	cmd := exec.Command("tar", "-x", "-f", "testdata/crypto.tar", "-C", tmpDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(string(out))
		fmt.Println(err)
		fmt.Println(help)
		os.Exit(1)
	}
	log.Root().SetHandler(log.DiscardHandler())
	os.Exit(m.Run())
}

func loadTRC(t *testing.T, desc TRCDesc) decoded.TRC {
	t.Helper()
	file := filepath.Join(tmpDir, desc.File())
	raw, err := ioutil.ReadFile(file)
	require.NoError(t, err, help)
	signed, err := trc.ParseSigned(raw)
	require.NoError(t, err, help)
	trcObj, err := signed.EncodedTRC.Decode()
	require.NoError(t, err, help)
	return decoded.TRC{
		Raw:    raw,
		Signed: signed,
		TRC:    trcObj,
	}
}
