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
	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/decoded"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/xtest"
)

const help = "Make sure you have generated crypto material: " +
	"'./go/lib/infra/modules/trust/testdata/gen_crypto_tar.sh'"

// tmpDir contains the generated crypto material.
var tmpDir string

type TRCDesc struct {
	ISD     addr.ISD
	Version scrypto.Version
}

func (desc TRCDesc) File() string {
	return fmt.Sprintf("ISD%d/trcs/ISD%d-V%d.trc", desc.ISD, desc.ISD, desc.Version)
}

type ChainDesc struct {
	IA      addr.IA
	Version scrypto.Version
}

func (desc ChainDesc) File() string {
	return fmt.Sprintf("ISD%d/AS%s/certs/%s-V%d.crt", desc.IA.I, desc.IA.A.FileFmt(),
		desc.IA.FileFmt(true), desc.Version)
}

// Primary ASes ISD 1
var (
	ia110 = xtest.MustParseIA("1-ff00:0:110")
	ia120 = xtest.MustParseIA("1-ff00:0:120")
	ia130 = xtest.MustParseIA("1-ff00:0:130")
)

// Non-primary ASes ISD 1
var (
	ia122 = xtest.MustParseIA("1-ff00:0:122")
)

// Primary ASes ISD 2
var (
	ia210 = xtest.MustParseIA("2-ff00:0:210")
)

// TRCs
var (
	trc1v1 = TRCDesc{ISD: 1, Version: 1}
	trc1v2 = TRCDesc{ISD: 1, Version: 2}
	trc1v3 = TRCDesc{ISD: 1, Version: 3}
	trc1v4 = TRCDesc{ISD: 1, Version: 4}

	trc2v1 = TRCDesc{ISD: 2, Version: 1}
)

// Chains
var (
	chain110v1 = ChainDesc{IA: ia110, Version: 1}
	chain120v1 = ChainDesc{IA: ia120, Version: 1}
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

func loadChain(t *testing.T, desc ChainDesc) decoded.Chain {
	t.Helper()
	file := filepath.Join(tmpDir, desc.File())
	var err error
	var chain decoded.Chain
	chain.Raw, err = ioutil.ReadFile(file)
	require.NoError(t, err, help)
	chain.Chain, err = cert.ParseChain(chain.Raw)
	require.NoError(t, err, help)
	chain.Issuer, err = chain.Chain.Issuer.Encoded.Decode()
	require.NoError(t, err, help)
	chain.AS, err = chain.Chain.AS.Encoded.Decode()
	require.NoError(t, err, help)
	return chain
}

func loadPrivateKey(t *testing.T, id keyconf.ID) keyconf.Key {
	t.Helper()
	file := filepath.Join(tmpDir, fmt.Sprintf("ISD%d/AS%s/keys", id.IA.I, id.IA.A.FileFmt()),
		keyconf.PrivateKeyFile(id.Usage, id.Version))
	key, err := keyconf.LoadKeyFromFile(file, keyconf.PrivateKey, id)
	require.NoError(t, err, help)
	return key
}
