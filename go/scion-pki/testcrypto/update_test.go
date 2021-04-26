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

package testcrypto_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/scion-pki/testcrypto"
	"github.com/scionproto/scion/go/scion-pki/trcs"
)

func TestUpdateExtend(t *testing.T) {
	if _, bazel := os.LookupEnv("TEST_UNDECLARED_OUTPUTS_DIR"); bazel {
		t.Skip("Test can't run through bazel because of symlinks and docker not playing nice")
	}
	outDir, cleanF := xtest.MustTempDir("", "testcrypto")
	defer cleanF()
	topo := "./testdata/test.topo"
	cryptoLib := "../../../scripts/cryptoplayground/crypto_lib.sh"
	err := testcrypto.Testcrypto(topo, cryptoLib, outDir, false, false)
	require.NoError(t, err)

	cmd := testcrypto.NewUpdate()
	cmd.SetArgs([]string{"-o", outDir, "--scenario", "extend"})

	err = cmd.Execute()
	require.NoError(t, err)

	allASes := []addr.IA{
		xtest.MustParseIA("1-ff00:0:110"),
		xtest.MustParseIA("1-ff00:0:120"),
		xtest.MustParseIA("1-ff00:0:130"),
		xtest.MustParseIA("1-ff00:0:111"),
		xtest.MustParseIA("1-ff00:0:131"),
		xtest.MustParseIA("2-ff00:0:210"),
		xtest.MustParseIA("2-ff00:0:220"),
	}

	loadTRC := func(t *testing.T, isd addr.ISD, s uint64) cppki.SignedTRC {
		trc, err := trcs.DecodeFromFile(fmt.Sprintf("%s/trcs/ISD%d-B1-S%d.trc", outDir, isd, s))
		require.NoError(t, err)
		return trc
	}
	trcs := map[addr.ISD]cppki.SignedTRC{
		1: loadTRC(t, 1, 2),
		2: loadTRC(t, 2, 2),
	}

	for _, ia := range allASes {
		t.Run(ia.String(), func(t *testing.T) {
			file := filepath.Join(testcrypto.CryptoASDir(ia, testcrypto.NewOut(outDir)),
				ia.FileFmt(true)+".pem")
			chain, err := cppki.ReadPEMCerts(file)
			require.NoError(t, err)
			trc := trcs[ia.I].TRC
			err = cppki.VerifyChain(chain, cppki.VerifyOptions{TRC: []*cppki.TRC{&trc}})
			require.NoError(t, err)
		})
	}
	for isd, trc := range trcs {
		t.Run(strconv.Itoa(int(isd)), func(t *testing.T) {
			old := loadTRC(t, isd, 1)
			err := trc.Verify(&old.TRC)
			require.NoError(t, err)

			for i, cert := range trc.TRC.Certificates {
				t.Run(fmt.Sprintf("cert: %d", i), func(t *testing.T) {
					updateT, err := cppki.ValidateCert(cert)
					require.NoError(t, err)
					oldT, err := cppki.ValidateCert(old.TRC.Certificates[i])
					require.NoError(t, err)

					require.Equal(t, oldT, updateT)
					if updateT == cppki.Regular || updateT == cppki.Root {
						require.NotEqual(t, old.TRC.Certificates[i], cert)
					} else {
						require.Equal(t, old.TRC.Certificates[i], cert)
					}
				})
			}
		})
	}
}

func TestUpdateReSign(t *testing.T) {
	if _, bazel := os.LookupEnv("TEST_UNDECLARED_OUTPUTS_DIR"); bazel {
		t.Skip("Test can't run through bazel because of symlinks and docker not playing nice")
	}
	outDir, cleanF := xtest.MustTempDir("", "testcrypto")
	defer cleanF()
	topo := "./testdata/test.topo"
	cryptoLib := "../../../scripts/cryptoplayground/crypto_lib.sh"
	err := testcrypto.Testcrypto(topo, cryptoLib, outDir, false, false)
	require.NoError(t, err)

	cmd := testcrypto.NewUpdate()
	cmd.SetArgs([]string{"-o", outDir, "--scenario", "re-sign"})

	err = cmd.Execute()
	require.NoError(t, err)

	allASes := []addr.IA{
		xtest.MustParseIA("1-ff00:0:110"),
		xtest.MustParseIA("1-ff00:0:120"),
		xtest.MustParseIA("1-ff00:0:130"),
		xtest.MustParseIA("1-ff00:0:111"),
		xtest.MustParseIA("1-ff00:0:131"),
		xtest.MustParseIA("2-ff00:0:210"),
		xtest.MustParseIA("2-ff00:0:220"),
	}

	loadTRC := func(t *testing.T, isd addr.ISD, s uint64) cppki.SignedTRC {
		trc, err := trcs.DecodeFromFile(fmt.Sprintf("%s/trcs/ISD%d-B1-S%d.trc", outDir, isd, s))
		require.NoError(t, err)
		return trc
	}
	trcs := map[addr.ISD]cppki.SignedTRC{
		1: loadTRC(t, 1, 2),
		2: loadTRC(t, 2, 2),
	}

	for _, ia := range allASes {
		t.Run(ia.String(), func(t *testing.T) {
			file := filepath.Join(testcrypto.CryptoASDir(ia, testcrypto.NewOut(outDir)),
				ia.FileFmt(true)+".pem")
			chain, err := cppki.ReadPEMCerts(file)
			require.NoError(t, err)
			trc := trcs[ia.I].TRC
			err = cppki.VerifyChain(chain, cppki.VerifyOptions{TRC: []*cppki.TRC{&trc}})
			require.NoError(t, err)
		})
	}
	for isd, trc := range trcs {
		t.Run(strconv.Itoa(int(isd)), func(t *testing.T) {
			old := loadTRC(t, isd, 1)
			err := trc.Verify(&old.TRC)
			require.NoError(t, err)

			for i, cert := range trc.TRC.Certificates {
				t.Run(fmt.Sprintf("cert: %d", i), func(t *testing.T) {
					updateT, err := cppki.ValidateCert(cert)
					require.NoError(t, err)
					oldT, err := cppki.ValidateCert(old.TRC.Certificates[i])
					require.NoError(t, err)

					require.Equal(t, oldT, updateT)
					require.Equal(t, old.TRC.Certificates[i], cert)
				})
			}
		})
	}
}

func TestUpdateReGen(t *testing.T) {
	if _, bazel := os.LookupEnv("TEST_UNDECLARED_OUTPUTS_DIR"); bazel {
		t.Skip("Test can't run through bazel because of symlinks and docker not playing nice")
	}
	outDir, cleanF := xtest.MustTempDir("", "testcrypto")
	defer cleanF()
	topo := "./testdata/test.topo"
	cryptoLib := "../../../scripts/cryptoplayground/crypto_lib.sh"
	err := testcrypto.Testcrypto(topo, cryptoLib, outDir, false, false)
	require.NoError(t, err)

	cmd := testcrypto.NewUpdate()
	cmd.SetArgs([]string{"-o", outDir, "--scenario", "re-gen"})

	err = cmd.Execute()
	require.NoError(t, err)

	allASes := []addr.IA{
		xtest.MustParseIA("1-ff00:0:110"),
		xtest.MustParseIA("1-ff00:0:120"),
		xtest.MustParseIA("1-ff00:0:130"),
		xtest.MustParseIA("1-ff00:0:111"),
		xtest.MustParseIA("1-ff00:0:131"),
		xtest.MustParseIA("2-ff00:0:210"),
		xtest.MustParseIA("2-ff00:0:220"),
	}

	loadTRC := func(t *testing.T, isd addr.ISD, s uint64) cppki.SignedTRC {
		trc, err := trcs.DecodeFromFile(fmt.Sprintf("%s/trcs/ISD%d-B1-S%d.trc", outDir, isd, s))
		require.NoError(t, err)
		return trc
	}
	trcs := map[addr.ISD]cppki.SignedTRC{
		1: loadTRC(t, 1, 2),
		2: loadTRC(t, 2, 2),
	}

	// Check that the certification path is broken for all AS certificates
	for _, ia := range allASes {
		t.Run(ia.String(), func(t *testing.T) {
			file := filepath.Join(testcrypto.CryptoASDir(ia, testcrypto.NewOut(outDir)),
				ia.FileFmt(true)+".pem")
			chain, err := cppki.ReadPEMCerts(file)
			require.NoError(t, err)
			trc := trcs[ia.I].TRC
			err = cppki.VerifyChain(chain, cppki.VerifyOptions{TRC: []*cppki.TRC{&trc}})
			require.Error(t, err)
		})
	}
	// Check that the certificates and keys are different from the previous TRC.
	for isd, trc := range trcs {
		t.Run(strconv.Itoa(int(isd)), func(t *testing.T) {
			old := loadTRC(t, isd, 1)
			err := trc.Verify(&old.TRC)
			require.NoError(t, err)

			for i, cert := range trc.TRC.Certificates {
				t.Run(fmt.Sprintf("cert: %d", i), func(t *testing.T) {
					oldCert := old.TRC.Certificates[i]
					require.NotEqual(t, oldCert, cert)
					require.NotEqual(t, oldCert.PublicKey, cert.PublicKey)

					certType, err := cppki.ValidateCert(cert)
					require.NoError(t, err)
					oldCertType, err := cppki.ValidateCert(oldCert)
					require.NoError(t, err)
					require.Equal(t, oldCertType, certType)

				})
			}
		})
	}
}
