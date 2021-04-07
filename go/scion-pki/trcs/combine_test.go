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

package trcs_test

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"flag"
	"fmt"
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto/cms/protocol"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/scion-pki/trcs"
)

var update = flag.Bool("update", false, "set to true to regenerate certificate files")

func TestCombine(t *testing.T) {
	if *update {
		dir, cleanF := xtest.MustTempDir("", "safedir")
		defer cleanF()

		root, err := filepath.Abs("../../../")
		require.NoError(t, err)
		playground, err := filepath.Abs(filepath.Join(root, "scripts", "cryptoplayground"))
		require.NoError(t, err)

		cmd := exec.Command("sh", "-c", filepath.Join(playground, "trc_ceremony.sh"))
		cmd.Env = []string{
			"SCION_ROOT=" + root,
			"PLAYGROUND=" + playground,
			"SAFEDIR=" + dir,
		}
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))

		runCmd := func(name string, arg ...string) {
			t.Helper()
			cmd := exec.Command(name, arg...)
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, string(out))
		}
		runCmd("sh", "-c", "rm -rf testdata/admin")
		runCmd("sh", "-c", fmt.Sprintf("cp -a %s testdata/", filepath.Join(dir, "admin/.")))

		// Sort signer infos for deterministic result.
		signed, err := trcs.DecodeFromFile("./testdata/admin/ISD1-B1-S1.trc")
		require.NoError(t, err)
		infos := signed.SignerInfos
		sort.Slice(infos, func(i, j int) bool {
			return bytes.Compare(infos[i].SID.FullBytes, infos[j].SID.FullBytes) < 0
		})
		raw, err := signed.Encode()
		require.NoError(t, err)
		ioutil.WriteFile("./testdata/admin/ISD1-B1-S1.trc", raw, 0644)
	}

	dir, clean := xtest.MustTempDir("", "scion-pki-trcs-combine")
	defer clean()
	out := filepath.Join(dir, "combined.der")

	parts := []string{
		"./testdata/admin/bern/ISD1-B1-S1.regular.trc",
		"./testdata/admin/bern/ISD1-B1-S1.sensitive.trc",
		"./testdata/admin/geneva/ISD1-B1-S1.regular.trc",
		"./testdata/admin/geneva/ISD1-B1-S1.sensitive.trc",
		"./testdata/admin/zürich/ISD1-B1-S1.regular.trc",
		"./testdata/admin/zürich/ISD1-B1-S1.sensitive.trc",
		// Duplicates
		"./testdata/admin/bern/ISD1-B1-S1.sensitive.trc",
		"./testdata/admin/geneva/ISD1-B1-S1.regular.trc",
	}

	testCases := map[string]struct {
		pld    string
		format string
	}{
		"der format": {
			pld:    "./testdata/admin/ISD1-B1-S1.pld.der",
			format: "der",
		},
		"pem format": {
			pld:    "./testdata/admin/ISD1-B1-S1.pld.pem",
			format: "pem",
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			err := trcs.RunCombine(parts, tc.pld, out, tc.format)
			require.NoError(t, err)
			written, err := trcs.DecodeFromFile(out)
			require.NoError(t, err)
			dec, err := trcs.DecodeFromFile(out)
			require.NoError(t, err)
			assert.Equal(t, dec, written)

			assert.Len(t, written.SignerInfos, 6)
		})
	}
}

func TestCombineSignerInfos(t *testing.T) {
	signed, err := trcs.DecodeFromFile("./testdata/admin/ISD1-B1-S1.trc")
	require.NoError(t, err)

	testCases := map[string]struct {
		partialTRCs func(t *testing.T) map[string]cppki.SignedTRC
		assert      assert.ErrorAssertionFunc
	}{
		"simple": {
			partialTRCs: func(t *testing.T) map[string]cppki.SignedTRC {
				return map[string]cppki.SignedTRC{
					"one": {TRC: signed.TRC, SignerInfos: signed.SignerInfos[:1]},
					"two": {TRC: signed.TRC, SignerInfos: signed.SignerInfos[1:]},
				}
			},
			assert: assert.NoError,
		},
		"slight overlap": {
			partialTRCs: func(t *testing.T) map[string]cppki.SignedTRC {
				return map[string]cppki.SignedTRC{
					"partial": {TRC: signed.TRC, SignerInfos: signed.SignerInfos[:1]},
					"full":    signed,
				}
			},
			assert: assert.NoError,
		},
		"double information": {
			partialTRCs: func(t *testing.T) map[string]cppki.SignedTRC {
				return map[string]cppki.SignedTRC{
					"one": signed,
					"two": signed,
				}
			},
			assert: assert.NoError,
		},
		"differing SignerInfo": {
			partialTRCs: func(t *testing.T) map[string]cppki.SignedTRC {
				infos := signed.SignerInfos
				si := infos[0]
				si.Signature = si.Signature[1:]
				infos = []protocol.SignerInfo{si}
				return map[string]cppki.SignedTRC{
					"one": {TRC: signed.TRC, SignerInfos: infos},
					"two": signed,
				}
			},
			assert: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			infos, err := trcs.CombineSignerInfos(tc.partialTRCs(t))
			tc.assert(t, err)
			if err != nil {
				return
			}
			assert.ElementsMatch(t, signed.SignerInfos, infos)
		})
	}
}

func TestCombineDigestAlgorithms(t *testing.T) {
	testCases := map[string]struct {
		algos    []pkix.AlgorithmIdentifier
		expected []pkix.AlgorithmIdentifier
	}{
		"double": {
			algos: []pkix.AlgorithmIdentifier{
				{Algorithm: asn1.ObjectIdentifier{1, 2, 3}},
				{Algorithm: asn1.ObjectIdentifier{1, 2, 3}},
			},
			expected: []pkix.AlgorithmIdentifier{
				{Algorithm: asn1.ObjectIdentifier{1, 2, 3}},
			},
		},
		"out-of-order": {
			algos: []pkix.AlgorithmIdentifier{
				{Algorithm: asn1.ObjectIdentifier{1, 2, 6}},
				{Algorithm: asn1.ObjectIdentifier{1, 2, 5}},
				{Algorithm: asn1.ObjectIdentifier{1, 2, 8}},
				{Algorithm: asn1.ObjectIdentifier{1, 2, 7}},
			},
			expected: []pkix.AlgorithmIdentifier{
				{Algorithm: asn1.ObjectIdentifier{1, 2, 5}},
				{Algorithm: asn1.ObjectIdentifier{1, 2, 6}},
				{Algorithm: asn1.ObjectIdentifier{1, 2, 7}},
				{Algorithm: asn1.ObjectIdentifier{1, 2, 8}},
			},
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// Construct signer infos from algorithms
			var infos []protocol.SignerInfo
			for _, id := range tc.algos {
				infos = append(infos, protocol.SignerInfo{DigestAlgorithm: id})
			}

			res := trcs.CombineDigestAlgorithms(infos)
			assert.Equal(t, tc.expected, res)
		})
	}

}
