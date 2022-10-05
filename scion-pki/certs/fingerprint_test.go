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

package certs

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/private/app/command"
)

func TestFingerprintOnSingleCert(t *testing.T) {
	testCases := map[string]struct {
		InputCertFile string
		OutputFormat  string
		Expected      string
		ErrAssertion  assert.ErrorAssertionFunc
	}{
		"single certificate hex fingerprint output": {
			InputCertFile: "testdata/fingerprint/ISD1-ASff00_0_112.pem",
			OutputFormat:  "hex",
			Expected:      "bd1cda0f5c1de4f7f02f1c947048615f5efb9aeb23bced019f591330d3f8c0e4",
			ErrAssertion:  assert.NoError,
		},
		"single certificate emoji fingerprint output": {
			InputCertFile: "testdata/fingerprint/ISD1-ASff00_0_112.pem",
			OutputFormat:  "emoji",
			Expected:      "✂️👦🏊‍♂️💈💂‍♂️💔👅👋🔓©️👦👌🕵️‍♀️🎡🐹🍔🔫👩⛅🐢🍬🎷👭🎱☎️🐐🚴‍♂️🌽🗽〰️🐚👅",
			ErrAssertion:  assert.NoError,
		},
		"certificate chain hex fingerprint output": {
			InputCertFile: "testdata/fingerprint/ISD1-ASff00_0_111.pem",
			OutputFormat:  "hex",
			Expected:      "bf5c910b77bbd25416bb8067a9ce34b6291a05a763279240dc5855e018ebc3d5",
			ErrAssertion:  assert.NoError,
		},
		"certificate chain emoji fingerprint output": {
			InputCertFile: "testdata/fingerprint/ISD1-ASff00_0_111.pem",
			OutputFormat:  "emoji",
			Expected:      "🐑💂‍♂️🔩🍼🔑😆⛲🌕🌼😆👨🗿👸👾😢🐓☁️💥👼🍗❤️🍫⭕🍆🎉👧🎲⛺🐗🐢💀🌻",
			ErrAssertion:  assert.NoError,
		},
		"empty certificate file hex fingerprint output": {
			InputCertFile: "testdata/fingerprint/empty_cert_file.pem",
			OutputFormat:  "hex",
			Expected:      "",
			ErrAssertion:  assert.Error,
		},
		"empty certificate file emoji fingerprint output": {
			InputCertFile: "testdata/fingerprint/empty_cert_file.pem",
			OutputFormat:  "emoji",
			Expected:      "",
			ErrAssertion:  assert.Error,
		},
		"invalid single certificate hex fingerprint output": {
			InputCertFile: "testdata/fingerprint/invalid_cert_file.pem",
			OutputFormat:  "hex",
			Expected:      "",
			ErrAssertion:  assert.Error,
		},
		"invalid single certificate emoji fingerprint output": {
			InputCertFile: "testdata/fingerprint/invalid_cert_file.pem",
			OutputFormat:  "emoji",
			Expected:      "",
			ErrAssertion:  assert.Error,
		},
		"invalid certificate chain hex fingerprint output": {
			InputCertFile: "testdata/fingerprint/invalid_cert_chain_file.pem",
			OutputFormat:  "hex",
			Expected:      "",
			ErrAssertion:  assert.Error,
		},
		"invalid certificate chain emoji fingerprint output": {
			InputCertFile: "testdata/fingerprint/invalid_cert_chain_file.pem",
			OutputFormat:  "emoji",
			Expected:      "",
			ErrAssertion:  assert.Error,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			cmd := newFingerprintCmd(command.StringPather("test"))

			args := []string{"--format", tc.OutputFormat, tc.InputCertFile}
			cmd.SetArgs(args)
			actualFingerprint := new(bytes.Buffer)
			cmd.SetOut(actualFingerprint)

			err := cmd.Execute()
			tc.ErrAssertion(t, err)
			if err != nil {
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.Expected, strings.Trim(actualFingerprint.String(), "\n"))
		})
	}
}
