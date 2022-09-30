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

package key_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/scion-pki/key"
)

func TestNewFingerprintCmd(t *testing.T) {

	testCases := map[string]struct {
		InputCertFile string
		OutputFormat  string
		Expected      string
		FullKeyDigest bool
		ErrAssertion  assert.ErrorAssertionFunc
	}{
		"key not set": {
			ErrAssertion: assert.Error,
		},
		"key does not exist": {
			InputCertFile: "testdata/notexist.key",
			ErrAssertion:  assert.Error,
		},
		"full key digest private": {
			InputCertFile: "testdata/private.key",
			FullKeyDigest: true,
			OutputFormat:  "emoji",
			Expected:      "🎹📷🐹❌🍌🐐😰🔪😎©️🎡🔪🍬🔛🌊🍀❌🐰👋🎠",
			ErrAssertion:  assert.NoError,
		},
		"full key digest public": {
			InputCertFile: "testdata/public.key",
			FullKeyDigest: true,
			OutputFormat:  "emoji",
			Expected:      "🎹📷🐹❌🍌🐐😰🔪😎©️🎡🔪🍬🔛🌊🍀❌🐰👋🎠",
			ErrAssertion:  assert.NoError,
		},
		"full key digest certificate": {
			InputCertFile: "testdata/cert.pem",
			FullKeyDigest: true,
			OutputFormat:  "emoji",
			Expected:      "🍀🌻🍩🚁🚕🔥🎃✔️🐧🐹⭕🍒🔔🐰🥜🚬👺❤️💪⭕",
			ErrAssertion:  assert.NoError,
		},
		"full key digest certificate chain": {
			InputCertFile: "testdata/chain.pem",
			FullKeyDigest: true,
			OutputFormat:  "emoji",
			Expected:      "🍀🌻🍩🚁🚕🔥🎃✔️🐧🐹⭕🍒🔔🐰🥜🚬👺❤️💪⭕",
			ErrAssertion:  assert.NoError,
		},
		"success private key": {
			InputCertFile: "testdata/private.key",
			OutputFormat:  "emoji",
			Expected:      "🍒🔓⭕⛔👉☁️♠️☎️🎾🔩🇪🇺🐱🎲👾👸🎼🍌🔥👯‍♀️🤘",
			ErrAssertion:  assert.NoError,
		},
		"success public key": {
			InputCertFile: "testdata/public.key",
			OutputFormat:  "emoji",
			Expected:      "🍒🔓⭕⛔👉☁️♠️☎️🎾🔩🇪🇺🐱🎲👾👸🎼🍌🔥👯‍♀️🤘",
			ErrAssertion:  assert.NoError,
		},
		"success certificate": {
			InputCertFile: "testdata/cert.pem",
			OutputFormat:  "emoji",
			Expected:      "🛁😰💪💨💋📎🏇🍫🐢🇮🇹™️😽🔔🇷🇺⭕🕵️‍♀️♣️🍍🚙💋",
			ErrAssertion:  assert.NoError,
		},
		"success certificate chain": {
			InputCertFile: "testdata/chain.pem",
			OutputFormat:  "emoji",
			Expected:      "🛁😰💪💨💋📎🏇🍫🐢🇮🇹™️😽🔔🇷🇺⭕🕵️‍♀️♣️🍍🚙💋",
			ErrAssertion:  assert.NoError,
		},
		"success hex": {
			InputCertFile: "testdata/chain.pem",
			OutputFormat:  "hex",
			Expected:      "1049883878996d27eb73e27912b792702aa21778",
			ErrAssertion:  assert.NoError,
		},
		"success base64": {
			InputCertFile: "testdata/chain.pem",
			OutputFormat:  "base64",
			Expected:      "EEmIOHiZbSfrc+J5EreScCqiF3g=",
			ErrAssertion:  assert.NoError,
		},
		"success base64-url": {
			InputCertFile: "testdata/chain.pem",
			OutputFormat:  "base64-url",
			Expected:      "EEmIOHiZbSfrc-J5EreScCqiF3g=",
			ErrAssertion:  assert.NoError,
		},
		"success base64-raw": {
			InputCertFile: "testdata/chain.pem",
			OutputFormat:  "base64-raw",
			Expected:      "EEmIOHiZbSfrc+J5EreScCqiF3g",
			ErrAssertion:  assert.NoError,
		},
		"success base64-url-raw": {
			InputCertFile: "testdata/chain.pem",
			OutputFormat:  "base64-url-raw",
			Expected:      "EEmIOHiZbSfrc-J5EreScCqiF3g",
			ErrAssertion:  assert.NoError,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			cmd := key.NewFingerprintCmd(command.StringPather("test"))

			args := []string{"--format", tc.OutputFormat, tc.InputCertFile}
			if tc.FullKeyDigest {
				args = append(args, "--full-key-digest")
			}
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
