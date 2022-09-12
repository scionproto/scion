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

	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/scion-pki/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFingerprintCmd(t *testing.T) {

	testCases := map[string]struct {
		Prepare      func(t *testing.T)
		Args         []string
		OutputFormat string
		Expected     string
		ErrAssertion assert.ErrorAssertionFunc
	}{
		"key not set": {
			ErrAssertion: assert.Error,
		},
		"key does not exist": {
			Args:         []string{"testdata/notexist.key"},
			ErrAssertion: assert.Error,
		},
		// "full key digest": {
		// 	Args:         []string{"--full-key-digest", "testdata/private.key"},
		// 	ErrAssertion: assert.NoError,
		// 	OutputFormat: "emoji",
		// 	Expected:     "???",
		// },
		// "success private key": {
		// 	Args:         []string{"testdata/private.key"},
		// 	ErrAssertion: assert.NoError,
		// 	OutputFormat: "emoji",
		// 	Expected:     "🎃🐌🙉🍭🙊⭐🍫😎〰️🎱✉🚀🐢🌼👽🔥🎆⚽⌛👀🚴‍♂️🍁🔑🍋🌼🌕🏠💅♦️🐝🎼⚽",
		// },
		// "success public key": {
		// 	Args:         []string{"testdata/public.key"},
		// 	ErrAssertion: assert.NoError,
		// 	OutputFormat: "emoji",
		// 	Expected:     "🎃🐌🙉🍭🙊⭐🍫😎〰️🎱✉🚀🐢🌼👽🔥🎆⚽⌛👀🚴‍♂️🍁🔑🍋🌼🌕🏠💅♦️🐝🎼⚽",
		// },
		// "success certificate": {
		// 	Args:         []string{"testdata/cert.pem"},
		// 	ErrAssertion: assert.NoError,
		// 	OutputFormat: "emoji",
		// 	Expected:     "🛁😰💪💨💋📎🏇🍫🐢🇮🇹™️😽🔔🇷🇺⭕🕵️‍♀️♣️🍍🚙💋",
		// },
		"success certificate chain": {
			Args:         []string{"testdata/chain.pem"},
			ErrAssertion: assert.NoError,
			OutputFormat: "emoji",
			Expected:     "🛁😰💪💨💋📎🏇🍫🐢🇮🇹™️😽🔔🇷🇺⭕🕵️‍♀️♣️🍍🚙💋",
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			if tc.Prepare != nil {
				tc.Prepare(t)
			}

			cmd := key.NewFingerprintCmd(command.StringPather("test"))
			cmd.SetArgs(tc.Args)
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
