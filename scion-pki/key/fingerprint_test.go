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
	"fmt"
	"os"
	"testing"

	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/scion-pki/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFingerprintCmd(t *testing.T) {
	dir, cleanup := xtest.MustTempDir("", "fingerprint-key-test")
	defer cleanup()

	testCases := map[string]struct {
		Prepare      func(t *testing.T)
		Args         []string
		ErrAssertion assert.ErrorAssertionFunc
		Expected     []byte
	}{
		"key not set": {
			ErrAssertion: assert.Error,
		},
		"key does not exist": {
			Args:         []string{"testdata/notexist.key"},
			ErrAssertion: assert.Error,
		},
		"subject key id is dir": {
			Args:         []string{"--out", dir, "testdata/private.key"},
			ErrAssertion: assert.Error,
		},
		"subject key id dir does not exist": {
			Args:         []string{"--out", dir + "/lol/", "testdata/private.key"},
			ErrAssertion: assert.Error,
		},
		"subject key id already exists": {
			Prepare: func(t *testing.T) {
				require.NoError(t, os.WriteFile(dir+"/skid.txt", []byte("exists"), 0666))
			},
			Args:         []string{"--out", dir + "/skid.txt", "testdata/private.key"},
			ErrAssertion: assert.Error,
		},
		// "force write subject key id": {
		// 	Prepare: func(t *testing.T) {
		// 		require.NoError(t, os.WriteFile(dir+"/force_skid.txt", []byte("exists"), 0666))
		// 	},
		// 	Args:         []string{"--out", dir + "/force_skid.txt", "--force", "testdata/private.key"},
		// 	ErrAssertion: assert.NoError,
		// 	Expected:     []byte{16, 73, 136, 56, 120, 153, 109, 39, 235, 115, 226, 121, 18, 183, 146, 112, 42, 162, 23, 120},
		// },
		// "full key digest": {
		// 	Args:         []string{"--out", dir + "/full-key-digest.txt", "--full-key-digest", "testdata/private.key"},
		// 	ErrAssertion: assert.NoError,
		// 	Expected:     []byte{79, 213, 60, 105, 222, 74, 116, 102, 158, 97, 146, 37, 18, 172, 82, 200, 117, 99, 136, 146},
		// },
		"success private key": {
			Args:         []string{"--out", dir + "/private_skid.txt", "testdata/private.key"},
			ErrAssertion: assert.NoError,
			Expected: []byte("I�8x�m'�s�y��p*�x"),
		},
		// "success public key": {
		// 	Args:         []string{"--out", dir + "/public_skid.txt", "testdata/public.key"},
		// 	ErrAssertion: assert.NoError,
		// 	Expected:     []byte{16, 73, 136, 56, 120, 153, 109, 39, 235, 115, 226, 121, 18, 183, 146, 112, 42, 162, 23, 120},
		// },
		// "success certificate": {
		// 	Args:         []string{"--out", dir + "/cert_skid.txt", "testdata/cert.pem"},
		// 	ErrAssertion: assert.NoError,
		// 	Expected:     []byte{16, 73, 136, 56, 120, 153, 109, 39, 235, 115, 226, 121, 18, 183, 146, 112, 42, 162, 23, 120},
		// },
		// "success certificate chain": {
		// 	Args:         []string{"--out", dir + "/chain_skid.txt", "testdata/chain.pem"},
		// 	ErrAssertion: assert.NoError,
		// 	Expected:     []byte{16, 73, 136, 56, 120, 153, 109, 39, 235, 115, 226, 121, 18, 183, 146, 112, 42, 162, 23, 120},
		// },
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			if tc.Prepare != nil {
				tc.Prepare(t)
			}

			cmd := key.NewFingerprintCmd(command.StringPather("test"))
			cmd.SetArgs(tc.Args)
			err := cmd.Execute()
			tc.ErrAssertion(t, err)
			if err != nil {
				return
			}
			fmt.Println(tc.Args[1])
			actual, err := os.ReadFile(tc.Args[1])
			require.NoError(t, err)
			assert.Equal(t, tc.Expected, actual)
		})
	}

}
