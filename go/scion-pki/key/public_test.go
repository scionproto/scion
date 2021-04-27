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

package key_test

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/command"
	"github.com/scionproto/scion/go/scion-pki/key"
)

func TestNewPublicCmd(t *testing.T) {
	dir, cleanup := xtest.MustTempDir("", "public-key-test")
	defer cleanup()

	testCases := map[string]struct {
		Prepare      func(t *testing.T)
		Args         []string
		ErrAssertion assert.ErrorAssertionFunc
	}{
		"private not set": {
			ErrAssertion: assert.Error,
		},
		"private key does not exist": {
			Args:         []string{"--out", dir, "testdata/notexist.key"},
			ErrAssertion: assert.Error,
		},
		"public key is dir": {
			Args:         []string{"--out", dir, "testdata/private.key"},
			ErrAssertion: assert.Error,
		},
		"public key dir does not exist": {
			Args:         []string{"--out", dir + "/lol/", "testdata/private.key"},
			ErrAssertion: assert.Error,
		},
		"public key already exists": {
			Prepare: func(t *testing.T) {
				require.NoError(t, ioutil.WriteFile(dir+"/exists.key", []byte("exists"), 0666))
			},
			Args:         []string{"--out", dir + "/exists.key", "testdata/private.key"},
			ErrAssertion: assert.Error,
		},
		"force write public key": {
			Prepare: func(t *testing.T) {
				require.NoError(t, ioutil.WriteFile(dir+"/force.key", []byte("exists"), 0666))
			},
			Args:         []string{"--out", dir + "/force.key", "--force", "testdata/private.key"},
			ErrAssertion: assert.NoError,
		},
		"success": {
			Args:         []string{"--out", dir + "/success.key", "testdata/private.key"},
			ErrAssertion: assert.NoError,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			if tc.Prepare != nil {
				tc.Prepare(t)
			}

			cmd := key.NewPublicCmd(command.StringPather("test"))
			cmd.SetArgs(tc.Args)
			err := cmd.Execute()
			tc.ErrAssertion(t, err)
			if err != nil {
				return
			}
			expected, err := ioutil.ReadFile("testdata/public.key")
			require.NoError(t, err)
			actual, err := ioutil.ReadFile(tc.Args[1])
			require.NoError(t, err)
			assert.Equal(t, string(expected), string(actual))
		})
	}
}
