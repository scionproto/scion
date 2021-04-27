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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/command"
	"github.com/scionproto/scion/go/scion-pki/key"
)

func TestNewPrivateCmd(t *testing.T) {
	dir, cleanup := xtest.MustTempDir("", "private-key-test")
	defer cleanup()

	testCases := map[string]struct {
		Prepare      func(t *testing.T)
		Args         []string
		ErrAssertion assert.ErrorAssertionFunc
	}{
		"private not set": {
			ErrAssertion: assert.Error,
		},
		"unknown curve": {
			Args:         []string{"--curve", "unknown", dir + "/unknown.key"},
			ErrAssertion: assert.Error,
		},
		"private key is dir": {
			Args:         []string{dir},
			ErrAssertion: assert.Error,
		},
		"private key dir does not exist": {
			Args:         []string{dir + "/lol/"},
			ErrAssertion: assert.Error,
		},
		"private key already exists": {
			Prepare: func(t *testing.T) {
				require.NoError(t, ioutil.WriteFile(dir+"/exists.key", []byte("exists"), 0666))
			},
			Args:         []string{dir + "/exists.key"},
			ErrAssertion: assert.Error,
		},
		"force write private key": {
			Prepare: func(t *testing.T) {
				require.NoError(t, ioutil.WriteFile(dir+"/force.key", []byte("exists"), 0666))
			},
			Args:         []string{"--force", dir + "/force.key"},
			ErrAssertion: assert.NoError,
		},
		"p-256": {
			Args:         []string{"--curve", "p-256", dir + "/p-256.key"},
			ErrAssertion: assert.NoError,
		},
		"p-384": {
			Args:         []string{"--curve", "p-384", dir + "/p-384.key"},
			ErrAssertion: assert.NoError,
		},
		"p-521": {
			Args:         []string{"--curve", "p-521", dir + "/p-521.key"},
			ErrAssertion: assert.NoError,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			if tc.Prepare != nil {
				tc.Prepare(t)
			}

			cmd := key.NewPrivateCmd(command.StringPather("test"))
			cmd.SetArgs(tc.Args)
			err := cmd.Execute()
			tc.ErrAssertion(t, err)
			if err != nil {
				return
			}
			filename := tc.Args[len(tc.Args)-1]
			_, err = key.LoadPrivateKey(filename)
			require.NoError(t, err)

			info, err := os.Stat(filename)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0600), info.Mode())
		})
	}
}
