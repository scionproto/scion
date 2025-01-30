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
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/scion-pki/key"
)

func TestNewSymmetricCmd(t *testing.T) {
	dir := t.TempDir()

	testCases := map[string]struct {
		Prepare      func(t *testing.T)
		Args         []string
		Check        func(t *testing.T)
		ErrAssertion assert.ErrorAssertionFunc
	}{
		"symmetric not set": {
			ErrAssertion: assert.Error,
		},
		"unknown format": {
			Args:         []string{"--format", "unknown", dir + "/unknown.key"},
			ErrAssertion: assert.Error,
		},
		"symmetric key is dir": {
			Args:         []string{dir},
			ErrAssertion: assert.Error,
		},
		"symmetric key dir does not exist": {
			Args:         []string{dir + "/lol/master-0.key"},
			ErrAssertion: assert.Error,
		},
		"symmetric key already exists": {
			Prepare: func(t *testing.T) {
				require.NoError(t, os.WriteFile(dir+"/exists.key", []byte("exists"), 0666))
			},
			Args:         []string{dir + "/exists.key"},
			ErrAssertion: assert.Error,
		},
		"force write symmetric key": {
			Prepare: func(t *testing.T) {
				require.NoError(t, os.WriteFile(dir+"/force.key", []byte("exists"), 0666))
			},
			Args:         []string{"--force", dir + "/force.key"},
			ErrAssertion: assert.NoError,
			Check: func(t *testing.T) {
				// Check that output was overwritten
				content, err := os.ReadFile(dir + "/force.key")
				require.NoError(t, err)
				assert.NotEqual(t, []byte("exists"), content)
			},
		},
		"key in pem format": {
			Args:         []string{"--format", "pem", dir + "/key.pem"},
			ErrAssertion: assert.NoError,
		},
		"key in base64 format": {
			Args:         []string{"--format", "base64", dir + "/key.64"},
			ErrAssertion: assert.NoError,
			Check: func(t *testing.T) {
				// Check that output was overwritten
				content, err := os.ReadFile(dir + "/key.64")
				require.NoError(t, err)
				key, err := base64.StdEncoding.DecodeString(string(content))
				assert.NoError(t, err)
				assert.Equal(t, 256, len(key))
			},
		},
		"key with valid size and file size": {
			Args:         []string{"--size", "257", dir + "/master-0-257.key"},
			ErrAssertion: assert.NoError,
			Check: func(t *testing.T) {
				// Check that output is not empty and has the specified size
				content, err := os.ReadFile(dir + "/master-0-257.key")
				require.NoError(t, err)
				block, rest := pem.Decode(content)
				assert.Equal(t, 0, len(rest))
				assert.Equal(t, "SYMMETRIC KEY", block.Type)
				assert.Equal(t, 257, len(block.Bytes))
			},
		},
		"negative size": {
			Args:         []string{"--size", "-5", dir + "/master-0--5.key"},
			ErrAssertion: assert.Error,
		},
		"zero size": {
			Args:         []string{"--size", "0", dir + "/master-0-0.key"},
			ErrAssertion: assert.Error,
		},
		"overflow size": {
			Args: []string{"--size",
				fmt.Sprintf("%v1", math.MaxInt64),
				dir + "/master-0-overflow.key"},
			ErrAssertion: assert.Error,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			if tc.Prepare != nil {
				tc.Prepare(t)
			}

			cmd := key.NewSymmetricCmd(command.StringPather("test"))
			cmd.SetArgs(tc.Args)
			err := cmd.Execute()
			tc.ErrAssertion(t, err)
			if err != nil {
				return
			}
			filename := tc.Args[len(tc.Args)-1]
			info, err := os.Stat(filename)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0600), info.Mode())

			if tc.Check != nil {
				tc.Check(t)
			}

		})
	}
}
