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

package trcs

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/command"
)

func TestNewFormatCmd(t *testing.T) {
	dir, cleanup := xtest.MustTempDir("", "format-trc-test")
	defer cleanup()

	testCases := map[string]struct {
		Prepare      func(t *testing.T)
		Args         []string
		ErrAssertion assert.ErrorAssertionFunc
		Expected     string
	}{
		"format not supported": {
			Args:         []string{"--format=gugus", "testdata/admin/ISD1-B1-S1.pem.trc"},
			ErrAssertion: assert.Error,
		},
		"file not set": {
			Args:         []string{"--format=der"},
			ErrAssertion: assert.Error,
		},
		"file does not exist": {
			Args:         []string{dir + "/lol"},
			ErrAssertion: assert.Error,
		},
		"out dir does not exist": {
			Args: []string{"testdata/admin/ISD1-B1-S1.pem.trc",
				"--out", dir + "/lol/file",
			},
			ErrAssertion: assert.Error,
		},
		"file exists": {
			Prepare: func(t *testing.T) {
				require.NoError(t, ioutil.WriteFile(dir+"/exists.pem", []byte("exists"), 0666))
			},
			Args: []string{"testdata/admin/ISD1-B1-S1.pem.trc",
				"--out", dir + "/exists.pem",
			},
			ErrAssertion: assert.Error,
		},
		"force": {
			Prepare: func(t *testing.T) {
				require.NoError(t, ioutil.WriteFile(dir+"/exists.pem", []byte("exists"), 0666))
			},
			Args: []string{"testdata/admin/ISD1-B1-S1.pem.trc",
				"--force",
				"--out", dir + "/force.pem",
			},
			ErrAssertion: assert.NoError,
			Expected:     "testdata/admin/ISD1-B1-S1.pem.trc",
		},
		"TRC pem to pem": {
			Args: []string{"testdata/admin/ISD1-B1-S1.pem.trc",
				"--out", dir + "/trc-pem.pem",
			},
			ErrAssertion: assert.NoError,
			Expected:     "testdata/admin/ISD1-B1-S1.pem.trc",
		},
		"TRC pem to der": {
			Args: []string{"testdata/admin/ISD1-B1-S1.pem.trc",
				"--format=der",
				"--out", dir + "/trc-pem.der",
			},
			ErrAssertion: assert.NoError,
			Expected:     "testdata/admin/ISD1-B1-S1.trc",
		},
		"TRC der to der": {
			Args: []string{"testdata/admin/ISD1-B1-S1.trc",
				"--format=der",
				"--out", dir + "/trc-der.der",
			},
			ErrAssertion: assert.NoError,
			Expected:     "testdata/admin/ISD1-B1-S1.trc",
		},
		"TRC der to pem": {
			Args: []string{"testdata/admin/ISD1-B1-S1.trc",
				"--out", dir + "/trc-der.pem",
			},
			ErrAssertion: assert.NoError,
			Expected:     "testdata/admin/ISD1-B1-S1.pem.trc",
		},
		"TRC payload pem to pem": {
			Args: []string{"testdata/admin/ISD1-B1-S1.pld.pem",
				"--out", dir + "/trc-pld-pem.pem",
			},
			ErrAssertion: assert.NoError,
			Expected:     "testdata/admin/ISD1-B1-S1.pld.pem",
		},
		"TRC payload pem to der": {
			Args: []string{"testdata/admin/ISD1-B1-S1.pld.pem",
				"--format=der",
				"--out", dir + "/trc-pld-pem.der",
			},
			ErrAssertion: assert.NoError,
			Expected:     "testdata/admin/ISD1-B1-S1.pld.der",
		},
		"TRC payload der to der": {
			Args: []string{"testdata/admin/ISD1-B1-S1.pld.der",
				"--format=der",
				"--out", dir + "/trc-pld-der.der",
			},
			ErrAssertion: assert.NoError,
			Expected:     "testdata/admin/ISD1-B1-S1.pld.der",
		},
		"TRC payload der to pem": {
			Args: []string{"testdata/admin/ISD1-B1-S1.pld.der",
				"--out", dir + "/trc-pld-der.pem",
			},
			ErrAssertion: assert.NoError,
			Expected:     "testdata/admin/ISD1-B1-S1.pld.pem",
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			if tc.Prepare != nil {
				tc.Prepare(t)
			}

			cmd := newFormatCmd(command.StringPather("test"))
			cmd.SetArgs(tc.Args)
			err := cmd.Execute()
			tc.ErrAssertion(t, err)
			if err != nil {
				return
			}
			filename := tc.Args[len(tc.Args)-1]
			expected, err := ioutil.ReadFile(tc.Expected)
			require.NoError(t, err)
			actual, err := ioutil.ReadFile(filename)
			require.NoError(t, err)
			assert.Equal(t, string(expected), string(actual))
		})
	}
}
