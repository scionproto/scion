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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/command"
)

var update = xtest.UpdateGoldenFiles()

func TestNewInspectCmd(t *testing.T) {
	testCases := map[string]struct {
		Args         []string
		ErrAssertion assert.ErrorAssertionFunc
		Golden       string
	}{
		"missing arguments": {
			Args:         []string{},
			ErrAssertion: assert.Error,
		},
		"invalid input file": {
			Args:         []string{"testdata/inspect/invalid.pem"},
			ErrAssertion: assert.Error,
		},
		"unknown pem block type": {
			Args:         []string{"testdata/inspect/unknown_block_type.pem"},
			ErrAssertion: assert.Error,
		},
		"unknown second pem block type": {
			Args:         []string{"testdata/inspect/unknown_block_type.pem"},
			ErrAssertion: assert.Error,
		},
		"csr": {
			Args:         []string{"testdata/inspect/sample_csr.pem"},
			ErrAssertion: assert.NoError,
			Golden:       "testdata/inspect/sample_csr.golden",
		},
		"csr short": {
			Args:         []string{"--short", "testdata/inspect/sample_csr.pem"},
			ErrAssertion: assert.NoError,
			Golden:       "testdata/inspect/sample_csr.short.golden",
		},
		"certificate": {
			Args:         []string{"testdata/inspect/sample_certificate.pem"},
			ErrAssertion: assert.NoError,
			Golden:       "testdata/inspect/sample_certificate.golden",
		},
		"certificate short": {
			Args:         []string{"--short", "testdata/inspect/sample_certificate.pem"},
			ErrAssertion: assert.NoError,
			Golden:       "testdata/inspect/sample_certificate.short.golden",
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			cmd := newInspectCmd(command.StringPather("test"))
			var buf bytes.Buffer
			cmd.SetOut(&buf)

			cmd.SetArgs(tc.Args)
			err := cmd.Execute()
			tc.ErrAssertion(t, err)
			if tc.Golden != "" {
				if *update {
					require.NoError(t, os.WriteFile(tc.Golden, buf.Bytes(), 0666))
				}
				raw, err := os.ReadFile(tc.Golden)
				require.NoError(t, err)
				assert.Equal(t, string(raw), buf.String())
			}
		})
	}
}
