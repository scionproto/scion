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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/command"
)

func TestNewCreateCmd(t *testing.T) {
	dir, cleanup := xtest.MustTempDir("", "certificate-create-test")
	defer cleanup()

	now := time.Now()

	testCases := map[string]struct {
		Prepare      func(t *testing.T)
		Args         []string
		ErrAssertion assert.ErrorAssertionFunc
		Validate     func(t *testing.T, certs []*x509.Certificate)
	}{
		"missing arguments": {
			Args:         []string{"testdata/create/subject.json"},
			ErrAssertion: assert.Error,
		},
		"missing key": {
			Args:         []string{"testdata/create/subject.json", dir + "/missing.crt"},
			ErrAssertion: assert.Error,
		},
		"unknown profile": {
			Args: []string{
				"testdata/create/subject.json",
				dir + "/unknown.crt",
				dir + "/unknown.key",
				"--profile=garbage",
			},
			ErrAssertion: assert.Error,
			Validate: func(t *testing.T, certs []*x509.Certificate) {
				require.NoFileExists(t, dir+"/unknown.crt")
				require.NoFileExists(t, dir+"/unknown.key")
			},
		},
		"unknown curve": {
			Args: []string{
				"testdata/create/subject.json",
				dir + "/unknown.crt",
				dir + "/unknown.key",
				"--curve=garbage",
			},
			ErrAssertion: assert.Error,
			Validate: func(t *testing.T, certs []*x509.Certificate) {
				require.NoFileExists(t, dir+"/unknown.crt")
				require.NoFileExists(t, dir+"/unknown.key")
			},
		},
		"key does not exist": {
			Args: []string{
				"testdata/create/subject.json",
				dir + "/missing-key.crt",
				"--key=testdata/create/garbage.key",
				"--profile=sensitive-voting",
			},
			ErrAssertion: assert.Error,
			Validate: func(t *testing.T, certs []*x509.Certificate) {
				require.NoFileExists(t, dir+"/missing-key.crt")
			},
		},
		"missing ca": {
			Args: []string{
				"testdata/create/subject.json",
				dir + "/missing-ca.crt",
				dir + "/missing-ca.key",
				"--profile=ca",
			},
			ErrAssertion: assert.Error,
			Validate: func(t *testing.T, certs []*x509.Certificate) {
				require.NoFileExists(t, dir+"/missing-ca.crt")
				require.NoFileExists(t, dir+"/missing-ca.key")
			},
		},
		"csr with CA info": {
			Args: []string{
				"testdata/create/subject.json",
				dir + "/csr-ca.csr",
				dir + "/csr-ca.key",
				"--csr",
				"--ca=some/ca",
			},
			ErrAssertion: assert.Error,
			Validate: func(t *testing.T, certs []*x509.Certificate) {
				require.NoFileExists(t, dir+"/csr-ca.crt")
				require.NoFileExists(t, dir+"/csr-ca.key")
			},
		},
		"self signed with CA info": {
			Args: []string{
				"testdata/create/subject.json",
				dir + "/self-signed-ca.crt",
				dir + "/self-signed-ca.key",
				"--profile=cp-root",
				"--ca=some/ca",
			},
			ErrAssertion: assert.Error,
			Validate: func(t *testing.T, certs []*x509.Certificate) {
				require.NoFileExists(t, dir+"/self-signed-ca.crt")
				require.NoFileExists(t, dir+"/self-signed-ca.key")
			},
		},
		"not self signed without CA info": {
			Args: []string{
				"testdata/create/subject.json",
				dir + "/missing-ca.crt",
				dir + "/missing-ca.key",
			},
			ErrAssertion: assert.Error,
			Validate: func(t *testing.T, certs []*x509.Certificate) {
				require.NoFileExists(t, dir+"/missing-ca.crt")
				require.NoFileExists(t, dir+"/missing-ca.key")
			},
		},
		"key exists": {
			Args: []string{
				"testdata/create/subject.json",
				dir + "/key-exists.crt",
				"testdata/create/private.key",
			},
			ErrAssertion: assert.Error,
		},
		"cert exists": {
			Args: []string{
				"testdata/create/subject.json",
				"testdata/create/subject.json",
				dir + "/cert-exists.key",
			},
			ErrAssertion: assert.Error,
		},
		"sensitive": {
			Args: []string{
				"testdata/create/subject.json",
				dir + "/sensitive.crt",
				dir + "/sensitive.key",
				"--profile=sensitive-voting",
			},
			ErrAssertion: assert.NoError,
			Validate: func(t *testing.T, certs []*x509.Certificate) {
				ct, err := cppki.ValidateCert(certs[0])
				require.NoError(t, err)
				require.Equal(t, cppki.Sensitive, ct)
				require.Equal(t, "1-ff00:0:111 Certificate", certs[0].Subject.CommonName)
			},
		},
		"regular": {
			Args: []string{
				"testdata/create/subject.json",
				dir + "/regular.crt",
				dir + "/regular.key",
				"--profile=regular-voting",
			},
			ErrAssertion: assert.NoError,
			Validate: func(t *testing.T, certs []*x509.Certificate) {
				ct, err := cppki.ValidateCert(certs[0])
				require.NoError(t, err)
				require.Equal(t, cppki.Regular, ct)
				require.Equal(t, "1-ff00:0:111 Certificate", certs[0].Subject.CommonName)
			},
		},
		"cp-root": {
			Args: []string{
				"testdata/create/subject.json",
				dir + "/cp-root.crt",
				dir + "/cp-root.key",
				"--profile=cp-root",
			},
			ErrAssertion: assert.NoError,
			Validate: func(t *testing.T, certs []*x509.Certificate) {
				ct, err := cppki.ValidateCert(certs[0])
				require.NoError(t, err)
				require.Equal(t, cppki.Root, ct)
				require.Equal(t, "1-ff00:0:111 Certificate", certs[0].Subject.CommonName)
			},
		},
		"cp-ca": {
			Prepare: func(t *testing.T) {
				cmd := newCreateCmd(command.StringPather("test"))
				cmd.SetArgs([]string{
					"testdata/create/subject.json",
					dir + "/cp-ca-root.crt",
					dir + "/cp-ca-root.key",
					"--profile=cp-root",
				})
				require.NoError(t, cmd.Execute())
			},
			Args: []string{
				"testdata/create/subject.json",
				dir + "/cp-ca.crt",
				dir + "/cp-ca.key",
				"--profile=cp-ca",
				"--ca=" + dir + "/cp-ca-root.crt",
				"--ca-key=" + dir + "/cp-ca-root.key",
			},
			ErrAssertion: assert.NoError,
			Validate: func(t *testing.T, certs []*x509.Certificate) {
				ct, err := cppki.ValidateCert(certs[0])
				require.NoError(t, err)
				require.Equal(t, cppki.CA, ct)
				require.Equal(t, "1-ff00:0:111 Certificate", certs[0].Subject.CommonName)
			},
		},
		"cp-as": {
			Prepare: func(t *testing.T) {
				rootCmd := newCreateCmd(command.StringPather("test"))
				rootCmd.SetArgs([]string{
					"testdata/create/subject.json",
					dir + "/cp-as-root.crt",
					dir + "/cp-as-root.key",
					"--profile=cp-root",
				})
				require.NoError(t, rootCmd.Execute())
				caCmd := newCreateCmd(command.StringPather("test"))
				caCmd.SetArgs([]string{
					"testdata/create/subject.json",
					dir + "/cp-as-ca.crt",
					dir + "/cp-as-ca.key",
					"--profile=cp-ca",
					"--ca=" + dir + "/cp-as-root.crt",
					"--ca-key=" + dir + "/cp-as-root.key",
				})
				require.NoError(t, caCmd.Execute())
			},
			Args: []string{
				"testdata/create/subject.json",
				dir + "/cp-as.crt",
				dir + "/cp-as.key",
				"--ca=" + dir + "/cp-as-ca.crt",
				"--ca-key=" + dir + "/cp-as-ca.key",
			},
			ErrAssertion: assert.NoError,
			Validate: func(t *testing.T, certs []*x509.Certificate) {
				ct, err := cppki.ValidateCert(certs[0])
				require.NoError(t, err)
				require.Equal(t, cppki.AS, ct)
				require.Equal(t, "1-ff00:0:111 Certificate", certs[0].Subject.CommonName)
			},
		},
		"chain": {
			Prepare: func(t *testing.T) {
				rootCmd := newCreateCmd(command.StringPather("test"))
				rootCmd.SetArgs([]string{
					"testdata/create/subject.json",
					dir + "/chain-root.crt",
					dir + "/chain-root.key",
					"--profile=cp-root",
				})
				require.NoError(t, rootCmd.Execute())
				caCmd := newCreateCmd(command.StringPather("test"))
				caCmd.SetArgs([]string{
					"testdata/create/subject.json",
					dir + "/chain-ca.crt",
					dir + "/chain-ca.key",
					"--profile=cp-ca",
					"--ca=" + dir + "/chain-root.crt",
					"--ca-key=" + dir + "/chain-root.key",
				})
				require.NoError(t, caCmd.Execute())
			},
			Args: []string{
				"testdata/create/subject.json",
				dir + "/chain.pem",
				dir + "/chain.key",
				"--ca=" + dir + "/chain-ca.crt",
				"--ca-key=" + dir + "/chain-ca.key",
				"--bundle",
			},
			ErrAssertion: assert.NoError,
			Validate: func(t *testing.T, certs []*x509.Certificate) {
				require.NoError(t, cppki.ValidateChain(certs))
				require.Equal(t, "1-ff00:0:111 Certificate", certs[0].Subject.CommonName)
			},
		},
		"existing key": {
			Args: []string{
				"testdata/create/subject.json",
				dir + "/existing-key.crt",
				"--key=testdata/create/private.key",
				"--profile=sensitive-voting",
			},
			ErrAssertion: assert.NoError,
			Validate: func(t *testing.T, certs []*x509.Certificate) {
				ct, err := cppki.ValidateCert(certs[0])
				require.NoError(t, err)
				require.Equal(t, cppki.Sensitive, ct)
				require.Equal(t, "1-ff00:0:111 Certificate", certs[0].Subject.CommonName)
			},
		},
		"optional flags": {
			Args: []string{
				"testdata/create/subject.json",
				dir + "/optional-flags.crt",
				dir + "/optional-flags.key",
				"--profile=sensitive-voting",
				"--curve=p-521",
				"--not-before=-1h",
				"--not-after=1h",
			},
			ErrAssertion: assert.NoError,
			Validate: func(t *testing.T, certs []*x509.Certificate) {
				ct, err := cppki.ValidateCert(certs[0])
				require.NoError(t, err)
				require.Equal(t, cppki.Sensitive, ct)
				require.Equal(t, "1-ff00:0:111 Certificate", certs[0].Subject.CommonName)

				key := certs[0].PublicKey.(*ecdsa.PublicKey)
				require.Equal(t, elliptic.P521(), key.Curve)
				withinDelta := func(expected, actual time.Time) {
					require.Less(t, int64(expected.Sub(actual)), int64(5*time.Second))
					require.Less(t, int64(actual.Sub(expected)), int64(5*time.Second))
				}
				withinDelta(now.Add(-time.Hour), certs[0].NotBefore)
				withinDelta(now.Add(time.Hour), certs[0].NotAfter)
			},
		},
		"unix time": {
			Args: []string{
				"testdata/create/subject.json",
				dir + "/unix-time.crt",
				dir + "/unix-time.key",
				"--profile=sensitive-voting",
				"--not-before=" + strconv.Itoa(int(now.Add(time.Hour).Unix())),
			},
			ErrAssertion: assert.NoError,
			Validate: func(t *testing.T, certs []*x509.Certificate) {
				ct, err := cppki.ValidateCert(certs[0])
				require.NoError(t, err)
				require.Equal(t, cppki.Sensitive, ct)
				require.Equal(t, "1-ff00:0:111 Certificate", certs[0].Subject.CommonName)

				require.Equal(t, now.Add(time.Hour).UTC().Truncate(time.Second), certs[0].NotBefore)
			},
		},
		"offset time": {
			Args: []string{
				"testdata/create/subject.json",
				dir + "/offset-time.crt",
				dir + "/offset-time.key",
				"--profile=sensitive-voting",
				"--not-before=-1h",
				"--not-after=1h",
			},
			ErrAssertion: assert.NoError,
			Validate: func(t *testing.T, certs []*x509.Certificate) {
				ct, err := cppki.ValidateCert(certs[0])
				require.NoError(t, err)
				require.Equal(t, cppki.Sensitive, ct)
				require.Equal(t, "1-ff00:0:111 Certificate", certs[0].Subject.CommonName)

				withinDelta := func(expected, actual time.Time) {
					require.Less(t, int64(expected.Sub(actual)), int64(5*time.Second))
					require.Less(t, int64(actual.Sub(expected)), int64(5*time.Second))
				}
				withinDelta(now.Add(-time.Hour), certs[0].NotBefore)
				withinDelta(now.Add(time.Hour), certs[0].NotAfter)
			},
		},
		"custom common name": {
			Args: []string{
				"testdata/create/subject.json",
				dir + "/common-name.crt",
				dir + "/common-name.key",
				"--profile=sensitive-voting",
				"--common-name=custom",
			},
			ErrAssertion: assert.NoError,
			Validate: func(t *testing.T, certs []*x509.Certificate) {
				ct, err := cppki.ValidateCert(certs[0])
				require.NoError(t, err)
				require.Equal(t, cppki.Sensitive, ct)
				require.Equal(t, "custom", certs[0].Subject.CommonName)
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			if tc.Prepare != nil {
				tc.Prepare(t)
			}

			cmd := newCreateCmd(command.StringPather("test"))
			cmd.SetArgs(tc.Args)
			err := cmd.Execute()
			tc.ErrAssertion(t, err)
			if tc.Validate != nil {
				certs, _ := cppki.ReadPEMCerts(tc.Args[1])
				tc.Validate(t, certs)
			}
		})
	}
}
