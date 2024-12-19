// Copyright 2020 Anapaya Systems
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

package conf_test

import (
	"crypto/x509"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/scion-pki/conf"
)

var updateNonDeterministic = xtest.UpdateNonDeterminsticGoldenFiles()

func TestUpdateCerts(t *testing.T) {
	if !(*updateNonDeterministic) {
		t.Skip("Specify -update-non-deterministic to update certs")
		return
	}
	dir, cleanF := xtest.MustTempDir("", "safedir")
	defer cleanF()

	cmd := exec.Command("sh", "-c", "./testdata/update_certs.sh")
	cmd.Env = []string{
		"SAFEDIR=" + dir,
		"STARTDATE=20200624120000Z",
		"ENDDATE=20250624120000Z",
	}
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	for _, cert := range []string{"regular-voting.crt", "sensitive-voting.crt"} {
		out, err := exec.Command("mv", filepath.Join(dir, cert),
			filepath.Join("./testdata", cert)).CombinedOutput()
		require.NoError(t, err, string(out))
	}
}

func TestLoadTRC(t *testing.T) {
	if *updateNonDeterministic {
		t.Skip("test crypto is being updated")
	}

	testCases := map[string]struct {
		file      string
		cfg       conf.TRC
		assertErr assert.ErrorAssertionFunc
		check     func(*conf.TRC)
	}{
		"file not found": {
			file:      "notfound.404",
			assertErr: assert.Error,
		},
		"valid": {
			file:      "testdata/testcfg.toml",
			assertErr: assert.NoError,
			check: func(cfg *conf.TRC) {
				assert.Equal(t, createTRC(t), cfg)
				assert.True(t, cfg.Validity.NotBefore.Time().IsZero())
			},
		},
		"unix": {
			file:      "testdata/testcfg.unix.toml",
			assertErr: assert.NoError,
			check: func(cfg *conf.TRC) {
				assert.Equal(t, int64(1719223994), cfg.Validity.NotBefore.Time().Unix())
			},
		},
		"rfc3339": {
			file:      "testdata/testcfg.rfc3339.toml",
			assertErr: assert.NoError,
			check: func(cfg *conf.TRC) {
				assert.Equal(t, int64(1719223994), cfg.Validity.NotBefore.Time().Unix())
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			cfg, err := conf.LoadTRC(tc.file)
			tc.assertErr(t, err)
			if tc.check != nil {
				tc.check(&cfg)
			}
		})
	}
}

func TestTRCCertificates(t *testing.T) {
	if *updateNonDeterministic {
		t.Skip("test crypto is being updated")
	}

	rVoting := loadCert(t, "testdata/regular-voting.crt")
	sVoting := loadCert(t, "testdata/sensitive-voting.crt")
	testCases := map[string]struct {
		prepareCfg   func(*conf.TRC)
		errMsg       string
		expectedCrts []*x509.Certificate
		pred         *cppki.TRC
	}{
		"valid": {
			prepareCfg:   func(_ *conf.TRC) {},
			expectedCrts: []*x509.Certificate{rVoting, sVoting},
		},
		"load from predecessor": {
			prepareCfg: func(cfg *conf.TRC) {
				cfg.CertificateFiles[0] = "predecessor:4"
			},
			expectedCrts: []*x509.Certificate{rVoting, sVoting},
			pred: &cppki.TRC{
				Certificates: []*x509.Certificate{4: rVoting},
			},
		},
		"file not found": {
			prepareCfg: func(cfg *conf.TRC) { cfg.CertificateFiles = []string{"notfound"} },
			errMsg:     "no such file or directory",
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			cfg := createTRC(t)
			tc.prepareCfg(cfg)
			crts, err := cfg.Certificates(tc.pred)
			if tc.errMsg != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errMsg)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.expectedCrts, crts)
		})
	}
}

func createTRC(t *testing.T) *conf.TRC {
	cfg, err := conf.LoadTRC("testdata/testcfg.toml")
	require.NoError(t, err)
	return &cfg
}

func loadCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	certs, err := cppki.ReadPEMCerts(path)
	require.NoError(t, err, "file: %s", path)
	require.Len(t, certs, 1, "file: %s", path)
	return certs[0]
}
