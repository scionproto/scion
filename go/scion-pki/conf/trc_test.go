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
	"flag"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/scion-pki/conf"
)

var update = flag.Bool("update", false, "set to true to regenerate certificate files")

func TestUpdateCerts(t *testing.T) {
	if !(*update) {
		t.Skip("Specify -update to update certs")
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
	if *update {
		t.Skip("test crypto is being updated")
	}

	testCases := map[string]struct {
		file      string
		cfg       conf.TRC
		assertErr assert.ErrorAssertionFunc
	}{
		"file not found": {
			file:      "notfound.404",
			assertErr: assert.Error,
		},
		"valid": {
			file:      "testdata/testcfg.toml",
			assertErr: assert.NoError,
			cfg:       *createTRC(t),
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			cfg, err := conf.LoadTRC(tc.file)
			tc.assertErr(t, err)
			assert.Equal(t, tc.cfg, cfg)
		})
	}
}

func TestTRCCertificates(t *testing.T) {
	if *update {
		t.Skip("test crypto is being updated")
	}

	rVoting := loadCert(t, "testdata/regular-voting.crt")
	sVoting := loadCert(t, "testdata/sensitive-voting.crt")
	testCases := map[string]struct {
		prepareCfg   func(*conf.TRC)
		errMsg       string
		expectedCrts []*x509.Certificate
	}{
		"valid": {
			prepareCfg:   func(_ *conf.TRC) {},
			expectedCrts: []*x509.Certificate{rVoting, sVoting},
		},
		"file not found": {
			prepareCfg: func(cfg *conf.TRC) { cfg.CertificateFiles = []string{"notfound"} },
			errMsg:     "no such file or directory file",
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			cfg := createTRC(t)
			tc.prepareCfg(cfg)
			crts, err := cfg.Certificates()
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
