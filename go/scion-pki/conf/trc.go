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

package conf

import (
	"crypto/x509"
	"path/filepath"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
)

// TRC holds the TRC configuration.
type TRC struct {
	ISD               addr.ISD        `toml:"isd"`
	Description       string          `toml:"description"`
	SerialVersion     scrypto.Version `toml:"serial_version"`
	BaseVersion       scrypto.Version `toml:"base_version"`
	VotingQuorum      uint8           `toml:"voting_quorum"`
	GracePeriod       util.DurWrap    `toml:"grace_period"`
	NoTrustReset      bool            `toml:"no_trust_reset"`
	Validity          Validity        `toml:"validity"`
	CoreASes          []addr.AS       `toml:"core_ases"`
	AuthoritativeASes []addr.AS       `toml:"authoritative_ases"`
	CertificateFiles  []string        `toml:"cert_files"`
	Votes             []int           `toml:"votes"`

	relPath string
}

// LoadTRC loads the TRC configuration from the provided file. The contents are already validated.
func LoadTRC(file string) (TRC, error) {
	var cfg TRC
	if err := config.LoadFile(file, &cfg); err != nil {
		return TRC{}, serrors.WrapStr("unable to load TRC config from file", err, "file", file)
	}
	cfg.relPath = filepath.Dir(file)
	return cfg, nil
}

// Certificates returns the specified certificates.
func (cfg *TRC) Certificates() ([]*x509.Certificate, error) {
	if len(cfg.CertificateFiles) == 0 {
		return nil, serrors.New("no cert_files specified")
	}
	certs := make([]*x509.Certificate, 0, len(cfg.CertificateFiles))
	for _, certFile := range cfg.CertificateFiles {
		if !strings.HasPrefix(certFile, "/") {
			certFile = filepath.Join(cfg.relPath, certFile)
		}
		read, err := cppki.ReadPEMCerts(certFile)
		if err != nil {
			return nil, serrors.WithCtx(err, "file", certFile)
		}
		for _, cert := range read {
			ct, err := cppki.ValidateCert(cert)
			if err != nil {
				return nil, serrors.WithCtx(err, "file", certFile)
			}
			if ct != cppki.Sensitive && ct != cppki.Regular && ct != cppki.Root {
				return nil, serrors.New("invalid certificate type", "file", certFile)
			}
		}
		certs = append(certs, read...)
	}
	return certs, nil
}
