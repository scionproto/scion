// Copyright 2019 Anapaya Systems
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
	"fmt"
	"io"
	"path/filepath"

	"github.com/BurntSushi/toml"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

// ASFile returns the file where the AS certificate config is written to.
func ASFile(dir string, ia addr.IA, version scrypto.Version) string {
	return filepath.Join(pkicmn.GetAsPath(dir, ia), fmt.Sprintf("as-v%d.toml", version))
}

// AllASFiles returns a glob string that matches all AS files for the given IA.
func AllASFiles(dir string, ia addr.IA) string {
	return filepath.Join(pkicmn.GetAsPath(dir, ia), "as-v*.toml")
}

// AS holds the AS certificate configuration.
type AS struct {
	Description          string              `toml:"description"`
	Version              scrypto.Version     `toml:"version"`
	SigningKeyVersion    *scrypto.KeyVersion `toml:"signing_key_version"`
	EncryptionKeyVersion *scrypto.KeyVersion `toml:"encryption_key_version"`
	RevocationKeyVersion *scrypto.KeyVersion `toml:"revocation_key_version"`
	IssuerIA             addr.IA             `toml:"issuer_ia"`
	IssuerCertVersion    scrypto.Version     `toml:"issuer_cert_version"`
	OptDistPoints        []addr.IA           `toml:"optional_distribution_points"`
	Validity             Validity            `toml:"validity"`
}

// LoadAS loads the AS certificate configuration from the provided file. The
// contents are already validated.
func LoadAS(file string) (AS, error) {
	var cfg AS
	if _, err := toml.DecodeFile(file, &cfg); err != nil {
		return AS{}, serrors.WrapStr("unable to load AS certificate config from file", err,
			"file", file)
	}
	if err := cfg.Validate(); err != nil {
		return AS{}, serrors.WrapStr("unable to validate AS certificate config", err, "file", file)
	}
	return cfg, nil
}

// Encode writes the encoded AS certificate config to the writer.
func (cfg AS) Encode(w io.Writer) error {
	if err := toml.NewEncoder(w).Encode(cfg); err != nil {
		return serrors.WrapStr("unable to encode AS certificate config", err)
	}
	return nil
}

// Validate checks all values are set.
func (cfg AS) Validate() error {
	switch {
	case cfg.Description == "":
		return serrors.New("description not set")
	case cfg.Version == scrypto.LatestVer:
		return serrors.New("version not set")
	case cfg.SigningKeyVersion == nil:
		return serrors.New("signing_key_version not set")
	case cfg.EncryptionKeyVersion == nil:
		return serrors.New("encryption_key_version not set")
	case cfg.IssuerIA.IsWildcard():
		return serrors.New("issuer_ia is wildcard", "input", cfg.IssuerIA)
	case cfg.IssuerCertVersion == scrypto.LatestVer:
		return serrors.New("issuer_cert_version not set")
	}
	if err := cfg.Validity.Validate(); err != nil {
		return serrors.WrapStr("invalid validity", err)
	}
	return nil
}
