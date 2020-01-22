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

// IssuerFile returns the file where the issuer certificate config is written to.
func IssuerFile(dir string, ia addr.IA, version scrypto.Version) string {
	return filepath.Join(pkicmn.GetAsPath(dir, ia), fmt.Sprintf("issuer-v%d.toml", version))
}

// AllIssuerFiles returns a glob string that matches all issuer files for the given IA.
func AllIssuerFiles(dir string, ia addr.IA) string {
	return filepath.Join(pkicmn.GetAsPath(dir, ia), "issuer-v*.toml")
}

// Issuer holds the issuer certificate configuration.
type Issuer struct {
	Description            string              `toml:"description"`
	Version                scrypto.Version     `toml:"version"`
	IssuingGrantKeyVersion *scrypto.KeyVersion `toml:"issuing_grant_key_version"`
	RevocationKeyVersion   *scrypto.KeyVersion `toml:"revocation_key_version"`
	TRCVersion             scrypto.Version     `toml:"trc_version"`
	OptDistPoints          []addr.IA           `toml:"optional_distribution_points"`
	Validity               Validity            `toml:"validity"`
}

// LoadIssuer loads the issuer certificate configuration from the provided file.
// The contents are already validated.
func LoadIssuer(file string) (Issuer, error) {
	var cfg Issuer
	if _, err := toml.DecodeFile(file, &cfg); err != nil {
		return Issuer{}, serrors.WrapStr("unable to load issuer certificate config from file", err,
			"file", file)
	}
	if err := cfg.Validate(); err != nil {
		return Issuer{}, serrors.WrapStr("unable to validate issuer certificate config", err,
			"file", file)
	}
	return cfg, nil
}

// Encode writes the encoded issuer certificate config to the writer.
func (cfg Issuer) Encode(w io.Writer) error {
	if err := toml.NewEncoder(w).Encode(cfg); err != nil {
		return serrors.WrapStr("unable to encode issuer certificate config", err)
	}
	return nil
}

// Validate checks all values are set.
func (cfg Issuer) Validate() error {
	switch {
	case cfg.Description == "":
		return serrors.New("description not set")
	case cfg.Version == scrypto.LatestVer:
		return serrors.New("version not set")
	case cfg.IssuingGrantKeyVersion == nil:
		return serrors.New("issuing_grant_key_version not set")
	case cfg.TRCVersion == scrypto.LatestVer:
		return serrors.New("trc_version not set")
	}
	if err := cfg.Validity.Validate(); err != nil {
		return serrors.WrapStr("invalid validity", err)
	}
	return nil
}
