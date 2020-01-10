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
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

// TRCFile returns the file where the TRC config is written to.
func TRCFile(dir string, isd addr.ISD, version scrypto.Version) string {
	return filepath.Join(pkicmn.GetIsdPath(dir, isd), fmt.Sprintf("trc-v%d.toml", version))
}

// AllTRCFiles returns a glob string that matches all TRC files for the given isd.
func AllTRCFiles(dir string, isd addr.ISD) string {
	return filepath.Join(pkicmn.GetIsdPath(dir, isd), "trc-v*.toml")
}

// TRC holds the TRC configuration.
type TRC struct {
	Description       string
	Version           scrypto.Version
	BaseVersion       scrypto.Version
	VotingQuorum      uint16
	GracePeriod       util.DurWrap
	TrustResetAllowed *bool
	Votes             []addr.AS
	Validity          Validity
	PrimaryASes       map[addr.AS]Primary
}

// LoadTRC loads the TRC configuration from the provided file. The contents are already validated.
func LoadTRC(file string) (TRC, error) {
	var t tomlTRC
	if _, err := toml.DecodeFile(file, &t); err != nil {
		return TRC{}, serrors.WrapStr("unable to load TRC config from file", err, "file", file)
	}
	cfg, err := t.TRC()
	if err != nil {
		return TRC{}, serrors.WithCtx(err, "file", file)
	}
	if err := cfg.Validate(); err != nil {
		return TRC{}, serrors.WrapStr("unable to validate TRC config", err, "file", file)
	}
	return cfg, nil
}

// Encode writes the encoded TRC config to the writer.
func (cfg TRC) Encode(w io.Writer) error {
	t := tomlTRCFromTRC(cfg)
	if err := toml.NewEncoder(w).Encode(t); err != nil {
		return serrors.WrapStr("unable to encode TRC config", err)
	}
	return nil
}

// Validate checks all values are set.
func (cfg TRC) Validate() error {
	switch {
	case cfg.Description == "":
		return serrors.New("description is not set")
	case cfg.Version == scrypto.LatestVer:
		return serrors.New("version not set")
	case cfg.BaseVersion == scrypto.LatestVer:
		return serrors.New("base_version not set")
	case cfg.VotingQuorum == 0:
		return serrors.New("voting_quorum not set")
	case cfg.TrustResetAllowed == nil:
		return serrors.New("trust_reset_allowed not set")
	case cfg.BaseVersion != cfg.Version && len(cfg.Votes) == 0:
		return serrors.New("votes not set")
	case cfg.BaseVersion == cfg.Version && len(cfg.Votes) != 0:
		return serrors.New("votes set in base TRC")
	}
	if err := cfg.Validity.Validate(); err != nil {
		return serrors.WrapStr("invalid validity", err)
	}
	if cfg.GracePeriod.Duration == 0 && cfg.Version != cfg.BaseVersion {
		return serrors.New("grace_period zero")
	} else if cfg.GracePeriod.Duration != 0 && cfg.Version == cfg.BaseVersion {
		return serrors.New("grace_period non-zero")
	}
	for as, primary := range cfg.PrimaryASes {
		if err := primary.Validate(); err != nil {
			return serrors.WrapStr("invalid primary_ases entry", err, "as", as)
		}
	}
	return nil
}

// Primary holds the primary AS configuration.
type Primary struct {
	Attributes              trc.Attributes      `toml:"attributes"`
	IssuingGrantKeyVersion  *scrypto.KeyVersion `toml:"issuing_grant_key_version"`
	VotingOnlineKeyVersion  *scrypto.KeyVersion `toml:"voting_online_key_version"`
	VotingOfflineKeyVersion *scrypto.KeyVersion `toml:"voting_offline_key_version"`
}

// Validate checks the right keys are set.
func (p Primary) Validate() error {
	for _, attr := range p.Attributes {
		switch attr {
		case trc.Core, trc.Authoritative:
		case trc.Issuing:
			if p.IssuingGrantKeyVersion == nil {
				return serrors.New("issuing_grant_key_version not set")
			}
		case trc.Voting:
			if p.VotingOnlineKeyVersion == nil {
				return serrors.New("voting_online_key_version not set")
			}
			if p.VotingOfflineKeyVersion == nil {
				return serrors.New("voting_offline_key_version not set")
			}
		default:
			return serrors.New("unknown attribute", "value", attr)
		}
	}
	return nil
}

type tomlTRC struct {
	Description       string             `toml:"description"`
	Version           scrypto.Version    `toml:"version"`
	BaseVersion       scrypto.Version    `toml:"base_version"`
	VotingQuorum      uint16             `toml:"voting_quorum"`
	GracePeriod       util.DurWrap       `toml:"grace_period"`
	TrustResetAllowed *bool              `toml:"trust_reset_allowed"`
	Votes             []addr.AS          `toml:"votes"`
	Validity          Validity           `toml:"validity"`
	PrimaryASes       map[string]Primary `toml:"primary_ases"`
}

func (t tomlTRC) TRC() (TRC, error) {
	cfg := TRC{
		Description:       t.Description,
		Version:           t.Version,
		BaseVersion:       t.BaseVersion,
		VotingQuorum:      t.VotingQuorum,
		GracePeriod:       t.GracePeriod,
		TrustResetAllowed: t.TrustResetAllowed,
		Votes:             t.Votes,
		Validity:          t.Validity,
		PrimaryASes:       make(map[addr.AS]Primary),
	}
	for raw, primary := range t.PrimaryASes {
		as, err := addr.ASFromString(raw)
		if err != nil {
			return TRC{}, serrors.WrapStr("unable to parse AS number", err, "input", raw)
		}
		cfg.PrimaryASes[as] = primary
	}
	return cfg, nil
}

func tomlTRCFromTRC(cfg TRC) tomlTRC {
	t := tomlTRC{
		Description:       cfg.Description,
		Version:           cfg.Version,
		BaseVersion:       cfg.BaseVersion,
		VotingQuorum:      cfg.VotingQuorum,
		GracePeriod:       cfg.GracePeriod,
		TrustResetAllowed: cfg.TrustResetAllowed,
		Votes:             cfg.Votes,
		Validity:          cfg.Validity,
		PrimaryASes:       make(map[string]Primary),
	}
	for as, primary := range cfg.PrimaryASes {
		t.PrimaryASes[as.String()] = primary
	}
	return t
}
