// Copyright 2018 ETH Zurich, Anapaya Systems
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
	"os"
	"path/filepath"
	"time"

	"github.com/go-ini/ini"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

const ISDCfgFileName = "isd.ini"

const (
	ErrAuthoritativeNotCore              = "authoritative must be core"
	ErrInvalidGracePeriod                = "invalid GracePeriod duration"
	ErrVotingQuorumGreaterThanVotingASes = "VotingQuorun > # Voting ASes"
	ErrVotingQuorumNotSet                = "VotingQuorum not set"
	ErrTrcVersionNotSet                  = "Version not set for TRC"
)

// ISDCfg holds config parameters read from isd.ini.
type ISDCfg struct {
	Desc string `comment:"General description for the ISD"`
	*TRC `ini:"TRC"`
}

// NewTemplateISDCfg creates a new template ISD configuration.
func NewTemplateISDCfg() *ISDCfg {
	i := &ISDCfg{
		TRC: &TRC{
			Version:           1,
			BaseVersion:       1,
			Validity:          180 * 24 * time.Hour,
			TrustResetAllowed: true,
		},
	}
	return i
}

// LoadISDCfg loads the ISD configuration from a directory.
func LoadISDCfg(dir string) (*ISDCfg, error) {
	cname := filepath.Join(dir, ISDCfgFileName)
	cfg, err := ini.Load(cname)
	if err != nil {
		return nil, err
	}
	i := &ISDCfg{}
	if err = cfg.MapTo(i); err != nil {
		return nil, err
	}
	if err = i.TRC.Validate(); err != nil {
		return nil, err
	}
	return i, nil
}

// Write writes the ISD config to the provided path.
func (i *ISDCfg) Write(path string, force bool) error {
	// Check if file exists and do not override without -f
	if !force {
		if _, err := os.Stat(path); err == nil {
			pkicmn.QuietPrint("%s already exists. Use -f to overwrite.\n", path)
			return nil
		}
	}
	i.Update()
	iniCfg := ini.Empty()
	if err := ini.ReflectFrom(iniCfg, i); err != nil {
		return err
	}
	if err := iniCfg.SaveTo(path); err != nil {
		return err
	}
	pkicmn.QuietPrint("Successfully written %s\n", path)
	return nil
}

// TRC holds the parameters that are used to generate a TRC.
type TRC struct {
	Version              uint64        `comment:"The version of the TRC. Must not be 0."`
	BaseVersion          uint64        `comment:"The base version of the TRC. Must not be 0."`
	VotingQuorum         int           `comment:"The number of voting ASes needed to update the TRC"`
	GracePeriod          time.Duration `ini:"-"`
	RawGracePeriod       string        `ini:"GracePeriod" comment:"The grace period for the previous TRC as duration string, e.g., 30m or 6h"`
	TrustResetAllowed    bool          `comment:"Whether trust resets are allowed for this ISD"`
	NotBefore            uint32        `comment:"Time of issuance as UNIX epoch. If 0 will be set to now."`
	Validity             time.Duration `ini:"-"`
	RawValidity          string        `ini:"Validity" comment:"The validity of the certificate as duration string, e.g., 180d or 36h."`
	AuthoritativeASes    []addr.AS     `ini:"-"`
	CoreASes             []addr.AS     `ini:"-"`
	IssuingASes          []addr.AS     `ini:"-"`
	VotingASes           []addr.AS     `ini:"-"`
	RawAuthoritativeASes []string      `ini:"AuthoritativeASes" comment:"The authoritative ASes of this ISD as comma-separated list, e.g., ff00:0:110,ff00:0:120"`
	RawCoreASes          []string      `ini:"CoreASes" comment:"The core ASes of this ISD as comma-separated list, e.g., ff00:0:110,ff00:0:120"`
	RawIssuingASes       []string      `ini:"IssuingASes" comment:"The issuing ASes of this ISD as comma-separated list, e.g., ff00:0:110,ff00:0:120"`
	RawVotingASes        []string      `ini:"VotingASes" comment:"The voting ASes of this ISD as comma-separated list, e.g., ff00:0:110,ff00:0:120"`
}

// Update sets the raw values from the set values.
func (t *TRC) Update() {
	// Make sure raw primaries and parsed primaries are in sync.
	t.setPrimaries()
	// Make sure RawValidity and Validity are in sync.
	t.RawValidity = util.FmtDuration(t.Validity)
	t.RawGracePeriod = util.FmtDuration(t.GracePeriod)
}

func (t *TRC) setPrimaries() {
	t.RawAuthoritativeASes = t.rawASes(t.AuthoritativeASes)
	t.RawCoreASes = t.rawASes(t.CoreASes)
	t.RawIssuingASes = t.rawASes(t.IssuingASes)
	t.RawVotingASes = t.rawASes(t.VotingASes)
}

func (t *TRC) rawASes(ases []addr.AS) []string {
	var raw []string
	for _, as := range ases {
		raw = append(raw, as.String())
	}
	return raw
}

// Validate parses the raw values and validates that the TRC config is correct.
func (t *TRC) Validate() error {
	if err := t.parsePrimaries(); err != nil {
		return err
	}
	if err := t.checkValuesSet(); err != nil {
		return err
	}
	if err := t.checkInvariant(); err != nil {
		return err
	}
	return nil
}

func (t *TRC) parsePrimaries() error {
	var err error
	if t.AuthoritativeASes, err = t.parsePrimary(t.RawAuthoritativeASes); err != nil {
		return common.NewBasicError("invalid AuthoritativeASes", err)
	}
	if t.CoreASes, err = t.parsePrimary(t.RawCoreASes); err != nil {
		return common.NewBasicError("invalid CoreASes", err)
	}
	if t.IssuingASes, err = t.parsePrimary(t.RawIssuingASes); err != nil {
		return common.NewBasicError("invalid IssuingASes", err)
	}
	if t.VotingASes, err = t.parsePrimary(t.RawVotingASes); err != nil {
		return common.NewBasicError("invalid VotingASes", err)
	}
	return nil
}

func (t *TRC) parsePrimary(raw []string) ([]addr.AS, error) {
	var ases []addr.AS
	if len(raw) == 0 {
		return nil, common.NewBasicError("section not set", nil)
	}
	for _, raw := range raw {
		as, err := addr.ASFromString(raw)
		if err != nil {
			return nil, err
		}
		if as == 0 {
			return nil, common.NewBasicError("invalid AS", nil, "as", as)
		}
		ases = append(ases, as)
	}
	return ases, nil
}

func (t *TRC) checkValuesSet() error {
	if t.Version == 0 {
		return common.NewBasicError(ErrTrcVersionNotSet, nil)
	}
	if t.BaseVersion != t.Version {
		return common.NewBasicError("only base TRCs supported currently", nil)
	}
	if t.VotingQuorum == 0 {
		return common.NewBasicError(ErrVotingQuorumNotSet, nil)
	}
	if t.RawGracePeriod == "" {
		t.RawGracePeriod = "0s"
	}
	var err error
	t.GracePeriod, err = util.ParseDuration(t.RawGracePeriod)
	if err != nil {
		return common.NewBasicError(ErrInvalidGracePeriod, nil, "duration", t.RawGracePeriod)
	}
	if err := parseValidity(&t.NotBefore, &t.Validity, t.RawValidity); err != nil {
		return err
	}
	return nil
}

func (t *TRC) checkInvariant() error {
	if int(t.VotingQuorum) > len(t.VotingASes) {
		return common.NewBasicError(ErrVotingQuorumGreaterThanVotingASes, nil,
			"quorum", t.VotingQuorum, "voting", t.VotingASes)
	}
	for _, as := range t.AuthoritativeASes {
		if !pkicmn.ContainsAS(t.CoreASes, as) {
			return common.NewBasicError(ErrAuthoritativeNotCore, nil, "as", as)
		}
	}
	if t.Version == t.BaseVersion && t.GracePeriod != 0 {
		return common.NewBasicError(ErrInvalidGracePeriod, nil,
			"reason", "must be zero for base TRC")
	}
	if t.Version != t.BaseVersion && t.GracePeriod == 0 {
		return common.NewBasicError(ErrInvalidGracePeriod, nil,
			"reason", "must not be zero for non-base TRC")
	}
	return nil
}
