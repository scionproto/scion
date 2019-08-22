// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

const (
	ErrASCertMissing            = "AS Certificate section missing"
	ErrInvalidValidityDuration  = "invalid validity duration"
	ErrIssuerMissing            = "issuer not set in AS certificate"
	ErrInvalidIssuer            = "issuer is not valid"
	ErrInvalidIssuerCertVersion = "issuer certificate version must not be zero"
	ErrInvalidIssuerTRCVersion  = "TRC version must not be zero"
	ErrInvalidOptDistPoint      = "invalid optional distribution point"
	ErrValidityDurationNotSet   = "validity duration not set"
	ErrVersionNotSet            = "version not set for certificate"
	ErrInvalidSignAlgorithm     = "invalid signature algorithm"
	ErrInvalidEncAlgorithm      = "invalid encryption algorithm"
)

const (
	ASConfFileName    = "as.ini"
	KeyAlgSectionName = "Key Algorithms"
	ASSectionName     = "AS Certificate"
	IssuerSectionName = "Issuer Certificate"
)

var (
	defaultSignAlgorithm = scrypto.Ed25519
	defaultEncAlgorithm  = scrypto.Curve25519xSalsa20Poly1305

	validSignAlgorithms = []string{defaultSignAlgorithm}
	validEncAlgorithms  = []string{defaultEncAlgorithm}
)

// ASCfg contains the as.ini configuration parameters.
type ASCfg struct {
	*AS                   `ini:"AS Certificate"`
	*Issuer               `ini:"Issuer Certificate,omitempty"`
	*PrimaryKeyAlgorithms `ini:"Key Algorithms,omitempty"`
}

// NewTemplateASCfg creates a new template AS configuration.
func NewTemplateASCfg(subject addr.IA, trcVer uint64, voting, issuing bool) *ASCfg {
	a := &ASCfg{}
	a.AS = &AS{
		BaseCert: &BaseCert{
			Version:     1,
			Description: "AS certificate",
			Validity:    24 * 3 * time.Hour,
		},
		EncAlgorithm:      defaultEncAlgorithm,
		SignAlgorithm:     defaultSignAlgorithm,
		IssuerIA:          addr.IA{},
		IssuerCertVersion: 1,
	}
	if issuing {
		a.Issuer = &Issuer{
			BaseCert: &BaseCert{
				Version:     1,
				Description: "Issuer certificate",
				Validity:    24 * 7 * time.Hour,
			},
			IssuingAlgorithm: defaultSignAlgorithm,
			TRCVersion:       trcVer,
		}
		a.AS.IssuerIA = subject
	}
	if issuing || voting {
		a.PrimaryKeyAlgorithms = &PrimaryKeyAlgorithms{}
		if issuing {
			a.PrimaryKeyAlgorithms.Issuing = defaultSignAlgorithm
		}
		if voting {
			a.PrimaryKeyAlgorithms.Online = defaultSignAlgorithm
			a.PrimaryKeyAlgorithms.Offline = defaultSignAlgorithm
		}
	}
	return a
}

// LoadASCfg loads the AS configuration from a directory.
func LoadASCfg(dir string) (*ASCfg, error) {
	cname := filepath.Join(dir, ASConfFileName)
	cfg, err := ini.Load(cname)
	if err != nil {
		return nil, err
	}
	as := &ASCfg{}
	if err := cfg.MapTo(as); err != nil {
		return nil, err
	}
	if err := as.Validate(); err != nil {
		return nil, err
	}
	return as, nil
}

// Validate parses the raw values and validates that the AS config is correct.
func (a *ASCfg) Validate() error {
	if a.AS == nil {
		return common.NewBasicError(ErrASCertMissing, nil)
	}
	if err := a.AS.validate(); err != nil {
		return err
	}
	if err := a.Issuer.validate(); err != nil {
		return err
	}
	if a.PrimaryKeyAlgorithms != nil {
		return a.PrimaryKeyAlgorithms.validate()
	}
	return nil
}

// Write writes the AS config to the provided path.
func (a *ASCfg) Write(path string, force bool) error {
	// Check if file exists and do not override without -f
	if !force {
		// Check if the file already exists.
		if _, err := os.Stat(path); err == nil {
			pkicmn.QuietPrint("%s already exists. Use -f to overwrite.\n", path)
			return nil
		}
	}
	a.Update()
	iniCfg := ini.Empty()
	if err := iniCfg.ReflectFrom(a); err != nil {
		return err
	}
	if err := iniCfg.SaveTo(path); err != nil {
		return err
	}
	pkicmn.QuietPrint("Successfully written %s\n", path)
	return nil
}

// Update sets the raw values from the set values.
func (a *ASCfg) Update() {
	a.AS.set()
	if a.Issuer != nil {
		a.Issuer.set()
	}
}

// AS corresponds to the "As Certificate" section.
type AS struct {
	*BaseCert         `ini:"AS Certificate"`
	EncAlgorithm      string  `comment:"Encryption algorithm used by AS, e.g., curve25519xsalsa20poly1305"`
	SignAlgorithm     string  `comment:"Signing algorithm used by AS, e.g., ed25519"`
	RawIssuerIA       string  `ini:"IssuerIA" comment:"The issuer IA."`
	IssuerIA          addr.IA `ini:"-"`
	IssuerCertVersion uint64  `comment:"The certificate version of the issuer certificate"`
}

func (c *AS) validate() error {
	if err := defaultAndValidateEncAlgorithm(&c.EncAlgorithm); err != nil {
		return err
	}
	if err := defaultAndValidateSignAlgorithm(&c.SignAlgorithm); err != nil {
		return common.NewBasicError("invalid SignAlgorithm", err)
	}
	if c.RawIssuerIA == "" {
		return common.NewBasicError(ErrIssuerMissing, nil)
	}
	var err error
	c.IssuerIA, err = addr.IAFromString(c.RawIssuerIA)
	if err != nil || c.IssuerIA.IsWildcard() {
		return common.NewBasicError(ErrInvalidIssuer, err, "ia", c.RawIssuerIA)
	}
	if c.IssuerCertVersion == 0 {
		return common.NewBasicError(ErrInvalidIssuerCertVersion, nil)
	}
	if err := c.BaseCert.validate(); err != nil {
		return err
	}
	return nil
}

func (c *AS) set() {
	c.RawIssuerIA = c.IssuerIA.String()
	c.BaseCert.set()
}

// Issuer corresponds to the "Issuer Certificate" section.
type Issuer struct {
	*BaseCert        `ini:"Issuer Certificate"`
	IssuingAlgorithm string `comment:"Issuing algorithm used by AS, e.g., ed25519"`
	TRCVersion       uint64 `comment:"The version of the current TRC"`
}

func (c *Issuer) validate() error {
	if c.isZero() {
		return nil
	}
	if err := defaultAndValidateSignAlgorithm(&c.IssuingAlgorithm); err != nil {
		return common.NewBasicError("invalid IssuingAlgorithm", err)
	}
	if c.TRCVersion == 0 {
		return common.NewBasicError(ErrInvalidIssuerTRCVersion, nil)
	}
	if err := c.BaseCert.validate(); err != nil {
		return err
	}
	return nil

}

func (c *Issuer) isZero() bool {
	return c == nil || *c == Issuer{}
}

// BaseCert holds the shared parameters that are used to create certs.
type BaseCert struct {
	Version                    uint64        `comment:"The version of the certificate. Cannot be 0"`
	Description                string        `comment:"Description of the AS and certificate"`
	OptionalDistributionPoints []addr.IA     `ini:"-"`
	RawOptDistPoints           []string      `ini:"OptionalDistributionPoints" comment:"List of optional revocation distribution points."`
	NotBefore                  uint32        `comment:"Time of issuance as UNIX epoch. If 0 will be set to now."`
	Validity                   time.Duration `ini:"-"`
	RawValidity                string        `ini:"Validity" comment:"The validity of the certificate as duration string, e.g., 180d or 36h"`
	RevAlgorithm               string        `comment:"Revocation algorithm used by AS, e.g., ed25519. If empty, no revocation key is generated."`
}

func (c *BaseCert) validate() error {
	if c.Version == 0 {
		return common.NewBasicError(ErrVersionNotSet, nil)
	}
	for _, raw := range c.RawOptDistPoints {
		ia, err := addr.IAFromString(raw)
		if err != nil || ia.IsWildcard() {
			return common.NewBasicError(ErrInvalidOptDistPoint, nil, "ia", ia)
		}
		c.OptionalDistributionPoints = append(c.OptionalDistributionPoints, ia)
	}
	if err := parseValidity(&c.NotBefore, &c.Validity, c.RawValidity); err != nil {
		return err
	}
	if c.RevAlgorithm != "" {
		if err := defaultAndValidateSignAlgorithm(&c.RevAlgorithm); err != nil {
			return common.NewBasicError("invalid RevAlgorithm", err)
		}
	}
	return nil
}

func (c *BaseCert) set() {
	c.RawOptDistPoints = nil
	for _, ia := range c.OptionalDistributionPoints {
		c.RawOptDistPoints = append(c.RawOptDistPoints, ia.String())
	}
	c.RawValidity = util.FmtDuration(c.Validity)
}

// PrimaryKeyAlgorithms holds the algorithms for the keys for a primary AS.
type PrimaryKeyAlgorithms struct {
	Online  string `ini:"Online,omitempty" comment:"Signing algorithm used by Online Key, e.g., ed25519"`
	Offline string `ini:"Offline,omitempty" comment:"Signing algorithm used by Offline Key, e.g., ed25519"`
	Issuing string `ini:"Issuing,omitempty" comment:"Signing algorithm used by Issuing Key, e.g., ed25519"`
}

func (k *PrimaryKeyAlgorithms) validate() error {
	if err := defaultAndValidateSignAlgorithm(&k.Online); err != nil {
		return err
	}
	if err := defaultAndValidateSignAlgorithm(&k.Offline); err != nil {
		return err
	}
	if err := defaultAndValidateSignAlgorithm(&k.Issuing); err != nil {
		return err
	}
	return nil
}

func defaultAndValidateSignAlgorithm(algo *string) error {
	if *algo == "" {
		*algo = defaultSignAlgorithm
	}
	return validateAlgorithm(*algo, validSignAlgorithms, ErrInvalidSignAlgorithm)

}

func defaultAndValidateEncAlgorithm(algo *string) error {
	if *algo == "" {
		*algo = defaultEncAlgorithm
	}
	return validateAlgorithm(*algo, validEncAlgorithms, ErrInvalidEncAlgorithm)
}

func validateAlgorithm(algorithm string, valid []string, errMsg string) error {
	for _, a := range valid {
		if a == algorithm {
			return nil
		}
	}
	return common.NewBasicError(errMsg, nil, "algorithm", algorithm)
}

func parseValidity(notBefore *uint32, validity *time.Duration, raw string) error {
	if *notBefore == 0 {
		*notBefore = util.TimeToSecs(time.Now())
	}
	if raw == "" {
		raw = "0s"
	}
	var err error
	*validity, err = util.ParseDuration(raw)
	if err != nil {
		return common.NewBasicError(ErrInvalidValidityDuration, nil, "duration", raw)
	}
	if int64(*validity) == 0 {
		return common.NewBasicError(ErrValidityDurationNotSet, nil)
	}
	return nil
}
