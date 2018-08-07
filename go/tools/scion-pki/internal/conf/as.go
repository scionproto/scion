// Copyright 2018 ETH Zurich
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
	ErrAsCertMissing           = "AS Certificate section missing"
	ErrInvalidValidityDuration = "Invalid validity duration"
	ErrIssuerMissing           = "Parameter Issuer not set in AS certificate"
	ErrTRCVersionNotSet        = "Parameter TRCVersion not set in Base Certificate"
	ErrValidityDurationNotSet  = "Validity duration not set"
	ErrVersionNotSet           = "Parameter Version not set for Base Certificate"
	ErrInvalidSignAlgorithm    = "Invalid sign algorithm"
	ErrInvalidEncAlgorithm     = "Invalid encryption algorithm"
)

const (
	AsConfFileName    = "as.ini"
	KeyAlgSectionName = "Key Algorithms"
	AsSectionName     = "AS Certificate"
	IssuerSectionName = "Issuer Certificate"
)

var (
	validSignAlgorithms = []string{scrypto.Ed25519}
	validEncAlgorithms  = []string{scrypto.Curve25519xSalsa20Poly1305}
)

// As contains the as.ini configuration parameters.
type As struct {
	*AsCert        `ini:"AS Certificate"`
	*IssuerCert    `ini:"Issuer Certificate,omitempty"`
	*KeyAlgorithms `ini:"Key Algorithms,omitempty"`
}

func (a *As) validate() error {
	if a.AsCert == nil {
		return common.NewBasicError(ErrAsCertMissing, nil)
	}
	if err := a.AsCert.validate(); err != nil {
		return err
	}
	if a.IssuerCert != nil && a.IssuerCert.BaseCert != nil {
		if err := a.IssuerCert.validate(); err != nil {
			return err
		}
	}
	if a.KeyAlgorithms != nil {
		return a.KeyAlgorithms.validate()
	}
	return nil
}

func (a *As) Write(path string, force bool) error {
	// Check if file exists and do not override without -f
	if !force {
		// Check if the file already exists.
		if _, err := os.Stat(path); err == nil {
			pkicmn.QuietPrint("%s already exists. Use -f to overwrite.\n", path)
			return nil
		}
	}
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

func NewTemplateAsConf(subject addr.IA, trcVer uint64, core bool) *As {
	a := &As{}
	bc := NewTemplateCertConf(trcVer)
	a.AsCert = &AsCert{
		Issuer:   "0-0",
		BaseCert: bc,
	}

	if core {
		ibc := NewTemplateCertConf(trcVer)
		a.IssuerCert = &IssuerCert{
			BaseCert: ibc,
		}
		a.AsCert.Issuer = subject.String()
		a.KeyAlgorithms = &KeyAlgorithms{
			Online:  scrypto.Ed25519,
			Offline: scrypto.Ed25519,
		}
	}
	return a
}

func LoadAsConf(dir string) (*As, error) {
	cname := filepath.Join(dir, AsConfFileName)
	cfg, err := ini.Load(cname)
	if err != nil {
		return nil, err
	}
	as := &As{}
	if err := cfg.MapTo(as); err != nil {
		return nil, err
	}
	if err := as.validate(); err != nil {
		return nil, err
	}
	return as, nil
}

// AsCert corresponds to the "As Certificate" section.
type AsCert struct {
	Issuer    string
	IssuerIA  addr.IA `ini:"-"`
	*BaseCert `ini:"AS Certificate"`
}

func (ac *AsCert) validate() error {
	if ac.Issuer == "" || ac.Issuer == "0-0" {
		return common.NewBasicError(ErrIssuerMissing, nil)
	}
	var err error
	if ac.IssuerIA, err = addr.IAFromString(ac.Issuer); err != nil {
		return err
	}
	if ac.BaseCert == nil {
		panic("ac.BaseCert is nil")
	}
	return ac.BaseCert.validate()
}

// IssuerCert corresponds to the "Issuer Certificate" section.
type IssuerCert struct {
	*BaseCert `ini:"Issuer Certificate"`
}

// BaseCert holds the parameters that are used to create certs.
type BaseCert struct {
	Comment       string        `comment:"Description of the AS and certificate"`
	EncAlgorithm  string        `comment:"Encryption algorithm used by AS, e.g., curve25519xsalsa20poly1305"`
	SignAlgorithm string        `comment:"Signing algotirhm used by AS, e.g., ed25519"`
	IssuingTime   uint32        `comment:"Time of issuance as UNIX epoch. If 0 will be set to now."`
	TRCVersion    uint64        `comment:"The version of the current TRC"`
	Version       uint64        `comment:"The version of the certificate. Cannot be 0"`
	Validity      time.Duration `ini:"-"`
	RawValidity   string        `ini:"Validity" comment:"The validity of the certificate as duration string, e.g., 180d or 36h"`
}

// KeyAlgorithms corresponds to the "Key Algorithms" section
type KeyAlgorithms struct {
	Online  string `comment:"Signing algorithm used by Online Key, e.g., ed25519"`
	Offline string `comment:"Signing algorithm used by Offline Key, e.g., ed25519"`
}

func (c *BaseCert) validate() error {
	if c.EncAlgorithm == "" {
		c.EncAlgorithm = scrypto.Curve25519xSalsa20Poly1305
	}
	if err := validateEncAlgorithm(c.EncAlgorithm); err != nil {
		return err
	}
	if c.SignAlgorithm == "" {
		c.SignAlgorithm = scrypto.Ed25519
	}
	if err := validateSignAlgorithm(c.SignAlgorithm); err != nil {
		return err
	}
	if c.TRCVersion == 0 {
		return common.NewBasicError(ErrTRCVersionNotSet, nil)
	}
	if c.Version == 0 {
		return common.NewBasicError(ErrVersionNotSet, nil)
	}
	if c.RawValidity == "" {
		c.RawValidity = "0s"
	}
	var err error
	c.Validity, err = util.ParseDuration(c.RawValidity)
	if err != nil {
		return common.NewBasicError(ErrInvalidValidityDuration, nil, "duration", c.RawValidity)
	}
	if int64(c.Validity) == 0 {
		return common.NewBasicError(ErrValidityDurationNotSet, nil)
	}
	return nil
}

func (ka *KeyAlgorithms) validate() error {
	if ka.Online == "" {
		ka.Online = scrypto.Ed25519
	}
	if err := validateSignAlgorithm(ka.Online); err != nil {
		return err
	}
	if ka.Offline == "" {
		ka.Offline = scrypto.Ed25519
	}
	return validateSignAlgorithm(ka.Offline)
}

func validateSignAlgorithm(algorithm string) error {
	return validateAlgorithm(algorithm, validSignAlgorithms, ErrInvalidSignAlgorithm)

}

func validateEncAlgorithm(algorithm string) error {
	return validateAlgorithm(algorithm, validEncAlgorithms, ErrInvalidEncAlgorithm)
}

func validateAlgorithm(algorithm string, valid []string, errMsg string) error {
	for _, a := range valid {
		if a == algorithm {
			return nil
		}
	}
	return common.NewBasicError(errMsg, nil, "algorithm", algorithm)
}

func NewTemplateCertConf(trcVer uint64) *BaseCert {
	return &BaseCert{
		EncAlgorithm:  scrypto.Curve25519xSalsa20Poly1305,
		SignAlgorithm: scrypto.Ed25519,
		Version:       1,
		TRCVersion:    trcVer,
	}
}
