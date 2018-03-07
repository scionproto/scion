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
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/go-ini/ini"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

const (
	AsConfFileName    = "as.ini"
	AsSectionName     = "AS Certificate"
	CoreAsSectionName = "Core AS Certificate"
)

// Cert holds the parameters that are used to create certs.
type Cert struct {
	Comment       string
	EncAlgorithm  string
	SignAlgorithm string
	Subject       string
	SubjectIA     addr.IA `ini:"-"`
	Issuer        string
	IssuerIA      addr.IA `ini:"-"`
	IssuingTime   int64
	TRCVersion    uint64
	Version       uint64
	Validity      uint64
}

func (c *Cert) validate() error {
	if c.EncAlgorithm == "" {
		return newValidationError("EncAlgorithm")
	}
	if c.SignAlgorithm == "" {
		return newValidationError("SignAlgorithm")
	}
	if c.Subject == "" {
		return newValidationError("Subject")
	}
	var err error
	if c.SubjectIA, err = addr.IAFromString(c.Subject); err != nil {
		return err
	}
	if c.Issuer == "" || c.Issuer == "0-0" {
		return newValidationError("Issuer")
	}
	if c.IssuerIA, err = addr.IAFromString(c.Issuer); err != nil {
		return err
	}
	if c.TRCVersion == 0 {
		return newValidationError("TRCVersion")
	}
	if c.Version == 0 {
		return newValidationError("Version")
	}
	if c.Validity == 0 {
		return newValidationError("Validity")
	}
	return nil
}

func NewTemplateCertConf(subject addr.IA, core bool, trcVer uint64) *Cert {
	issuer := addr.IA{}
	if core {
		issuer = subject
	}
	return &Cert{
		SubjectIA:     subject,
		Subject:       subject.String(),
		EncAlgorithm:  "curve25519xsalsa20poly1305",
		SignAlgorithm: "ed25519",
		IssuerIA:      issuer,
		Issuer:        issuer.String(),
		Version:       1,
		TRCVersion:    trcVer,
	}
}

type As struct {
	IsCore bool
	C      *Cert
	CC     *Cert
}

func (a *As) SaveTo(path string, force bool) error {
	// Check if file exists and do not override without -f
	if !force {
		// Check if the file already exists.
		if _, err := os.Stat(path); err == nil {
			fmt.Printf("%s already exists. Use -f to overwrite.\n", path)
			return nil
		}
	}
	iniCfg := ini.Empty()
	if _, err := iniCfg.Section("").NewKey("core", strconv.FormatBool(a.IsCore)); err != nil {
		return err
	}
	if a.C == nil {
		return common.NewBasicError("Empty as.ini", nil)
	}
	asSection, err := iniCfg.NewSection(AsSectionName)
	if err != nil {
		return err
	}
	if err = asSection.ReflectFrom(a.C); err != nil {
		return err
	}
	if a.CC != nil {
		coreSection, err := iniCfg.NewSection(CoreAsSectionName)
		if err != nil {
			return err
		}
		if err = coreSection.ReflectFrom(a.CC); err != nil {
			return err
		}
	}
	if err = iniCfg.SaveTo(path); err != nil {
		return err
	}
	fmt.Println("Successfully written", path)
	return nil
}

func NewTemplateAsConf(subject addr.IA, core bool, trcVer uint64) *As {
	a := &As{IsCore: core}
	a.C = NewTemplateCertConf(subject, false, trcVer)
	if core {
		a.CC = NewTemplateCertConf(subject, true, trcVer)
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
	if cfg.Section("").Haskey("core") {
		as.IsCore, err = cfg.Section("").Key("core").Bool()
		if err != nil {
			return nil, err
		}
	}
	asSection, err := cfg.GetSection(AsSectionName)
	if err != nil {
		return nil, err
	}
	as.C, err = readSection(asSection)
	if err != nil {
		return nil, err
	}
	coreSection, err := cfg.GetSection(CoreAsSectionName)
	if err != nil {
		return as, nil
	}
	as.CC, err = readSection(coreSection)
	if err != nil {
		return nil, err
	}
	return as, nil
}

func readSection(s *ini.Section) (*Cert, error) {
	c := &Cert{}
	if err := s.MapTo(c); err != nil {
		return nil, err
	}
	if c.IssuingTime == 0 {
		c.IssuingTime = time.Now().Unix()
	}
	if c.EncAlgorithm == "" {
		c.EncAlgorithm = "curve25519xalsa20poly1305"
	}
	if c.SignAlgorithm == "" {
		c.SignAlgorithm = "ed25519"
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func newValidationError(param string) error {
	return common.NewBasicError(fmt.Sprintf("Parameter '%s' not set.", param), nil)
}
