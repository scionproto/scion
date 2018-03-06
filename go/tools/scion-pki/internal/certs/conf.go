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

package certs

import (
	"fmt"
	"time"

	"github.com/go-ini/ini"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

const (
	confFile     = "cert.ini"
	coreConfFile = "core-cert.ini"
)

// conf holds the parameters that are used to create certs.
type certConf struct {
	CanIssue      bool
	Comment       string
	EncAlgorithm  string
	SignAlgorithm string
	Subject       string
	subjectIA     *addr.ISD_AS
	Issuer        string
	issuerIA      *addr.ISD_AS
	IssuingTime   int64
	TRCVersion    uint64
	Version       uint64
	Validity      uint64
}

func (c *certConf) validate() error {
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
	if c.subjectIA, err = addr.IAFromString(c.Subject); err != nil {
		return err
	}
	if c.Issuer == "" || c.Issuer == "0-0" {
		return newValidationError("Issuer")
	}
	if c.issuerIA, err = addr.IAFromString(c.Issuer); err != nil {
		return err
	}
	// FIXME(shitz): Uncomment the version checks as soon as the main code
	// disallows version 0.
	//	if c.TRCVersion == 0 {
	//		return newValidationError("TRCVersion")
	//	}
	//	if c.Version == 0 {
	//		return newValidationError("Version")
	//	}
	if c.Validity == 0 {
		return newValidationError("Validity")
	}
	return nil
}

func newTemplateCertConf(subject *addr.ISD_AS, canIssue bool) *certConf {
	issuer := &addr.ISD_AS{}
	if canIssue {
		issuer = subject
	}
	return &certConf{
		subjectIA:     subject,
		Subject:       subject.String(),
		EncAlgorithm:  "curve25519xsalsa20poly1305",
		SignAlgorithm: "ed25519",
		issuerIA:      issuer,
		Issuer:        issuer.String(),
		CanIssue:      canIssue,
	}
}

func loadCertConf(cname string) (*certConf, error) {
	cfg, err := ini.Load(cname)
	if err != nil {
		return nil, err
	}
	section := cfg.Section("")
	c := &certConf{}
	if err = section.MapTo(c); err != nil {
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
	if err = c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func newValidationError(param string) error {
	return common.NewBasicError(fmt.Sprintf("Parameter '%s' not set.", param), nil)
}

func getConfName(core bool) string {
	if core {
		return coreConfFile
	}
	return confFile
}
