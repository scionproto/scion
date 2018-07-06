// Copyright 2017 ETH Zurich
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

// Go implementation of the certificate.
// To create JSON strings, either json.Marshal or json.MarshalIndent

package cert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto"
	"github.com/scionproto/scion/go/lib/util"
)

const (
	EarlyUsage      = "Certificate IssuingTime in the future"
	Expired         = "Certificate expired"
	InvalidSubject  = "Invalid subject"
	ReservedVersion = "Invalid version 0"
	UnableSigPack   = "Cert: Unable to create signature input"
)

const (
	canIssue       = "CanIssue"
	comment        = "Comment"
	encAlgorithm   = "EncAlgorithm"
	expirationTime = "ExpirationTime"
	issuer         = "Issuer"
	issuingTime    = "IssuingTime"
	signAlgorithm  = "SignAlgorithm"
	signature      = "Signature"
	subject        = "Subject"
	subjectEncKey  = "SubjectEncKey"
	subjectSignKey = "SubjectSignKey"
	trcVersion     = "TRCVersion"
	version        = "Version"
)

type Certificate struct {
	// CanIssue describes whether the subject is able to issue certificates.
	CanIssue bool
	// Comment is an arbitrary and optional string used by the subject to describe the certificate.
	Comment string
	// EncAlgorithm is the algorithm associated with SubjectEncKey.
	EncAlgorithm string
	// ExpirationTime is the unix timestamp in seconds at which the certificate expires.
	ExpirationTime uint32
	// Issuer is the certificate issuer. It can only be a issuing AS.
	Issuer addr.IA
	// IssuingTime is the unix timestamp in seconds at which the certificate was created.
	IssuingTime uint32
	// SignAlgorithm is the algorithm associated with SubjectSigKey.
	SignAlgorithm string
	// Signature is the certificate signature. It is computed over the rest of the certificate.
	Signature common.RawBytes `json:",omitempty"`
	// Subject is the certificate subject.
	Subject addr.IA
	// SubjectEncKey is the public key used for encryption.
	SubjectEncKey common.RawBytes
	// SubjectSignKey the public key used for signature verification.
	SubjectSignKey common.RawBytes
	// TRCVersion is the version of the issuing trc.
	TRCVersion uint64
	// Version is the certificate version. The value 0 is reserved and shall not be used.
	Version uint64
}

func CertificateFromRaw(raw common.RawBytes) (*Certificate, error) {
	cert := &Certificate{}
	if err := json.Unmarshal(raw, cert); err != nil {
		return nil, common.NewBasicError("Unable to parse Certificate", err)
	}
	if cert.Version == 0 {
		return nil, common.NewBasicError(ReservedVersion, nil)
	}
	return cert, nil
}

// Verify checks the signature of the certificate based on a trusted verifying key and the
// associated signature algorithm. Further, it verifies that the certificate belongs to the given
// subject, and that it is valid at the current time.
func (c *Certificate) Verify(subject addr.IA, verifyKey common.RawBytes, signAlgo string) error {
	if !subject.Eq(c.Subject) {
		return common.NewBasicError(InvalidSubject, nil,
			"expected", c.Subject, "actual", subject)
	}
	if err := c.VerifyTime(uint32(time.Now().Unix())); err != nil {
		return err
	}
	return c.VerifySignature(verifyKey, signAlgo)
}

// VerifyTime checks that the time ts is between issuing and expiration time. This function does
// not check the validity of the signature.
func (c *Certificate) VerifyTime(ts uint32) error {
	if ts < c.IssuingTime {
		return common.NewBasicError(EarlyUsage, nil,
			"IssuingTime", util.TimeToString(util.USecsToTime(c.IssuingTime)),
			"current", util.TimeToString(util.USecsToTime(ts)))
	}
	if ts > c.ExpirationTime {
		return common.NewBasicError(Expired, nil,
			"ExpirationTime", util.TimeToString(util.USecsToTime(c.ExpirationTime)),
			"current", util.TimeToString(util.USecsToTime(ts)))
	}
	return nil
}

// VerifySignature checks the signature of the certificate based on a trusted verifying key and the
// associated signature algorithm.
func (c *Certificate) VerifySignature(verifyKey common.RawBytes, signAlgo string) error {
	sigInput, err := c.sigPack()
	if err != nil {
		return common.NewBasicError(UnableSigPack, err)
	}
	return crypto.Verify(sigInput, c.Signature, verifyKey, signAlgo)
}

// Sign adds signature to the certificate. The signature is computed over the certificate
// without the signature field.
func (c *Certificate) Sign(signKey common.RawBytes, signAlgo string) error {
	sigInput, err := c.sigPack()
	if err != nil {
		return err
	}
	sig, err := crypto.Sign(sigInput, signKey, signAlgo)
	if err != nil {
		return err
	}
	c.Signature = sig
	return nil
}

// sigPack creates a sorted json object of all fields, except for the signature field.
func (c *Certificate) sigPack() (common.RawBytes, error) {
	if c.Version == 0 {
		return nil, common.NewBasicError(ReservedVersion, nil)
	}
	m := make(map[string]interface{})
	m[canIssue] = c.CanIssue
	m[comment] = c.Comment
	m[encAlgorithm] = c.EncAlgorithm
	m[expirationTime] = c.ExpirationTime
	m[issuer] = c.Issuer
	m[issuingTime] = c.IssuingTime
	m[signAlgorithm] = c.SignAlgorithm
	m[subject] = c.Subject
	m[subjectEncKey] = c.SubjectEncKey
	m[subjectSignKey] = c.SubjectSignKey
	m[trcVersion] = c.TRCVersion
	m[version] = c.Version
	sigInput, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return sigInput, nil
}

func (c *Certificate) Copy() *Certificate {
	n := &Certificate{
		CanIssue:       c.CanIssue,
		Comment:        c.Comment,
		EncAlgorithm:   c.EncAlgorithm,
		ExpirationTime: c.ExpirationTime,
		Issuer:         c.Issuer,
		IssuingTime:    c.IssuingTime,
		SignAlgorithm:  c.SignAlgorithm,
		Signature:      make(common.RawBytes, len(c.Signature)),
		Subject:        c.Subject,
		SubjectEncKey:  make(common.RawBytes, len(c.SubjectEncKey)),
		SubjectSignKey: make(common.RawBytes, len(c.SubjectSignKey)),
		TRCVersion:     c.TRCVersion,
		Version:        c.Version}
	copy(n.Signature, c.Signature)
	copy(n.SubjectEncKey, c.SubjectEncKey)
	copy(n.SubjectSignKey, c.SubjectSignKey)
	return n
}

func (c *Certificate) String() string {
	return fmt.Sprintf("Certificate %sv%d", c.Subject, c.Version)
}

func (c *Certificate) JSON(indent bool) ([]byte, error) {
	if indent {
		return json.MarshalIndent(c, "", strings.Repeat(" ", 4))
	}
	return json.Marshal(c)
}

func (c *Certificate) UnmarshalJSON(b []byte) error {
	type Alias Certificate
	var m map[string]interface{}
	err := json.Unmarshal(b, &m)
	if err != nil {
		return err
	}
	if err = validateFields(m, certFields); err != nil {
		return common.NewBasicError(UnableValidateFields, err)
	}
	// XXX(roosd): Unmarshalling twice might affect performance.
	// After switching to go 1.10 we might make use of
	// https://golang.org/pkg/encoding/json/#Decoder.DisallowUnknownFields.
	return json.Unmarshal(b, (*Alias)(c))
}

func (c *Certificate) Eq(o *Certificate) bool {
	return c.CanIssue == o.CanIssue &&
		c.Comment == o.Comment &&
		c.ExpirationTime == o.ExpirationTime &&
		c.IssuingTime == o.IssuingTime &&
		c.TRCVersion == o.TRCVersion &&
		c.Version == o.Version &&
		c.Issuer.Eq(o.Issuer) &&
		c.Subject.Eq(o.Subject) &&
		c.SignAlgorithm == o.SignAlgorithm &&
		c.EncAlgorithm == o.EncAlgorithm &&
		bytes.Equal(c.SubjectEncKey, o.SubjectEncKey) &&
		bytes.Equal(c.SubjectSignKey, o.SubjectSignKey) &&
		bytes.Equal(c.Signature, o.Signature)
}
