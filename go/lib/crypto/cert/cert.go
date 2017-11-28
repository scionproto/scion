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

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/crypto"
)

const (
	EarlyUsage     = "Certificate IssuingTime in the future"
	InvalidSubject = "Invalid subject"
	Expired        = "Certificate expired"
	UnableSigPack  = "Cert: Unable to create signature input"
)

type Certificate struct {
	// CanIssue describes whether the subject is able to issue certificates.
	CanIssue bool
	// Comment is an arbitrary and optional string used by the subject to describe the certificate.
	Comment string
	// EncAlgorithm is the algorithm associated with SubjectEncKey.
	EncAlgorithm string
	// ExpirationTime is the unix timestamp in seconds at which the certificate expires.
	ExpirationTime uint64
	// Issuer is the certificate issuer. It can only be a core AS.
	Issuer *addr.ISD_AS
	// IssuingTime is the unix timestamp in seconds at which the certificate was created.
	IssuingTime uint64
	// SignAlgorithm is the algorithm associated with SubjectSigKey.
	SignAlgorithm string
	// Signature is the certificate signature. It is computed over the rest of the certificate.
	Signature common.RawBytes `json:",omitempty"`
	// Subject is the certificate subject.
	Subject *addr.ISD_AS
	// SubjectEncKey is the public key used for encryption.
	SubjectEncKey common.RawBytes
	// SubjectSignKey the public key used for signature verification.
	SubjectSignKey common.RawBytes
	// TRCVersion is the version of the issuing trc.
	TRCVersion uint64
	// Version is the certificate version.
	Version uint64
}

func CertificateFromRaw(raw common.RawBytes) (*Certificate, error) {
	cert := &Certificate{}
	if err := json.Unmarshal(raw, cert); err != nil {
		return nil, common.NewCError("Unable to parse Certificate", "err", err)
	}
	return cert, nil
}

// Verify checks the signature of the certificate based on a trusted verifying key and the
// associated signature algorithm. Further, it verifies that the certificate belongs to the given
// subject, and that it is valid at the current time.
func (c *Certificate) Verify(subject *addr.ISD_AS, verifyKey common.RawBytes, signAlgo string) error {
	if !subject.Eq(c.Subject) {
		return common.NewCError(InvalidSubject, "expected", c.Subject,
			"actual", subject)
	}
	currTime := uint64(time.Now().Unix())
	if currTime < c.IssuingTime {
		return common.NewCError(EarlyUsage, "IssuingTime",
			timeToString(c.IssuingTime), "current", timeToString(currTime))
	}
	if currTime > c.ExpirationTime {
		return common.NewCError(Expired, "Expiration Time",
			timeToString(c.ExpirationTime), "current", timeToString(currTime))
	}
	return c.VerifySignature(verifyKey, signAlgo)
}

// VerifySignature checks the signature of the certificate based on a trusted verifying key and the
// associated signature algorithm.
func (c *Certificate) VerifySignature(verifyKey common.RawBytes, signAlgo string) error {
	sigInput, err := c.sigPack()
	if err != nil {
		return common.NewCError(UnableSigPack, "error", err)
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
	m := make(map[string]interface{})
	m["CanIssue"] = c.CanIssue
	m["Comment"] = c.Comment
	m["EncAlgorithm"] = c.EncAlgorithm
	m["ExpirationTime"] = c.ExpirationTime
	m["Issuer"] = c.Issuer
	m["IssuingTime"] = c.IssuingTime
	m["SignAlgorithm"] = c.SignAlgorithm
	m["Subject"] = c.Subject
	m["SubjectEncKey"] = c.SubjectEncKey
	m["SubjectSignKey"] = c.SubjectSignKey
	m["TRCVersion"] = c.TRCVersion
	m["Version"] = c.Version
	sigInput, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return sigInput, nil
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

func timeToString(t uint64) string {
	return time.Unix(int64(t), 0).UTC().Format(common.TimeFmt)
}
