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

type Certificate struct {
	// All fields in this struct need to be sorted to create a sorted JSON.
	// They need to be sorted in alphabetic order of the field names,
	// since MarshalJSON marshals struct fields in order of declaration.
	// This is important for a consistent creation of signature input.

	// CanIssue describes wheter the subject is able to issue certificates.
	CanIssue bool
	// Comment is an arbitrary and optional string used by the subject to describe the certificate.
	Comment string
	// EncAlgorithm is the algorithm associated with SubjectEncKey.
	EncAlgorithm string
	// ExpirationTime is the time at which the certificate expires.
	ExpirationTime int64
	// Issuer is the certificate issuer. It can only be a core AS.
	Issuer *addr.ISD_AS
	// IssuingTime is the time at which the certificate was created.
	IssuingTime int64
	// SignAlgorithm is the algorithm associated with SubjectSigKey.
	SignAlgorithm string
	// Signature is the certificate signature. It is computed over the rest of the certificate.
	Signature common.RawBytes `json:",omitempty"`
	// Subject is the certificate subject.
	Subject *addr.ISD_AS
	// SubjectEncKey is the public key used for encryption.
	SubjectEncKey common.RawBytes
	// SubjectSigKey the public key used for signature verification.
	SubjectSigKey common.RawBytes
	// TRCVersion is the version of the issuing trc.
	TRCVersion int
	// Version is the certificate version.
	Version int
}

func CertificateFromRaw(raw common.RawBytes) (*Certificate, error) {
	cert := &Certificate{}
	if err := json.Unmarshal(raw, cert); err != nil {
		return nil, common.NewCError("Unable to parse Certificate", "err", err)
	}
	return cert, nil
}

// Verify checks the signature of the certificate based on a trusted verifying key and the
// associated signature algorithm. Further, it verifies that the certificate belongs to the given subject,
// and that it is valid at the current time.
func (c *Certificate) Verify(subject *addr.ISD_AS, verifyKey common.RawBytes, signAlgo string) error {
	if !subject.Eq(c.Subject) {
		return common.NewCError("Subject does not match", "expected", c.Subject, "actual", subject)
	}
	t := time.Now()
	if t.Unix() < c.IssuingTime {
		return common.NewCError("Certificate used before IssuingTime", "IssuingTime",
			time.Unix(c.IssuingTime, 0), "current", t)
	}
	if t.Unix() > c.ExpirationTime {
		return common.NewCError("Certificate expired", "Expiration Time",
			time.Unix(c.ExpirationTime, 0), "current", t)
	}
	sigInput, err := c.sigPack()
	if err != nil {
		return common.NewCError("Signature input creation faild", "error", err)
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
	l := len(c.Signature)
	c.Signature = c.Signature[:0]
	sigInput, err := json.Marshal(c)
	c.Signature = c.Signature[:l]
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
		bytes.Equal(c.SubjectSigKey, o.SubjectSigKey) &&
		bytes.Equal(c.Signature, o.Signature)
}
