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

package ctrl

import (
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/proto"
)

// Signer takes a Pld and signs it, producing a SignedPld.
type Signer interface {
	Sign(*Pld) (*SignedPld, error)
}

// BasicSigner is a simple implementation of Signer.
type BasicSigner struct {
	s   *proto.SignS
	key common.RawBytes
}

// NewBasicSigner creates a Signer that uses the supplied s and key to sign Pld's.
func NewBasicSigner(s *proto.SignS, key common.RawBytes) *BasicSigner {
	return &BasicSigner{s: s, key: key}
}

func (b *BasicSigner) Sign(pld *Pld) (*SignedPld, error) {
	return newSignedPld(pld, b.s, b.key)
}

// NullSigner is a Signer that creates SignedPld's with no signature.
var NullSigner = NewBasicSigner(nil, nil)

type trustStore struct{} // TODO(kormat): replace this with trust store interface

// VerifySig does some sanity checks on p, and then verifies the signature using sigV.
func VerifySig(p *SignedPld, sigV SigVerifier) error {
	// Perform common checks before calling real checker.
	if p.Sign.Type == proto.SignType_none && len(p.Sign.Signature) == 0 {
		// Nothing to check.
		return nil
	}
	if p.Sign.Type == proto.SignType_none {
		return common.NewBasicError("SignedPld has signature of type none", nil)
	}
	if len(p.Sign.Signature) == 0 {
		return common.NewBasicError("SignedPld is missing signature", nil, "type", p.Sign.Type)
	}
	return sigV.Verify(p)
}

// SigVerifier verifies the signature of a SignedPld.
type SigVerifier interface {
	Verify(*SignedPld) error
}

// BasicSigVerifier is a SigVerifier that ignores signatures on cert_mgmt.TRC
// and cert_mgmt.Chain messages, to avoid depdendency cycles.
type BasicSigVerifier struct {
	tStore *trustStore
}

func (b *BasicSigVerifier) Verify(p *SignedPld) error {
	cpld, err := p.Pld()
	if err != nil {
		return err
	}
	if b.ignoreSign(cpld) {
		return nil
	}
	c, err := b.getCertForSign(p.Sign)
	if err != nil {
		return err
	}
	return p.Sign.Verify(c.SubjectSignKey, p.Blob)
}

func (b *BasicSigVerifier) ignoreSign(p *Pld) bool {
	u0, _ := p.Union()
	outer, ok := u0.(*cert_mgmt.Pld)
	if !ok {
		return false
	}
	u1, _ := outer.Union()
	switch u1.(type) {
	case *cert_mgmt.Chain, *cert_mgmt.TRC:
		return true
	default:
		return false
	}
}

func (b *BasicSigVerifier) getCertForSign(s *proto.SignS) (*cert.Certificate, error) {
	// TODO(kormat): Parse s.Src, query b.tStore
	return nil, nil
}
