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

type Signer func(*Pld) (*SignedPld, error)

func MkSigner(s *proto.SignS, key common.RawBytes) Signer {
	return func(p *Pld) (*SignedPld, error) {
		return newSignedPld(p, s, key)
	}
}

func NullSigner(p *Pld) (*SignedPld, error) {
	return newSignedPld(p, nil, nil)
}

type trustStore struct{} // TODO(kormat): replace this with the actual trust store.

type SigChecker func(*SignedPld) error
type SigCheckerInner func(*SignedPld, *trustStore) error

func MkSigchecker(sigCin SigCheckerInner, tStore *trustStore) SigChecker {
	return func(p *SignedPld) error {
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
		return sigCin(p, tStore)
	}
}

func BasicSigCheck(p *SignedPld, tStore *trustStore) error {
	cpld, err := p.Pld()
	if err != nil {
		return err
	}
	if ignoreSign(cpld) {
		return nil
	}
	c, err := GetCertForSign(p.Sign, tStore)
	if err != nil {
		return err
	}
	return p.Sign.Verify(c.SubjectSignKey, p.Blob)
}

func GetCertForSign(s *proto.SignS, tStore *trustStore) (*cert.Certificate, error) {
	// TODO(kormat): Parse s.Src, query tStore
	return nil, nil
}

func ignoreSign(p *Pld) bool {
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

// MkSPld creates a SignedPld from the provided Plder and Signer.
func MkSPld(plder Plder, signer Signer) (*SignedPld, error) {
	pld, err := plder()
	if err != nil {
		return nil, err
	}
	return signer(pld)
}
