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
// limitations under the License.package trust

package trust

import (
	"context"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

const (
	SignatureValidity = 2 * time.Second
)

var _ ctrl.Signer = (*BasicSigner)(nil)

// BasicSigner is a simple implementation of Signer.
type BasicSigner struct {
	s   *proto.SignS
	key common.RawBytes
}

// NewBasicSigner creates a Signer that uses the supplied s and key to sign Pld's.
func NewBasicSigner(s *proto.SignS, key common.RawBytes) *BasicSigner {
	return &BasicSigner{s: s, key: key}
}

func (b *BasicSigner) Sign(pld *ctrl.Pld) (*ctrl.SignedPld, error) {
	return ctrl.NewSignedPld(pld, b.s, b.key)
}

var _ ctrl.SigVerifier = (*BasicSigVerifier)(nil)

// BasicSigVerifier is a SigVerifier that ignores signatures on cert_mgmt.TRC
// and cert_mgmt.Chain messages, to avoid dependency cycles.
type BasicSigVerifier struct {
	tStore infra.TrustStore
}

func NewBasicSigVerifier(tStore infra.TrustStore) *BasicSigVerifier {
	return &BasicSigVerifier{
		tStore: tStore,
	}
}

func (v *BasicSigVerifier) Verify(ctx context.Context, p *ctrl.SignedPld) error {
	cpld, err := p.Pld()
	if err != nil {
		return err
	}
	if v.ignoreSign(cpld) {
		return nil
	}
	now := time.Now()
	ts := p.Sign.Time()
	diff := now.Sub(ts)
	if diff < 0 {
		return common.NewBasicError("Invalid timestamp. Signature from future", nil,
			"ts", util.TimeToString(ts), "now", util.TimeToString(now))
	}
	if diff > SignatureValidity {
		return common.NewBasicError("Invalid timestamp. Signature expired", nil,
			"ts", util.TimeToString(ts), "now", util.TimeToString(now),
			"validity", SignatureValidity)
	}
	vKey, err := v.getVerifyKeyForSign(ctx, p.Sign)
	if err != nil {
		return err
	}
	return p.Sign.Verify(vKey, p.Blob)
}

func (v *BasicSigVerifier) ignoreSign(p *ctrl.Pld) bool {
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

func (v *BasicSigVerifier) getVerifyKeyForSign(ctx context.Context,
	s *proto.SignS) (common.RawBytes, error) {

	if s.Type == proto.SignType_none {
		return nil, nil
	}
	sigSrc, err := ctrl.NewSignSrcDefFromRaw(s.Src)
	if err != nil {
		return nil, err
	}
	chain, err := GetChainForSign(ctx, sigSrc, v.tStore)
	if err != nil {
		return nil, err
	}
	return chain.Leaf.SubjectSignKey, nil
}
