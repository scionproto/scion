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
	"context"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

const SignatureValidity = 2 * time.Second

// Signer takes a Pld and signs it, producing a SignedPld.
type Signer interface {
	Sign(*Pld) (*SignedPld, error)
}

var _ Signer = (*BasicSigner)(nil)

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
var NullSigner Signer = NewBasicSigner(nil, nil)

// VerifySig does some sanity checks on p, and then verifies the signature using sigV.
func VerifySig(ctx context.Context, p *SignedPld, sigV SigVerifier) error {
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
	return sigV.Verify(ctx, p)
}

// SigVerifier verifies the signature of a SignedPld.
type SigVerifier interface {
	Verify(context.Context, *SignedPld) error
}

var _ SigVerifier = (*BasicSigVerifier)(nil)

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

func (v *BasicSigVerifier) Verify(ctx context.Context, p *SignedPld) error {
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

func (v *BasicSigVerifier) ignoreSign(p *Pld) bool {
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
	sigSrc, err := NewSignSrcDefFromRaw(s.Src)
	if err != nil {
		return nil, err
	}
	chain, err := GetChainForSign(ctx, sigSrc, v.tStore)
	if err != nil {
		return nil, err
	}
	return chain.Leaf.SubjectSignKey, nil
}

func GetChainForSign(ctx context.Context, s *SignSrcDef,
	tStore infra.TrustStore) (*cert.Chain, error) {

	t, err := tStore.GetTRC(ctx, s.IA.I, s.TRCVer)
	if err != nil {
		return nil, common.NewBasicError("Unable to get TRC", err)
	}
	c, err := tStore.GetChain(ctx, s.IA, s.ChainVer)
	if err != nil {
		return nil, common.NewBasicError("Unable to get certificate chain", err)
	}
	maxTRC, err := tStore.GetValidTRC(ctx, t.ISD, nil)
	if err != nil {
		return nil, common.NewBasicError("Unable to get maxTRC", err)
	}
	if err := t.IsActive(maxTRC); err != nil {
		// The certificate chain might still be verifiable with the max TRC
		t = maxTRC
	}
	if err := c.Verify(c.Leaf.Subject, t); err != nil {
		return nil, common.NewBasicError("Unable to verify certificate chain", err)
	}
	return c, nil
}

const (
	// SrcDefaultPrefix is the default prefix for proto.SignS.Src.
	SrcDefaultPrefix = "DEFAULT: "
	// SrcDefaultFmt is the default format for proto.SignS.Src.
	SrcDefaultFmt = `^` + SrcDefaultPrefix + `IA: (\S+) CHAIN: (\d+) TRC: (\d+)$`
)

type SignSrcDef struct {
	IA       addr.IA
	ChainVer uint64
	TRCVer   uint64
}

func NewSignSrcDefFromRaw(b common.RawBytes) (*SignSrcDef, error) {
	re := regexp.MustCompile(SrcDefaultFmt)
	s := re.FindStringSubmatch(string(b))
	if len(s) == 0 {
		return nil, common.NewBasicError("Unable to match default src", nil, "string", string(b))
	}
	ia, err := addr.IAFromString(s[1])
	if err != nil {
		return nil, common.NewBasicError("Unable to parse default src IA", err)
	}
	chainVer, err := strconv.ParseUint(s[2], 10, 64)
	if err != nil {
		return nil, common.NewBasicError("Unable to parse default src ChainVer", err)
	}
	trcVer, err := strconv.ParseUint(s[3], 10, 64)
	if err != nil {
		return nil, common.NewBasicError("Unable to parse default src TRCVer", err)
	}
	return &SignSrcDef{IA: ia, ChainVer: chainVer, TRCVer: trcVer}, nil
}

func (s *SignSrcDef) Pack() common.RawBytes {
	return common.RawBytes(fmt.Sprintf("%sIA: %s CHAIN: %d TRC: %d", SrcDefaultPrefix,
		s.IA, s.ChainVer, s.TRCVer))
}

func (s *SignSrcDef) String() string {
	return fmt.Sprintf("IA: %s ChainVer: %d TRCVer: %d", s.IA, s.ChainVer, s.TRCVer)
}

var _ SigVerifier = (*nullSigVerifier)(nil)

// NullSigVerifier ignores signatures on all messages.
var NullSigVerifier SigVerifier = &nullSigVerifier{}

type nullSigVerifier struct{}

func (_ *nullSigVerifier) Verify(_ context.Context, p *SignedPld) error {
	return nil
}
