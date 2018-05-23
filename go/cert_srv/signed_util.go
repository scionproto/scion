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

package main

import (
	"time"

	"github.com/scionproto/scion/go/cert_srv/conf"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/trust"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

const SignatureValidity = 2 * time.Second

func CreateSign(ia addr.IA, store *trust.Store) (*proto.SignS, error) {
	c := store.GetNewestChain(ia)
	if c == nil {
		return nil, common.NewBasicError("Unable to find local certificate chain", nil)
	}
	t := store.GetNewestTRC(ia.I)
	if t == nil {
		return nil, common.NewBasicError("Unable to find local TRC", nil)
	}
	var sigType proto.SignType
	switch c.Leaf.SignAlgorithm {
	case crypto.Ed25519:
		sigType = proto.SignType_ed25519
	default:
		return nil, common.NewBasicError("Unsupported signing algorithm", nil, "algo",
			c.Leaf.SignAlgorithm)
	}
	src := &ctrl.SignSrcDef{
		IA:       ia,
		ChainVer: c.Leaf.Version,
		TRCVer:   t.Version}
	return proto.NewSignS(sigType, src.Pack()), nil
}

var _ ctrl.SigVerifier = (*SigVerifier)(nil)

// SigVerifier is a SigVerifier that ignores signatures on cert_mgmt.TRC
// cert_mgmt.Chain and cert_mgmt.ChainIssRep messages, to avoid dependency cycles.
type SigVerifier struct {
	*ctrl.BasicSigVerifier
}

func (v *SigVerifier) Verify(p *ctrl.SignedPld) error {
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
	vKey, err := v.getVerifyKeyForSign(p.Sign)
	if err != nil {
		return err
	}
	return p.Sign.Verify(vKey, p.Blob)
}

func (v *SigVerifier) ignoreSign(p *ctrl.Pld) bool {
	u0, _ := p.Union()
	outer, ok := u0.(*cert_mgmt.Pld)
	if !ok {
		return false
	}
	u1, _ := outer.Union()
	switch u1.(type) {
	// FIXME(roosd): ChainIssRep is disregarded to avoid deadlock when
	// the issuer updates its leaf certificate at the same time. Remove
	// it when trust store supports lookup of missing certificates.
	case *cert_mgmt.Chain, *cert_mgmt.TRC, *cert_mgmt.ChainIssRep:
		return true
	default:
		return false
	}
}

func (v *SigVerifier) getVerifyKeyForSign(s *proto.SignS) (common.RawBytes, error) {
	if s.Type == proto.SignType_none {
		return nil, nil
	}
	sigSrc, err := ctrl.NewSignSrcDefFromRaw(s.Src)
	if err != nil {
		return nil, err
	}
	chain, err := getChainForSign(sigSrc)
	if err != nil {
		return nil, err
	}
	return chain.Leaf.SubjectSignKey, nil
}

func getChainForSign(s *ctrl.SignSrcDef) (*cert.Chain, error) {
	c := conf.Get().Store.GetChain(s.IA, s.ChainVer)
	if c == nil {
		return nil, common.NewBasicError("Unable to get certificate chain", nil,
			"ISD-AS", s.IA, "ver", s.ChainVer)
	}
	t := conf.Get().Store.GetTRC(s.IA.I, s.TRCVer)
	if t == nil {
		return nil, common.NewBasicError("Unable to get TRC", nil, "ISD", s.IA.I, "ver", s.TRCVer)
	}
	maxTRC := conf.Get().Store.GetNewestTRC(t.ISD)
	if err := t.CheckActive(maxTRC); err != nil {
		// The certificate chain might still be verifiable with the max TRC
		t = maxTRC
	}
	if err := c.Verify(c.Leaf.Subject, t); err != nil {
		return nil, common.NewBasicError("Unable to verify certificate chain", err)
	}
	return c, nil
}
