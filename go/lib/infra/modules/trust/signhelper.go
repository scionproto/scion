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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

const (
	SignatureValidity = 2 * time.Second
)

var _ infra.CPSigner = (*BasicSigner)(nil)

// BasicSigner is a simple implementation of Signer.
type BasicSigner struct {
	meta infra.CPSignerMeta
	s    *proto.SignS
	key  common.RawBytes
}

// NewBasicSigner creates a Signer that uses the supplied meta to sign
// messages.
func NewBasicSigner(key common.RawBytes, meta infra.CPSignerMeta) (*BasicSigner, error) {
	if meta.Src.IA.IsWildcard() {
		return nil, common.NewBasicError("IA must not contain wildcard", nil, "ia", meta.Src.IA)
	}
	if meta.Src.ChainVer == scrypto.LatestVer {
		return nil, common.NewBasicError("ChainVer must be valid", nil, "ver", meta.Src.ChainVer)
	}
	if meta.Src.TRCVer == scrypto.LatestVer {
		return nil, common.NewBasicError("TRCVer must be valid", nil, "ver", meta.Src.TRCVer)
	}
	var signType proto.SignType
	switch meta.Algo {
	case scrypto.Ed25519:
		signType = proto.SignType_ed25519
	default:
		return nil, common.NewBasicError("Unsupported signing algorithm", nil, "algo", meta.Algo)
	}
	signer := &BasicSigner{
		meta: meta,
		s:    proto.NewSignS(signType, meta.Src.Pack()),
		key:  key,
	}
	return signer, nil
}

// Sign signs the message.
func (b *BasicSigner) Sign(msg common.RawBytes) (*proto.SignS, error) {
	sign := b.s.Copy()
	return sign, sign.SignAndSet(b.key, msg)
}

// Meta returns the meta data the signer uses when signing.
func (b *BasicSigner) Meta() infra.CPSignerMeta {
	return b.meta
}

var _ infra.CPVerifier = (*BasicSigVerifier)(nil)

// BasicSigVerifier is a SigVerifier that ignores signatures on cert_mgmt.TRC
// and cert_mgmt.Chain messages, to avoid dependency cycles.
type BasicSigVerifier struct {
	store  *Store
	remote addr.IA
}

func NewBasicSigVerifier(store *Store) *BasicSigVerifier {
	return &BasicSigVerifier{
		store: store,
	}
}

func (v *BasicSigVerifier) BindToRemote(ia addr.IA) ctrl.SigVerifier {
	return &BasicSigVerifier{
		store:  v.store,
		remote: ia,
	}
}

func (v *BasicSigVerifier) VerifyPld(ctx context.Context, spld *ctrl.SignedPld) (*ctrl.Pld, error) {
	cpld, err := ctrl.NewPldFromRaw(spld.Blob)
	if err != nil {
		return nil, err
	}
	if v.ignoreSign(cpld, spld.Sign) {
		return cpld, nil
	}
	if err := v.sanityChecks(spld); err != nil {
		return nil, err
	}
	src, err := ctrl.NewSignSrcDefFromRaw(spld.Sign.Src)
	if err != nil {
		return nil, err
	}
	if err := v.checkRemote(src); err != nil {
		return nil, err
	}
	vKey, err := v.getVerifyKeyForSign(ctx, src)
	if err != nil {
		return nil, err
	}
	return cpld, spld.Sign.Verify(vKey, spld.Blob)
}

func (v *BasicSigVerifier) ignoreSign(p *ctrl.Pld, sign *proto.SignS) bool {
	u0, _ := p.Union()
	outer, ok := u0.(*cert_mgmt.Pld)
	if !ok {
		return false
	}
	u1, _ := outer.Union()
	switch u1.(type) {
	case *cert_mgmt.Chain, *cert_mgmt.TRC:
		return true
	case *cert_mgmt.ChainReq, *cert_mgmt.TRCReq:
		if sign == nil || sign.Type == proto.SignType_none {
			return true
		}
	}
	return false
}

func (v *BasicSigVerifier) sanityChecks(spld *ctrl.SignedPld) error {
	if len(spld.Sign.Signature) == 0 {
		return common.NewBasicError("SignedPld is missing signature", nil, "type", spld.Sign.Type)
	}
	now := time.Now()
	ts := spld.Sign.Time()
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
	return nil
}

func (v *BasicSigVerifier) checkRemote(src *ctrl.SignSrcDef) error {
	if v.remote.A != 0 && src.IA.A != v.remote.A {
		return common.NewBasicError("AS does not match remote", nil,
			"src", src, "remote", v.remote)
	}
	if v.remote.I != 0 && src.IA.I != v.remote.I {
		return common.NewBasicError("ISD does not match remote", nil,
			"src", src, "remote", v.remote)
	}
	return nil
}

func (v *BasicSigVerifier) getVerifyKeyForSign(ctx context.Context,
	src *ctrl.SignSrcDef) (common.RawBytes, error) {

	chain, err := GetChainForSign(ctx, src, v.store)
	if err != nil {
		return nil, err
	}
	return chain.Leaf.SubjectSignKey, nil
}
