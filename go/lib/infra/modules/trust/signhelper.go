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
	"net"
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

var _ infra.Signer = (*BasicSigner)(nil)

// BasicSigner is a simple implementation of Signer.
type BasicSigner struct {
	meta      infra.SignerMeta
	signType  proto.SignType
	packedSrc common.RawBytes
	key       common.RawBytes
}

// NewBasicSigner creates a Signer that uses the supplied meta to sign
// messages.
func NewBasicSigner(key common.RawBytes, meta infra.SignerMeta) (*BasicSigner, error) {
	if meta.Src.IA.IsWildcard() {
		return nil, common.NewBasicError("IA must not contain wildcard", nil, "ia", meta.Src.IA)
	}
	if meta.Src.ChainVer == scrypto.LatestVer {
		return nil, common.NewBasicError("ChainVer must be valid", nil, "ver", meta.Src.ChainVer)
	}
	if meta.Src.TRCVer == scrypto.LatestVer {
		return nil, common.NewBasicError("TRCVer must be valid", nil, "ver", meta.Src.TRCVer)
	}
	signer := &BasicSigner{
		meta:      meta,
		key:       key,
		packedSrc: meta.Src.Pack(),
	}
	switch meta.Algo {
	case scrypto.Ed25519:
		signer.signType = proto.SignType_ed25519
	default:
		return nil, common.NewBasicError("Unsupported signing algorithm", nil, "algo", meta.Algo)
	}
	return signer, nil
}

// Sign signs the message.
func (b *BasicSigner) Sign(msg common.RawBytes) (*proto.SignS, error) {
	var err error
	sign := proto.NewSignS(b.signType, append(common.RawBytes(nil), b.packedSrc...))
	sign.Signature, err = scrypto.Sign(sign.SigInput(msg, true), b.key, b.meta.Algo)
	return sign, err
}

// Meta returns the meta data the signer uses when signing.
func (b *BasicSigner) Meta() infra.SignerMeta {
	return b.meta
}

var _ infra.Verifier = (*BasicVerifier)(nil)

// BasicVerifier is a verifier that ignores signatures on cert_mgmt.TRC
// and cert_mgmt.Chain messages, to avoid dependency cycles.
type BasicVerifier struct {
	store  *Store
	ia     addr.IA
	src    ctrl.SignSrcDef
	server net.Addr
}

// NewBasicVerifier creates a new verifier.
func NewBasicVerifier(store *Store) *BasicVerifier {
	return &BasicVerifier{store: store}
}

// WithIA creates a verifier that is bound to the remote AS. Only
// signatures created by that AS are accepted.
func (v *BasicVerifier) WithIA(ia addr.IA) infra.Verifier {
	verifier := *v
	verifier.ia = ia
	return &verifier
}

// WithSrc returns a verifier that is bound to the specified source. The
// verifies against the specified source, and not the value provided by the
// sign meta data.
func (v *BasicVerifier) WithSrc(src ctrl.SignSrcDef) infra.Verifier {
	verifier := *v
	verifier.src = src
	return &verifier
}

// WithServer returns a verifier that requests the required crypto material
// from the specified server.
func (v *BasicVerifier) WithServer(server net.Addr) infra.Verifier {
	verifier := *v
	verifier.server = server
	return &verifier
}

// Verify verifies the message based on the provided sign meta data.
func (v *BasicVerifier) Verify(ctx context.Context, msg common.RawBytes, sign *proto.SignS) error {
	if err := v.sanityChecks(sign, false); err != nil {
		return err
	}
	return v.verify(ctx, msg, sign)
}

// VerifyPld verifies and unpacks the signed payload. In addition to the
// regular checks, this also verifies that the signature is not older than
// SignatureValidity.
func (v *BasicVerifier) VerifyPld(ctx context.Context, spld *ctrl.SignedPld) (*ctrl.Pld, error) {
	cpld, err := ctrl.NewPldFromRaw(spld.Blob)
	if err != nil {
		return nil, common.NewBasicError("Unable to parse payload", err)
	}
	if v.ignoreSign(cpld, spld.Sign) {
		return cpld, nil
	}
	if err := v.sanityChecks(spld.Sign, true); err != nil {
		return nil, common.NewBasicError("Sanity check failed", err, "pld", cpld)
	}
	if err := v.verify(ctx, spld.Blob, spld.Sign); err != nil {
		return nil, common.NewBasicError("Unable to verify", err, "pld", cpld)
	}
	return cpld, nil
}

func (v *BasicVerifier) ignoreSign(p *ctrl.Pld, sign *proto.SignS) bool {
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

func (v *BasicVerifier) sanityChecks(sign *proto.SignS, timeout bool) error {
	if sign == nil {
		return common.NewBasicError("SignS is unset", nil)
	}
	if len(sign.Signature) == 0 {
		return common.NewBasicError("SignedPld is missing signature", nil, "type", sign.Type)
	}
	now := time.Now()
	ts := sign.Time()
	diff := now.Sub(ts)
	if diff < 0 {
		return common.NewBasicError("Invalid timestamp. Signature from future", nil,
			"ts", util.TimeToString(ts), "now", util.TimeToString(now))
	}
	if timeout && diff > SignatureValidity {
		return common.NewBasicError("Invalid timestamp. Signature expired", nil,
			"ts", util.TimeToString(ts), "now", util.TimeToString(now),
			"validity", SignatureValidity)
	}
	return nil
}

func (v *BasicVerifier) verify(ctx context.Context, msg common.RawBytes,
	sign *proto.SignS) error {

	var err error
	src := v.src
	if src.IsUninitialized() {
		if src, err = ctrl.NewSignSrcDefFromRaw(sign.Src); err != nil {
			return err
		}
	}
	if err := v.checkSrc(src); err != nil {
		return err
	}
	chain, err := GetChainForSign(ctx, src, v.store, v.server)
	if err != nil {
		return err
	}
	err = scrypto.Verify(sign.SigInput(msg, false), sign.Signature, chain.Leaf.SubjectSignKey,
		chain.Leaf.SignAlgorithm)
	if err != nil {
		return common.NewBasicError("Verification failed", err)
	}
	return nil
}

func (v *BasicVerifier) checkSrc(src ctrl.SignSrcDef) error {
	if v.ia.A != 0 && src.IA.A != v.ia.A {
		return common.NewBasicError("AS does not match bound source", nil,
			"srcSet", !v.src.IsUninitialized(), "expected", v.ia, "actual", src.IA)
	}
	if v.ia.I != 0 && src.IA.I != v.ia.I {
		return common.NewBasicError("ISD does not match bound source", nil,
			"srcSet", !v.src.IsUninitialized(), "expected", v.ia, "actual", src.IA)
	}
	return nil
}
