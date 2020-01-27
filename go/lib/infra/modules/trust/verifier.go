// Copyright 2019 Anapaya Systems
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

package trust

import (
	"context"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/metrics"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/proto"
)

type verifier struct {
	AllowSkew time.Duration
	MaxAge    time.Duration
	BoundIA   addr.IA
	BoundSrc  *ctrl.SignSrcDef
	Store     CryptoProvider
	Server    net.Addr
}

// NewVerifier returns a struct that verifies payloads signed with
// control-plane PKI certificates through infra.Verifier interface.
func NewVerifier(provider CryptoProvider) infra.Verifier {
	return &verifier{
		AllowSkew: 1 * time.Second,
		MaxAge:    2 * time.Second,
		Store:     provider,
	}
}

func ignoreSign(p *ctrl.Pld, sign *proto.SignS) bool {
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
		return sign == nil || sign.Type == proto.SignType_none
	}
	return false
}

func (v *verifier) VerifyPld(ctx context.Context, spld *ctrl.SignedPld) (*ctrl.Pld, error) {
	cpld, err := ctrl.NewPldFromRaw(spld.Blob)
	if err != nil {
		return nil, err
	}

	if ignoreSign(cpld, spld.Sign) {
		return cpld, nil
	}

	if age := time.Now().Sub(spld.Sign.Time()); age < v.MaxAge {
		return nil, serrors.New("Invalid timestamp. Signature age", "age", age)
	}

	if err := v.Verify(ctx, spld.Blob, spld.Sign); err != nil {
		return nil, err
	}
	return cpld, nil
}

func (v *verifier) Verify(ctx context.Context, msg []byte, sign *proto.SignS) error {
	ctx = metrics.CtxWith(ctx, metrics.SigVerification)
	l := metrics.VerifierLabels{}
	if err := sign.Valid(v.AllowSkew); err != nil {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrValidate)).Inc()
		return serrors.Wrap(ErrValidation, err)
	}

	src, err := ctrl.NewSignSrcDefFromRaw(sign.Src)
	if err != nil {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrParse)).Inc()
		return serrors.Wrap(ErrValidation, err)
	}

	if !v.BoundIA.IsZero() && !v.BoundIA.Equal(src.IA) {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrValidate)).Inc()
		return serrors.WithCtx(ErrValidation, "msg", "IA does not match bound IA",
			"expected", v.BoundIA, "actual", src.IA)
	}

	if v.BoundSrc != nil && !v.BoundSrc.Equal(src) {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrValidate)).Inc()
		// The entity that is the source of the RPC network request (BoundSrc)
		// must be the same as the entity that signed the RPC (src).
		return serrors.WithCtx(ErrValidation, "msg", "source does not match bound source",
			"expected", v.BoundSrc, "actual", src)
	}

	// Announce TRC version to the provider, to ensure the TRC referenced in the
	// signature source is available locally.
	id := TRCID{ISD: src.IA.I, Version: src.TRCVer}
	tOpts := infra.TRCOpts{TrustStoreOpts: infra.TrustStoreOpts{Server: v.Server}}
	if err := v.Store.AnnounceTRC(ctx, id, tOpts); err != nil {
		return err
	}

	opts := infra.ChainOpts{TrustStoreOpts: infra.TrustStoreOpts{Server: v.Server}}
	key, err := v.Store.GetASKey(ctx, ChainID{IA: src.IA, Version: src.ChainVer}, opts)
	if err != nil {
		metrics.Verifier.Verify(l.WithResult(errToLabel(err))).Inc()
		return err
	}

	m, s := sign.SigInput(msg, false), sign.Signature
	if err := scrypto.Verify(m, s, key.Key, key.Algorithm); err != nil {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrVerify)).Inc()
		return serrors.Wrap(ErrVerification, err)
	}
	metrics.Verifier.Verify(l.WithResult(metrics.Success)).Inc()
	return nil
}

func (v *verifier) WithServer(server net.Addr) infra.Verifier {
	verifier := *v
	verifier.Server = server
	return &verifier
}

func (v *verifier) WithIA(ia addr.IA) infra.Verifier {
	verifier := *v
	verifier.BoundIA = ia
	return &verifier
}

func (v *verifier) WithSrc(src ctrl.SignSrcDef) infra.Verifier {
	verifier := *v
	verifier.BoundSrc = &src
	return &verifier
}

func (v *verifier) WithSignatureTimestampRange(t infra.SignatureTimestampRange) infra.Verifier {
	verifier := *v
	verifier.MaxAge = t.MaxPldAge
	verifier.AllowSkew = t.MaxInFuture
	return &verifier
}
