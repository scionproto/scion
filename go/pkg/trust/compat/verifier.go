// Copyright 2020 Anapaya Systems
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

package compat

import (
	"context"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/internal/metrics"
	"github.com/scionproto/scion/go/proto"
)

// Verifier wraps the trust Verifier to implement the infra.Verifier interface.
type Verifier struct {
	trust.Verifier
}

func (v Verifier) VerifyPld(ctx context.Context, spld *ctrl.SignedPld) (*ctrl.Pld, error) {
	l := metrics.VerifierLabels{}
	cpld, err := ctrl.NewPldFromRaw(spld.Blob)
	if err != nil {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrParse)).Inc()
		return nil, err
	}
	if ignoreSign(cpld, spld.Sign) {
		metrics.Verifier.Verify(l.WithResult(metrics.OkIgnored)).Inc()
		return cpld, nil
	}
	if err := v.Verify(ctx, spld.Blob, spld.Sign); err != nil {
		return nil, err
	}
	return cpld, nil
}

func (v Verifier) WithIA(ia addr.IA) infra.Verifier {
	v.BoundIA = ia
	return v
}

func (v Verifier) WithServer(server net.Addr) infra.Verifier {
	v.BoundServer = server
	return v
}

func (v Verifier) WithSignatureTimestampRange(_ infra.SignatureTimestampRange) infra.Verifier {
	panic("not supported")
}

func ignoreSign(p *ctrl.Pld, sign *proto.SignS) bool {
	u0, _ := p.Union()
	outer, ok := u0.(*cert_mgmt.Pld)
	if !ok {
		return false
	}
	u1, _ := outer.Union()
	switch u1.(type) {
	case *cert_mgmt.Chain, *cert_mgmt.TRC, *cert_mgmt.ChainReq, *cert_mgmt.TRCReq:
		return true
	}
	return false
}
