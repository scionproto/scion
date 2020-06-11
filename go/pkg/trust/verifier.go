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

package trust

import (
	"context"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/trust/internal/metrics"
	"github.com/scionproto/scion/go/proto"
)

// Verifier is used to verify control plane messages using the AS cert
// stored in the database.
type Verifier struct {
	// BoundIA when non-zero makes sure that only a signature originated from that IA
	// can be valid.
	BoundIA addr.IA
	// BoundServer binds a remote server to ask for missing crypto material.
	BoundServer net.Addr
	// Engine provides verified certificate chains.
	Engine Provider
}

// Verify verifies the signature of the msg.
func (v Verifier) Verify(ctx context.Context, msg []byte, meta *proto.SignS) error {
	l := metrics.VerifierLabels{}
	if meta == nil {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrValidate)).Inc()
		return serrors.New("signature is unset")
	}
	if len(meta.Signature) == 0 {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrValidate)).Inc()
		return serrors.New("missing signature")
	}
	src, err := ctrl.NewX509SignSrc(meta.Src)
	if err != nil {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrParse)).Inc()
		return err
	}
	if !v.BoundIA.IsZero() && !v.BoundIA.Equal(src.IA) {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrValidate)).Inc()
		return serrors.New("IA does not match bound IA",
			"expected", v.BoundIA, "actual", src.IA)
	}
	if v.Engine == nil {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrInternal)).Inc()
		return serrors.New("nil engine that provides cert chains")
	}
	id := cppki.TRCID{ISD: src.IA.I, Base: src.Base, Serial: src.Serial}
	if err := v.Engine.NotifyTRC(ctx, id, Server(v.BoundServer)); err != nil {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrInternal)).Inc()
		return serrors.WrapStr("reporting TRC", err, "id", id)
	}
	chains, err := v.Engine.GetChains(ctx,
		ChainQuery{
			IA:           src.IA,
			SubjectKeyID: src.SubjectKeyID,
			Date:         time.Now(),
		},
		Server(v.BoundServer),
	)
	if err != nil {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrInternal)).Inc()
		return err
	}
	for _, c := range chains {
		asCrt := c[0]
		input := meta.SigInput(msg, false)
		if err := asCrt.CheckSignature(asCrt.SignatureAlgorithm, input,
			meta.Signature); err == nil {
			metrics.Verifier.Verify(l.WithResult(metrics.Success)).Inc()
			return nil
		}
	}
	metrics.Verifier.Verify(l.WithResult(metrics.ErrNotFound)).Inc()
	return serrors.New("no chain in database can verify signature")
}
