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

	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
	"github.com/scionproto/scion/go/pkg/trust/internal/metrics"
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
func (v Verifier) Verify(ctx context.Context, signedMsg *cryptopb.SignedMessage,
	associatedData ...[]byte) (*signed.Message, error) {

	l := metrics.VerifierLabels{}
	hdr, err := signed.ExtractUnverifiedHeader(signedMsg)
	if err != nil {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrValidate)).Inc()
		return nil, err
	}

	var keyID cppb.VerificationKeyID
	if err := proto.Unmarshal(hdr.VerificationKeyID, &keyID); err != nil {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrValidate)).Inc()
		return nil, serrors.WrapStr("parsiing verification key ID", err)
	}
	ia := addr.IAInt(keyID.IsdAs).IA()
	if !v.BoundIA.IsZero() && !v.BoundIA.Equal(ia) {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrValidate)).Inc()
		return nil, serrors.New("does not match bound ISD-AS", "expected", v.BoundIA, "actual", ia)
	}
	if v.Engine == nil {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrInternal)).Inc()
		return nil, serrors.New("nil engine that provides cert chains")
	}
	id := cppki.TRCID{ISD: ia.I,
		Base:   scrypto.Version(keyID.TrcBase),
		Serial: scrypto.Version(keyID.TrcSerial),
	}
	if err := v.Engine.NotifyTRC(ctx, id, Server(v.BoundServer)); err != nil {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrInternal)).Inc()
		return nil, serrors.WrapStr("reporting TRC", err, "id", id)
	}
	chains, err := v.Engine.GetChains(ctx,
		ChainQuery{
			IA:           ia,
			SubjectKeyID: keyID.SubjectKeyId,
			Date:         time.Now(),
		},
		Server(v.BoundServer),
	)
	if err != nil {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrInternal)).Inc()
		return nil, err
	}
	for _, c := range chains {
		signedMsg, err := signed.Verify(signedMsg, c[0].PublicKey, associatedData...)
		if err == nil {
			metrics.Verifier.Verify(l.WithResult(metrics.Success)).Inc()
			return signedMsg, nil
		}
	}
	metrics.Verifier.Verify(l.WithResult(metrics.ErrNotFound)).Inc()
	return nil, serrors.New("no chain in database can verify signature")
}
