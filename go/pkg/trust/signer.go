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
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto/cms/protocol"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
	"github.com/scionproto/scion/go/pkg/trust/internal/metrics"
)

// Signer is used to sign control plane messages with the AS private key.
type Signer struct {
	PrivateKey    crypto.Signer
	Algorithm     signed.SignatureAlgorithm
	IA            addr.IA
	Subject       pkix.Name
	Chain         []*x509.Certificate
	SubjectKeyID  []byte
	Expiration    time.Time
	TRCID         cppki.TRCID
	ChainValidity cppki.Validity
	InGrace       bool
}

// Sign signs the message with the associated data and returns a SignedMessage protobuf payload. The
// associated data is not included in the header or body of the signed message.
func (s Signer) Sign(ctx context.Context, msg []byte,
	associatedData ...[]byte) (*cryptopb.SignedMessage, error) {

	l := metrics.SignerLabels{}
	now := time.Now()
	if err := s.validate(ctx, now); err != nil {
		metrics.Signer.Sign(l.WithResult(metrics.ErrValidate)).Inc()
		return nil, err
	}

	id := &cppb.VerificationKeyID{
		IsdAs:        uint64(s.IA.IAInt()),
		TrcBase:      uint64(s.TRCID.Base),
		TrcSerial:    uint64(s.TRCID.Serial),
		SubjectKeyId: s.SubjectKeyID,
	}
	rawID, err := proto.Marshal(id)
	if err != nil {
		metrics.Signer.Sign(l.WithResult(metrics.ErrInternal)).Inc()
		return nil, serrors.WrapStr("packing verification_key_id", err)
	}
	hdr := signed.Header{
		SignatureAlgorithm:   s.Algorithm,
		VerificationKeyID:    rawID,
		Timestamp:            now,
		AssociatedDataLength: associatedDataLen(associatedData...),
	}
	signedMsg, err := signed.Sign(hdr, msg, s.PrivateKey, associatedData...)
	if err != nil {
		metrics.Signer.Sign(l.WithResult(metrics.ErrInternal)).Inc()
		return nil, err
	}
	metrics.Signer.Sign(l.WithResult(metrics.Success)).Inc()
	return signedMsg, nil
}

// SignCMS signs the message and returns a CMS/PKCS7 encoded payload.
func (s Signer) SignCMS(ctx context.Context, msg []byte) ([]byte, error) {
	l := metrics.SignerLabels{}
	if err := s.validate(ctx, time.Now()); err != nil {
		metrics.Signer.Sign(l.WithResult(metrics.ErrValidate)).Inc()
		return nil, err
	}

	eci, err := protocol.NewDataEncapsulatedContentInfo(msg)
	if err != nil {
		metrics.Signer.Sign(l.WithResult(metrics.ErrParse)).Inc()
		return nil, err
	}
	sd, err := protocol.NewSignedData(eci)
	if err != nil {
		metrics.Signer.Sign(l.WithResult(metrics.ErrParse)).Inc()
		return nil, err
	}
	if err := sd.AddSignerInfo(s.Chain, s.PrivateKey); err != nil {
		metrics.Signer.Sign(l.WithResult(metrics.ErrInternal)).Inc()
		return nil, err
	}
	encoded, err := sd.ContentInfoDER()
	if err != nil {
		metrics.Signer.Sign(l.WithResult(metrics.ErrInternal)).Inc()
		return nil, err
	}
	metrics.Signer.Sign(l.WithResult(metrics.Success)).Inc()
	return encoded, nil
}

func (s Signer) validate(ctx context.Context, now time.Time) error {
	expDiff := s.Expiration.Sub(now)
	if expDiff < 0 {
		return serrors.New("signer is expired",
			"subject_key_id", fmt.Sprintf("%x", s.SubjectKeyID),
			"expiration", s.Expiration)
	}
	if expDiff < time.Hour {
		log.FromCtx(ctx).Info("Signer expiration time is near",
			"subject_key_id", fmt.Sprintf("%x", s.SubjectKeyID),
			"expiration", s.Expiration)
	}

	return nil
}

func (s Signer) Equal(o Signer) bool {
	return s.IA.Equal(o.IA) &&
		bytes.Equal(s.SubjectKeyID, o.SubjectKeyID) &&
		s.Expiration.Equal(o.Expiration) &&
		s.TRCID == o.TRCID &&
		s.ChainValidity == o.ChainValidity &&
		s.InGrace == o.InGrace
}

func associatedDataLen(associatedData ...[]byte) int {
	var associatedDataLen int
	for _, d := range associatedData {
		associatedDataLen += len(d)
	}
	return associatedDataLen
}
