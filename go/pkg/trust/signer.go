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
	"crypto/rand"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
	"github.com/scionproto/scion/go/pkg/trust/internal/metrics"
	legacy "github.com/scionproto/scion/go/proto"
)

// Signer is used to sign control plane messages with the AS private key.
type Signer struct {
	PrivateKey crypto.Signer
	Algorithm  signed.SignatureAlgorithm
	// Deprecated: will be removed soon.
	Hash          crypto.Hash
	IA            addr.IA
	SubjectKeyID  []byte
	Expiration    time.Time
	TRCID         cppki.TRCID
	ChainValidity cppki.Validity
	InGrace       bool
}

// SignLegacy signs the message in the legacy format.
// Deprecated: Do not use with new code anymore.
func (s Signer) SignLegacy(ctx context.Context, msg []byte) (*legacy.SignS, error) {
	l := metrics.SignerLabels{}

	src := ctrl.X509SignSrc{
		IA:           s.IA,
		Base:         s.TRCID.Base,
		Serial:       s.TRCID.Serial,
		SubjectKeyID: s.SubjectKeyID,
	}
	meta := &legacy.SignS{Src: src.Pack()}
	meta.SetTimestamp(time.Now())

	expDiff := s.Expiration.Sub(time.Now())
	if expDiff < 0 {
		return nil, serrors.New("signer is expired",
			"subject_key_id", fmt.Sprintf("%x", s.SubjectKeyID),
			"expiration", s.Expiration)
	}
	if expDiff < time.Hour {
		log.FromCtx(ctx).Info("Signer expiration time is near",
			"subject_key_id", fmt.Sprintf("%x", s.SubjectKeyID),
			"expiration", s.Expiration)
	}

	input := meta.SigInput(msg, false)
	if s.Hash != 0 {
		h := s.Hash.New()
		h.Write(input)
		input = h.Sum(nil)
	}

	var err error
	meta.Signature, err = s.PrivateKey.Sign(rand.Reader, input, s.Hash)
	if err != nil {
		metrics.Signer.Sign(l.WithResult(metrics.ErrInternal)).Inc()
		return nil, err
	}
	metrics.Signer.Sign(l.WithResult(metrics.Success)).Inc()
	return meta, nil
}

// Sign signs the message with the associated data. The associated data is not
// included in the header or body of the signed message.
func (s Signer) Sign(ctx context.Context, msg []byte,
	associatedData ...[]byte) (*cryptopb.SignedMessage, error) {

	l := metrics.SignerLabels{}

	now := time.Now()
	expDiff := s.Expiration.Sub(now)
	if expDiff < 0 {
		return nil, serrors.New("signer is expired",
			"subject_key_id", fmt.Sprintf("%x", s.SubjectKeyID),
			"expiration", s.Expiration)
	}
	if expDiff < time.Hour {
		log.FromCtx(ctx).Info("Signer expiration time is near",
			"subject_key_id", fmt.Sprintf("%x", s.SubjectKeyID),
			"expiration", s.Expiration)
	}

	id := &cppb.VerificationKeyID{
		IsdAs:        uint64(s.IA.IAInt()),
		TrcBase:      uint64(s.TRCID.Base),
		TrcSerial:    uint64(s.TRCID.Serial),
		SubjectKeyId: s.SubjectKeyID,
	}
	rawID, err := proto.Marshal(id)
	if err != nil {
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
