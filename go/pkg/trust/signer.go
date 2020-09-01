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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/trust/internal/metrics"
	"github.com/scionproto/scion/go/proto"
)

// Signer is used to sign control plane messages with the AS private key.
type Signer struct {
	PrivateKey    crypto.Signer
	Hash          crypto.Hash
	IA            addr.IA
	SubjectKeyID  []byte
	Expiration    time.Time
	TRCID         cppki.TRCID
	ChainValidity cppki.Validity
	InGrace       bool
}

// Sign signs the message.
func (s Signer) Sign(ctx context.Context, msg []byte) (*proto.SignS, error) {
	l := metrics.SignerLabels{}

	src := ctrl.X509SignSrc{
		IA:           s.IA,
		Base:         s.TRCID.Base,
		Serial:       s.TRCID.Serial,
		SubjectKeyID: s.SubjectKeyID,
	}
	meta := &proto.SignS{Src: src.Pack()}
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

func (s Signer) Equal(o Signer) bool {
	return s.IA.Equal(o.IA) &&
		bytes.Equal(s.SubjectKeyID, o.SubjectKeyID) &&
		s.Expiration.Equal(o.Expiration) &&
		s.TRCID == o.TRCID &&
		s.ChainValidity == o.ChainValidity &&
		s.InGrace == o.InGrace
}
