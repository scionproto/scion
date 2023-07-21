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
	"time"

	"github.com/scionproto/scion/pkg/private/serrors"
	cryptopb "github.com/scionproto/scion/pkg/proto/crypto"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/trust"
)

// SignerGen generates signers.
type SignerGen interface {
	Generate(ctx context.Context) (trust.Signer, error)
}

// RenewingSigner is a signer that automatically picks up new key/cert material.
type RenewingSigner struct {
	SignerGen SignerGen
}

// Sign signs the message with the latest available Signer.
func (s RenewingSigner) Sign(
	ctx context.Context,
	msg []byte,
	associatedData ...[]byte,
) (*cryptopb.SignedMessage, error) {

	signer, err := s.SignerGen.Generate(ctx)
	if err != nil {
		return nil, serrors.WrapStr("failed to generate signer", err)
	}
	return signer.Sign(ctx, msg, associatedData...)
}

// SignCMS signs the message with the latest available Signer.
func (s RenewingSigner) SignCMS(ctx context.Context, msg []byte) ([]byte, error) {
	signer, err := s.SignerGen.Generate(ctx)
	if err != nil {
		return nil, serrors.WrapStr("failed to generate signer", err)
	}
	return signer.SignCMS(ctx, msg)
}

// Generate returns the latest available Signer and its expiration time.
func (s RenewingSigner) Generate(ctx context.Context) (seg.Signer, time.Time, error) {
	signer, err := s.SignerGen.Generate(ctx)
	if err != nil {
		return trust.Signer{}, time.Time{}, serrors.WrapStr("failed to generate signer", err)
	}
	return signer, signer.Expiration, nil
}
