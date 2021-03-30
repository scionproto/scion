// Copyright 2021 Anapaya Systems
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

package grpc

import (
	"context"
	"crypto/x509"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/pkg/ca/renewal"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
	"github.com/scionproto/scion/go/pkg/trust"
)

// Signer signs the message.
type Signer interface {
	Sign(ctx context.Context, msg []byte, associatedData ...[]byte) (*cryptopb.SignedMessage, error)
}

// LegacyHandlerMetrics contains the counters for the LegacyHandler.
type LegacyHandlerMetrics struct {
	Success metrics.Counter

	DatabaseError metrics.Counter
	InternalError metrics.Counter
	NotFoundError metrics.Counter
	ParseError    metrics.Counter
	VerifyError   metrics.Counter
}

// Legacy handles legacy requests.
type Legacy struct {
	Verifier     RenewalRequestVerifier
	ChainBuilder ChainBuilder
	Signer       Signer
	DB           renewal.DB

	// Metrics contains the counters. It is safe to pass nil-counters.
	Metrics LegacyHandlerMetrics
}

// HandleLegacyRequest handles a legacy request.
func (s Legacy) HandleLegacyRequest(
	ctx context.Context,
	req *cppb.ChainRenewalRequest,
) (*cppb.ChainRenewalResponse, error) {

	logger := log.FromCtx(ctx)

	unverifiedHeader, err := signed.ExtractUnverifiedHeader(req.SignedRequest)
	if err != nil {
		logger.Debug("Unable to extract signed header", "err", err)
		metrics.CounterInc(s.Metrics.ParseError)
		return nil,
			status.Error(codes.InvalidArgument, "request malformed: cannot extract header")
	}
	var keyID cppb.VerificationKeyID
	if err := proto.Unmarshal(unverifiedHeader.VerificationKeyID, &keyID); err != nil {
		logger.Debug("Unable to extract verification key ID", "err", err)
		metrics.CounterInc(s.Metrics.ParseError)
		return nil, status.Error(codes.InvalidArgument,
			"request malformed: cannot extract verification key ID")
	}
	if ia := addr.IAInt(keyID.IsdAs).IA(); ia.IsWildcard() {
		logger.Debug("Verification key ID contains wildcard ISD-AS", "isd_as", ia, "err", err)
		metrics.CounterInc(s.Metrics.ParseError)
		return nil, status.Error(codes.InvalidArgument,
			"request malformed: verification key ID contains wildcard ISD-AS")
	}
	chains, err := s.loadClientChains(ctx, addr.IAInt(keyID.IsdAs).IA(),
		keyID.SubjectKeyId, logger)
	if err != nil {
		return nil, err
	}

	csr, err := s.Verifier.VerifyPbSignedRenewalRequest(ctx, req.SignedRequest, chains)
	if err != nil {
		logger.Info("Failed to verify certificate chain renewal request", "err", err)
		metrics.CounterInc(s.Metrics.VerifyError)
		return nil,
			status.Error(codes.InvalidArgument, "failed to verify")
	}

	chain, err := s.createNewClientChain(ctx, csr, logger)
	if err != nil {
		return nil, err
	}

	body := &cppb.ChainRenewalResponseBody{
		Chain: &cppb.Chain{
			AsCert: chain[0].Raw,
			CaCert: chain[1].Raw,
		},
	}
	rawBody, err := proto.Marshal(body)
	if err != nil {
		logger.Info("Failed to pack body for signature", "err", err)
		metrics.CounterInc(s.Metrics.InternalError)
		return nil, status.Error(codes.Unavailable, "failed to pack reply")
	}

	signedMsg, err := s.Signer.Sign(ctx, rawBody)
	if err != nil {
		logger.Info("Failed to sign reply", "err", err)
		metrics.CounterInc(s.Metrics.InternalError)
		return nil,
			status.Error(codes.Unavailable, "failed to sign reply")
	}

	logger.Info("Issued new certificate chain",
		"isd_as", addr.IAInt(keyID.IsdAs).IA(),
		"subject_key_id", chain[0].SubjectKeyId,
		"validity", cppki.Validity{
			NotBefore: chain[0].NotBefore,
			NotAfter:  chain[0].NotAfter,
		},
		"request_type", "pb",
	)

	metrics.CounterInc(s.Metrics.Success)
	return &cppb.ChainRenewalResponse{
		SignedResponse: signedMsg,
	}, nil
}

func (s Legacy) loadClientChains(ctx context.Context, ia addr.IA, keyID []byte,
	logger log.Logger) ([][]*x509.Certificate, error) {

	chains, err := s.DB.ClientChains(ctx, trust.ChainQuery{
		IA:           ia,
		SubjectKeyID: keyID,
		Date:         time.Now(),
	})
	if err != nil {
		logger.Info("Failed to load client chains", "err", err)
		metrics.CounterInc(s.Metrics.DatabaseError)
		return nil, status.Error(codes.Unavailable, "db error")
	}
	if len(chains) == 0 {
		logger.Info("No client chain found", "err", err)
		metrics.CounterInc(s.Metrics.NotFoundError)
		return nil, status.Error(codes.PermissionDenied, "not a client")
	}

	return chains, nil
}

func (s Legacy) createNewClientChain(ctx context.Context, csr *x509.CertificateRequest,
	logger log.Logger) ([]*x509.Certificate, error) {

	chain, err := s.ChainBuilder.CreateChain(ctx, csr)
	if err != nil {
		logger.Info("Failed to create renewed certificate chain", "err", err)
		metrics.CounterInc(s.Metrics.InternalError)
		return nil, status.Error(codes.Unavailable, "failed to create chain")
	}
	if _, err := s.DB.InsertClientChain(ctx, chain); err != nil {
		logger.Info("Failed to insert renewed certificate chain", "err", err)
		metrics.CounterInc(s.Metrics.DatabaseError)
		return nil, status.Error(codes.Unavailable, "failed to insert chain")
	}

	return chain, nil
}
