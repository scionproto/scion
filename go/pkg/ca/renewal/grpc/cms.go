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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
)

// ChainBuilder creates a chain for the given CSR.
type ChainBuilder interface {
	CreateChain(context.Context, *x509.CertificateRequest) ([]*x509.Certificate, error)
}

// RenewalRequestVerifier verifies the incoming chain renewal request.
type RenewalRequestVerifier interface {
	VerifyPbSignedRenewalRequest(context.Context, *cryptopb.SignedMessage,
		[][]*x509.Certificate) (*x509.CertificateRequest, error)
	VerifyCMSSignedRenewalRequest(context.Context, []byte) (*x509.CertificateRequest, error)
}

// CMSHandlerMetrics contains the counters for the CMSHandler
type CMSHandlerMetrics struct {
	Success metrics.Counter

	DatabaseError metrics.Counter
	InternalError metrics.Counter
	NotFoundError metrics.Counter
	ParseError    metrics.Counter
	VerifyError   metrics.Counter
}

// CMS handles CMS requests.
type CMS struct {
	Verifier     RenewalRequestVerifier
	ChainBuilder ChainBuilder
	IA           addr.IA

	// Metrics contains the counters. It is safe to pass nil-counters.
	Metrics CMSHandlerMetrics
}

// HandleCMSRequest handles a request with CMS signature.
func (s CMS) HandleCMSRequest(
	ctx context.Context,
	req *cppb.ChainRenewalRequest,
) ([]*x509.Certificate, error) {

	logger := log.FromCtx(ctx)

	issuerIA, err := extractIssuerIA(req.CmsSignedRequest, logger)
	if err != nil {
		metrics.CounterInc(s.Metrics.ParseError)
		return nil, err
	}
	if issuerIA.I != s.IA.I {
		logger.Debug("Renewal requester is not part of the ISD", "issuer_isd_as", issuerIA)
		metrics.CounterInc(s.Metrics.NotFoundError)
		return nil, status.Error(codes.PermissionDenied, "not a client")
	}

	csr, err := s.Verifier.VerifyCMSSignedRenewalRequest(ctx, req.CmsSignedRequest)
	if err != nil {
		logger.Info("Failed to verify certificate chain renewal request", "err", err)
		metrics.CounterInc(s.Metrics.VerifyError)
		return nil, status.Error(codes.InvalidArgument, "failed to verify")
	}

	newClientChain, err := s.ChainBuilder.CreateChain(ctx, csr)
	if err != nil {
		logger.Info("Failed to create renewed certificate chain", "err", err)
		metrics.CounterInc(s.Metrics.InternalError)
		return nil, status.Error(codes.Unavailable, "failed to create chain")
	}

	metrics.CounterInc(s.Metrics.Success)
	return newClientChain, nil
}

func extractIssuerIA(raw []byte, logger log.Logger) (addr.IA, error) {
	chain, err := extractChain(raw)
	if err != nil {
		logger.Debug("Failed to extract client certificate", "err", err)
		return addr.IA{}, status.Error(codes.InvalidArgument,
			"request malformed: cannot extract client chain")
	}
	issuerIA, err := cppki.ExtractIA(chain[1].Subject)
	if err != nil {
		logger.Debug("Failed to extract IA from issuer certificate", "err", err)
		return addr.IA{}, status.Error(codes.InvalidArgument,
			"request malformed: cannot extract issuer subject")
	}
	return issuerIA, nil
}
