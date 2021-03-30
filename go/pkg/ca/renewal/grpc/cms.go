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
	"github.com/scionproto/scion/go/lib/scrypto/cms/protocol"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/ca/renewal"
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
	DB           renewal.DB
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

	// Check that the requester is actually a client of the CA.
	chain, err := extractClientChain(req.CmsSignedRequest)
	if err != nil {
		logger.Debug("Failed to extract client certificate", "err", err)
		metrics.CounterInc(s.Metrics.ParseError)
		return nil, status.Error(codes.InvalidArgument,
			"request malformed: cannot extract client chain")
	}
	issuerIA, err := cppki.ExtractIA(chain[1].Subject)
	if err != nil {
		logger.Debug("Failed to extract IA from issuer certificate", "err", err)
		metrics.CounterInc(s.Metrics.ParseError)
		return nil, status.Error(codes.InvalidArgument,
			"request malformed: cannot extract issuer subject")
	}
	if !issuerIA.Equal(s.IA) {
		logger.Debug("Renewal requester is not a client", "issuer_isd_as", issuerIA)
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
	if _, err := s.DB.InsertClientChain(ctx, newClientChain); err != nil {
		logger.Info("Failed to insert renewed certificate chain", "err", err)
		metrics.CounterInc(s.Metrics.DatabaseError)
		return nil, status.Error(codes.Unavailable, "failed to insert chain")
	}

	metrics.CounterInc(s.Metrics.Success)
	return newClientChain, nil
}

func extractClientChain(raw []byte) ([]*x509.Certificate, error) {
	ci, err := protocol.ParseContentInfo(raw)
	if err != nil {
		return nil, serrors.WrapStr("parsing ContentInfo", err)
	}
	sd, err := ci.SignedDataContent()
	if err != nil {
		return nil, serrors.WrapStr("parsing SignedData", err)
	}
	if len(sd.SignerInfos) != 1 {
		return nil, serrors.New("unexpected number of signers", "expected", 1,
			"actual", len(sd.SignerInfos))
	}
	si := sd.SignerInfos[0]
	certs, err := sd.X509Certificates()
	if certs == nil {
		err = protocol.ErrNoCertificate
	} else if len(certs) != 2 {
		err = serrors.New("unexpected number of certificates")
	}
	if err != nil {
		return nil, serrors.WrapStr("parsing client chain", err)
	}
	cert, err := si.FindCertificate(certs)
	if err != nil {
		return nil, serrors.WrapStr("selecting client certificate", err)
	}
	if cert != certs[0] {
		certs[0], certs[1] = certs[1], certs[0]
	}

	return certs, nil
}
