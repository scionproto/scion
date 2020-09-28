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

package grpc

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/opentracing/opentracing-go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/tracing"
	trustmetrics "github.com/scionproto/scion/go/pkg/cs/trust/internal/metrics"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/renewal"
)

type Signer interface {
	Sign(ctx context.Context, msg []byte,
		associatedData ...[]byte) (*cryptopb.SignedMessage, error)
}

// RenewalRequestVerifier verifies the incoming chain renewal request.
type RenewalRequestVerifier interface {
	VerifyChainRenewalRequest(*cppb.ChainRenewalRequest,
		[][]*x509.Certificate) (*x509.CertificateRequest, error)
}

// RenewalRequestVerifierFunc allows a func to implement the interface
type RenewalRequestVerifierFunc func(*cppb.ChainRenewalRequest,
	[][]*x509.Certificate) (*x509.CertificateRequest, error)

func (f RenewalRequestVerifierFunc) VerifyChainRenewalRequest(req *cppb.ChainRenewalRequest,
	chains [][]*x509.Certificate) (*x509.CertificateRequest, error) {
	return f(req, chains)
}

// ChainBuilder creates a chain for the given CSR.
type ChainBuilder interface {
	CreateChain(context.Context, *x509.CertificateRequest) ([]*x509.Certificate, error)
}

// RenewalServer servers trust material for gRPC requests.
type RenewalServer struct {
	Verifier     RenewalRequestVerifier
	ChainBuilder ChainBuilder
	Signer       Signer
	DB           renewal.DB
	IA           addr.IA

	// Requests aggregates all the incoming requests received by the handler. If
	// it is not initialized, nothing is reported.
	Requests metrics.Counter
}

func (s RenewalServer) ChainRenewal(ctx context.Context,
	req *cppb.ChainRenewalRequest) (*cppb.ChainRenewalResponse, error) {

	labels := requestLabels{
		ReqType: trustmetrics.ChainRenewalReq,
		Client:  infra.PromSrcUnknown,
	}
	peer, ok := peer.FromContext(ctx)
	if ok {
		labels.Client = trustmetrics.PeerToLabel(peer.Addr, s.IA)
	}
	span := opentracing.SpanFromContext(ctx)
	logger := log.FromCtx(ctx)

	unverfiedHeader, err := signed.ExtractUnverifiedHeader(req.SignedRequest)
	if err != nil {
		logger.Debug("Unable to extract signed header", "peer", peer, "err", err)
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrParse), err)
		return nil, status.Error(codes.InvalidArgument, "request malformed: cannot extract header")
	}
	var keyID cppb.VerificationKeyID
	if err := proto.Unmarshal(unverfiedHeader.VerificationKeyID, &keyID); err != nil {
		logger.Debug("Unable to extract verification key ID", "peer", peer, "err", err)
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrParse), err)
		return nil, status.Error(codes.InvalidArgument,
			"request malformed: cannot extract verification key ID")
	}
	if ia := addr.IAInt(keyID.IsdAs).IA(); ia.IsWildcard() {
		logger.Debug("Verification key ID contains wildcard ISD-AS", "isd_as", ia, "peer", peer,
			"err", err)
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrParse), err)
		return nil, status.Error(codes.InvalidArgument,
			"request malformed: verification key ID contains wildcard ISD-AS")
	}

	chains, err := s.DB.ClientChains(ctx, trust.ChainQuery{
		IA:           addr.IAInt(keyID.IsdAs).IA(),
		SubjectKeyID: keyID.SubjectKeyId,
		Date:         time.Now(),
	})
	if err != nil {
		logger.Info("Failed to load client chains", "peer", peer, "err", err)
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrDB), err)
		return nil, status.Error(codes.Unavailable, "db error")
	}
	if len(chains) == 0 {
		logger.Info("No client chain found", "peer", peer, "err", err)
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrNotFound), err)
		return nil, status.Error(codes.PermissionDenied, "not a client")
	}
	csr, err := s.Verifier.VerifyChainRenewalRequest(req, chains)
	if err != nil {
		logger.Info("Failed to verify certificate chain renewal request", "peer", peer, "err", err)
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrVerify), err)
		return nil, status.Error(codes.InvalidArgument, "failed to verify")
	}
	chain, err := s.ChainBuilder.CreateChain(ctx, csr)
	if err != nil {
		logger.Info("Failed to create renewed certificate chain", "peer", peer, "err", err)
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrInternal), err)
		return nil, status.Error(codes.Unavailable, "failed to create chain")
	}
	if _, err := s.DB.InsertClientChain(ctx, chain); err != nil {
		logger.Info("Failed to insert renewed certificate chain", "peer", peer, "err", err)
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrDB), err)
		return nil, status.Error(codes.Unavailable, "failed to insert chain")
	}

	body := &cppb.ChainRenewalResponseBody{
		Chain: &cppb.Chain{
			AsCert: chain[0].Raw,
			CaCert: chain[1].Raw,
		},
	}
	rawBody, err := proto.Marshal(body)
	if err != nil {
		logger.Info("Failed to pack body for signature", "peer", peer, "err", err)
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrInternal), err)
		return nil, status.Error(codes.Unavailable, "failed to pack reply")
	}
	signedMsg, err := s.Signer.Sign(ctx, rawBody)
	if err != nil {
		logger.Info("Failed to sign reply", "peer", peer, "err", err)
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrInternal), err)
		return nil, status.Error(codes.Unavailable, "failed to sign reply")
	}
	logger.Info("Issued new certificate chain",
		"isd_as", addr.IAInt(keyID.IsdAs).IA(),
		"subject_key_id", chain[0].SubjectKeyId,
		"validity", cppki.Validity{
			NotBefore: chain[0].NotBefore,
			NotAfter:  chain[0].NotAfter,
		},
	)
	return &cppb.ChainRenewalResponse{
		SignedResponse: signedMsg,
	}, nil
}

func (s RenewalServer) updateMetric(span opentracing.Span, l requestLabels, err error) {
	if s.Requests != nil {
		s.Requests.With(l.Expand()...).Add(1)
	}
	if span != nil {
		tracing.ResultLabel(span, l.Result)
		tracing.Error(span, err)
	}
}
