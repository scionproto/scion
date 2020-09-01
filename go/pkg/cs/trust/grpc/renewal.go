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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/tracing"
	trustmetrics "github.com/scionproto/scion/go/pkg/cs/trust/internal/metrics"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/renewal"
	"github.com/scionproto/scion/go/proto"
)

// RenewalRequestVerifier verifies the incoming chain renewal request.
type RenewalRequestVerifier interface {
	VerifyChainRenewalRequest(*cert_mgmt.ChainRenewalRequest,
		[][]*x509.Certificate) (*x509.CertificateRequest, error)
}

// RenewalRequestVerifierFunc allows a func to implement the interface
type RenewalRequestVerifierFunc func(*cert_mgmt.ChainRenewalRequest,
	[][]*x509.Certificate) (*x509.CertificateRequest, error)

func (f RenewalRequestVerifierFunc) VerifyChainRenewalRequest(req *cert_mgmt.ChainRenewalRequest,
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
	Signer       ctrl.Signer
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

	chainReq := &cert_mgmt.ChainRenewalRequest{}
	if err := proto.ParseFromRaw(chainReq, req.Raw); err != nil {
		logger.Debug("Unable to parse chain request", "peer", peer, "err", err)
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrParse), err)
		return nil, status.Error(codes.InvalidArgument, "request malformed")
	}
	src, err := ctrl.NewX509SignSrc(chainReq.Signature.Src)
	if err != nil {
		logger.Debug("Unable to parse chain request signature", "peer", peer, "err", err)
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrParse), err)
		return nil, status.Error(codes.InvalidArgument, "request malformed")
	}
	chains, err := s.DB.ClientChains(ctx, trust.ChainQuery{
		IA:           src.IA,
		SubjectKeyID: src.SubjectKeyID,
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
	csr, err := s.Verifier.VerifyChainRenewalRequest(chainReq, chains)
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
	msg := append(append([]byte(nil), chain[0].Raw...), chain[1].Raw...)
	signature, err := s.Signer.Sign(ctx, msg)
	if err != nil {
		logger.Info("Failed to sign reply", "peer", peer, "err", err)
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrInternal), err)
		return nil, status.Error(codes.Unavailable, "failed to sign reply")
	}
	rep, err := proto.PackRoot(&cert_mgmt.ChainRenewalReply{
		RawChain:  msg,
		Signature: signature,
	})
	if err != nil {
		logger.Debug("Failed to pack renewed certificate chain", "peer", peer, "err", err)
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrInternal), err)
		return nil, status.Error(codes.Unavailable, "failed to pack reply")
	}
	logger.Info("Issued new certificate chain",
		"isd_as", src.IA,
		"subject_key_id", chain[0].SubjectKeyId,
		"validity", cppki.Validity{
			NotBefore: chain[0].NotBefore,
			NotAfter:  chain[0].NotAfter,
		},
	)
	return &cppb.ChainRenewalResponse{
		Raw: rep,
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
