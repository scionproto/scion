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
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/scrypto/cms/protocol"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/tracing"
	"github.com/scionproto/scion/go/pkg/ca/renewal"
	renewalmetrics "github.com/scionproto/scion/go/pkg/ca/renewal/metrics"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
	"github.com/scionproto/scion/go/pkg/trust"
)

type Signer interface {
	Sign(ctx context.Context, msg []byte, associatedData ...[]byte) (*cryptopb.SignedMessage, error)
}

type CMSSigner interface {
	SignCMS(ctx context.Context, msg []byte) ([]byte, error)
}

// RenewalRequestVerifier verifies the incoming chain renewal request.
type RenewalRequestVerifier interface {
	VerifyPbSignedRenewalRequest(context.Context, *cryptopb.SignedMessage,
		[][]*x509.Certificate) (*x509.CertificateRequest, error)
	VerifyCMSSignedRenewalRequest(context.Context, []byte) (*x509.CertificateRequest, error)
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
	CMSSigner    CMSSigner
	DB           renewal.DB
	IA           addr.IA

	// Requests aggregates all the incoming requests received by the handler. If
	// it is not initialized, nothing is reported.
	Requests metrics.Counter
}

func (s RenewalServer) ChainRenewal(ctx context.Context,
	req *cppb.ChainRenewalRequest) (*cppb.ChainRenewalResponse, error) {

	labels := requestLabels{
		ReqType: renewalmetrics.ChainRenewalReq,
		Client:  infra.PromSrcUnknown,
	}
	peer, ok := peer.FromContext(ctx)
	if ok {
		labels.Client = renewalmetrics.PeerToLabel(peer.Addr, s.IA)
	}
	span := opentracing.SpanFromContext(ctx)
	logger := log.FromCtx(ctx).New("peer", peer)

	handleRequest := s.handlePbSignedRequest
	if req.CmsSignedRequest != nil {
		handleRequest = s.handleCMSSignedRequest
	}
	response, labelValue, err := handleRequest(ctx, req, logger)
	s.updateMetric(span, labels.WithResult(labelValue), err)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (s RenewalServer) handlePbSignedRequest(
	ctx context.Context,
	req *cppb.ChainRenewalRequest,
	logger log.Logger) (*cppb.ChainRenewalResponse, string, error) {

	unverfiedHeader, err := signed.ExtractUnverifiedHeader(req.SignedRequest)
	if err != nil {
		logger.Debug("Unable to extract signed header", "err", err)
		return nil, renewalmetrics.ErrParse,
			status.Error(codes.InvalidArgument, "request malformed: cannot extract header")
	}
	var keyID cppb.VerificationKeyID
	if err := proto.Unmarshal(unverfiedHeader.VerificationKeyID, &keyID); err != nil {
		logger.Debug("Unable to extract verification key ID", "err", err)
		return nil, renewalmetrics.ErrParse, status.Error(codes.InvalidArgument,
			"request malformed: cannot extract verification key ID")
	}
	if ia := addr.IAInt(keyID.IsdAs).IA(); ia.IsWildcard() {
		logger.Debug("Verification key ID contains wildcard ISD-AS", "isd_as", ia, "err", err)
		return nil, renewalmetrics.ErrParse, status.Error(codes.InvalidArgument,
			"request malformed: verification key ID contains wildcard ISD-AS")
	}
	chains, labelValue, err := s.loadClientChains(ctx, addr.IAInt(keyID.IsdAs).IA(),
		keyID.SubjectKeyId, logger)
	if err != nil {
		return nil, labelValue, err
	}

	csr, err := s.Verifier.VerifyPbSignedRenewalRequest(ctx, req.SignedRequest, chains)
	if err != nil {
		logger.Info("Failed to verify certificate chain renewal request", "err", err)
		return nil, renewalmetrics.ErrVerify,
			status.Error(codes.InvalidArgument, "failed to verify")
	}

	chain, labelValue, err := s.createNewClientChain(ctx, csr, logger)
	if err != nil {
		return nil, labelValue, err
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
		return nil, renewalmetrics.ErrInternal,
			status.Error(codes.Unavailable, "failed to pack reply")
	}

	signedMsg, err := s.Signer.Sign(ctx, rawBody)
	if err != nil {
		logger.Info("Failed to sign reply", "err", err)
		return nil, renewalmetrics.ErrInternal,
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

	return &cppb.ChainRenewalResponse{
		SignedResponse: signedMsg,
	}, renewalmetrics.Success, nil
}

func (s RenewalServer) handleCMSSignedRequest(ctx context.Context, req *cppb.ChainRenewalRequest,
	logger log.Logger) (*cppb.ChainRenewalResponse, string, error) {

	// Check that the requester is actually a client of the CA.
	chain, err := extractChain(req.CmsSignedRequest)
	if err != nil {
		logger.Debug("Failed to extract client certificate", "err", err)
		return nil, renewalmetrics.ErrParse, status.Error(codes.InvalidArgument,
			"request malformed: cannot extract client chain")
	}
	issuerIA, err := cppki.ExtractIA(chain[1].Subject)
	if err != nil {
		logger.Debug("Failed to extract IA from issuer certificate", "err", err)
		return nil, renewalmetrics.ErrParse, status.Error(codes.InvalidArgument,
			"request malformed: cannot extract issuer subject")
	}
	if !issuerIA.Equal(s.IA) {
		logger.Debug("Renewal requester is not a client", "issuer_isd_as", issuerIA)
		return nil, renewalmetrics.ErrNotFound, status.Error(codes.PermissionDenied, "not a client")
	}

	csr, err := s.Verifier.VerifyCMSSignedRenewalRequest(ctx, req.CmsSignedRequest)
	if err != nil {
		logger.Info("Failed to verify certificate chain renewal request", "err", err)
		return nil, renewalmetrics.ErrVerify,
			status.Error(codes.InvalidArgument, "failed to verify")
	}

	newClientChain, labelValue, err := s.createNewClientChain(ctx, csr, logger)
	if err != nil {
		return nil, labelValue, err
	}

	// Create response body.
	rawBody := append(newClientChain[0].Raw, newClientChain[1].Raw...)
	signedCMS, err := s.CMSSigner.SignCMS(ctx, rawBody)
	if err != nil {
		logger.Info("Failed to sign reply", "err", err)
		return nil, renewalmetrics.ErrInternal,
			status.Error(codes.Unavailable, "failed to sign reply")
	}

	clientIA, _ := cppki.ExtractIA(newClientChain[0].Subject)
	logger.Info("Issued new certificate chain",
		"isd_as", clientIA,
		"subject_key_id", newClientChain[0].SubjectKeyId,
		"validity", cppki.Validity{
			NotBefore: newClientChain[0].NotBefore,
			NotAfter:  newClientChain[0].NotAfter,
		},
		"request_type", "cms",
	)

	return &cppb.ChainRenewalResponse{
		CmsSignedResponse: signedCMS,
	}, renewalmetrics.Success, nil
}

func (s RenewalServer) loadClientChains(ctx context.Context, ia addr.IA, keyID []byte,
	logger log.Logger) ([][]*x509.Certificate, string, error) {

	chains, err := s.DB.ClientChains(ctx, trust.ChainQuery{
		IA:           ia,
		SubjectKeyID: keyID,
		Date:         time.Now(),
	})
	if err != nil {
		logger.Info("Failed to load client chains", "err", err)
		return nil, renewalmetrics.ErrDB, status.Error(codes.Unavailable, "db error")
	}
	if len(chains) == 0 {
		logger.Info("No client chain found", "err", err)
		return nil, renewalmetrics.ErrNotFound, status.Error(codes.PermissionDenied, "not a client")
	}

	return chains, renewalmetrics.Success, nil
}

func (s RenewalServer) createNewClientChain(ctx context.Context, csr *x509.CertificateRequest,
	logger log.Logger) ([]*x509.Certificate, string, error) {

	chain, err := s.ChainBuilder.CreateChain(ctx, csr)
	if err != nil {
		logger.Info("Failed to create renewed certificate chain", "err", err)
		return nil, renewalmetrics.ErrInternal,
			status.Error(codes.Unavailable, "failed to create chain")
	}
	if _, err := s.DB.InsertClientChain(ctx, chain); err != nil {
		logger.Info("Failed to insert renewed certificate chain", "err", err)
		return nil, renewalmetrics.ErrDB, status.Error(codes.Unavailable, "failed to insert chain")
	}

	return chain, renewalmetrics.Success, nil
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

func extractChain(raw []byte) ([]*x509.Certificate, error) {
	ci, err := protocol.ParseContentInfo(raw)
	if err != nil {
		return nil, serrors.WrapStr("parsing ContentInfo", err)
	}
	sd, err := ci.SignedDataContent()
	if err != nil {
		return nil, serrors.WrapStr("parsing SignedData", err)
	}
	certs, err := sd.X509Certificates()
	if certs == nil {
		err = protocol.ErrNoCertificate
	} else if len(certs) != 2 {
		err = serrors.New("unexpected number of certificates")
	}
	if err != nil {
		return nil, serrors.WrapStr("parsing certificate chain", err)
	}

	certType, err := cppki.ValidateCert(certs[0])
	if err != nil {
		return nil, serrors.WrapStr("checking certificate type", err)
	}
	if certType == cppki.CA {
		certs[0], certs[1] = certs[1], certs[0]
	}
	if err := cppki.ValidateChain(certs); err != nil {
		return nil, serrors.WrapStr("validating chain", err)
	}
	return certs, nil
}

type requestLabels struct {
	Client  string
	ReqType string
	Result  string
}

func (l requestLabels) Expand() []string {
	return []string{
		"client", l.Client,
		"req_type", l.ReqType,
		prom.LabelResult, l.Result,
	}
}

func (l requestLabels) WithResult(result string) requestLabels {
	l.Result = result
	return l
}
