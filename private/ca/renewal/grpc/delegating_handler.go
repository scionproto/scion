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
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/ca/api"
)

// CAServiceClient is the minimal interface that is needed from
// private/ca/api:ClientWithResponsesInterface.
type CAServiceClient interface {
	PostCertificateRenewal(
		ctx context.Context,
		isd int,
		as api.AS,
		body api.PostCertificateRenewalJSONRequestBody,
		reqEditors ...api.RequestEditorFn,
	) (*http.Response, error)
}

// DelegatingHandlerMetrics contains the counters for the DelegatingHandler
type DelegatingHandlerMetrics struct {
	BadRequests   metrics.Counter
	InternalError metrics.Counter
	Unavailable   metrics.Counter
	Success       metrics.Counter
}

// DelegatingHandler delegates requests to the CA service.
type DelegatingHandler struct {
	Client CAServiceClient

	// Metrics contains the counters. It is safe to pass nil-counters.
	Metrics DelegatingHandlerMetrics
}

// HandleCMSRequest handles a certificate renewal request that was signed with
// CMS by delegating it to the CA Service.
func (h *DelegatingHandler) HandleCMSRequest(
	ctx context.Context,
	req *cppb.ChainRenewalRequest,
) ([]*x509.Certificate, error) {

	logger := log.FromCtx(ctx)

	chain, err := extractChain(req.CmsSignedRequest)
	if err != nil {
		logger.Info("Failed to extract client certificate", "err", err)
		metrics.CounterInc(h.Metrics.BadRequests)
		return nil, status.Error(
			codes.InvalidArgument,
			"malformed request: cannot extract client certificate chain",
		)
	}
	subject, err := cppki.ExtractIA(chain[0].Subject)
	if err != nil {
		logger.Info("Failed to extract IA from AS certificate",
			"err", err,
			"subject", chain[0].Subject,
		)
		metrics.CounterInc(h.Metrics.BadRequests)
		return nil, status.Error(
			codes.InvalidArgument,
			"malformed request: cannot extract ISD-AS from subject",
		)
	}

	rep, err := h.Client.PostCertificateRenewal(
		ctx,
		int(subject.ISD()),
		subject.AS().String(),
		api.PostCertificateRenewalJSONRequestBody{
			Csr: req.CmsSignedRequest,
		},
	)
	if err != nil {
		logger.Info("Request to CA service failed", "err", err)
		metrics.CounterInc(h.Metrics.InternalError)
		return nil, status.Error(
			codes.Internal,
			"connection to server failed",
		)
	}
	defer rep.Body.Close()
	body, err := io.ReadAll(rep.Body)
	if err != nil {
		logger.Info("Error reading CA service response", "err", err)
		metrics.CounterInc(h.Metrics.InternalError)
		return nil, status.Error(
			codes.Internal,
			"reading server response failed",
		)
	}
	if rep.StatusCode != http.StatusOK {
		return nil, h.handleErrors(rep.StatusCode, body, logger)
	}
	var r api.RenewalResponse
	if err := json.Unmarshal(body, &r); err != nil {
		logger.Info("Failed to extract renewal response", "err", err)
		metrics.CounterInc(h.Metrics.InternalError)
		return nil, status.Error(
			codes.Internal,
			"reading server response failed",
		)
	}
	renewed, err := h.parseChain(r)
	if err != nil {
		logger.Info("Failed to extract renewal certificate chain", "err", err)
		metrics.CounterInc(h.Metrics.InternalError)
		return nil, status.Error(
			codes.Internal,
			"malformed renewed certificate chain",
		)
	}
	metrics.CounterInc(h.Metrics.Success)
	return renewed, nil
}

func (h *DelegatingHandler) parseChain(rep api.RenewalResponse) ([]*x509.Certificate, error) {
	chain, chainErr := rep.CertificateChain.AsCertificateChain()
	pkcs7, pkcs7Err := rep.CertificateChain.AsCertificateChainPKCS7()
	switch {
	case chainErr == nil:
		return h.parseChainJSON(chain)
	case pkcs7Err == nil:
		return extractChain(pkcs7)
	default:
		return nil, serrors.New("certificate_chain unset",
			"chain_err", chainErr, "pkcs7_err", pkcs7Err,
		)
	}
}

func (h *DelegatingHandler) parseChainJSON(rep api.CertificateChain) ([]*x509.Certificate, error) {
	as, err := x509.ParseCertificate(rep.AsCertificate)
	if err != nil {
		return nil, serrors.WrapStr("parsing AS certificate", err)
	}
	ca, err := x509.ParseCertificate(rep.CaCertificate)
	if err != nil {
		return nil, serrors.WrapStr("parsing CA certificate", err)
	}
	chain := []*x509.Certificate{as, ca}
	if err := cppki.ValidateChain(chain); err != nil {
		return nil, serrors.WrapStr("validating certificate chain", err)
	}
	return chain, nil
}

func (h *DelegatingHandler) handleErrors(code int, body []byte, logger log.Logger) error {
	var problem api.Problem
	if err := json.Unmarshal(body, &problem); err != nil {
		log.Info("Failed to decode CA service response", "err", err)
		metrics.CounterInc(h.Metrics.InternalError)
		return status.Error(codes.Internal, "invalid service response")
	}

	switch code {
	case http.StatusBadRequest:
		logger.Info("Malformed certificate renewal request", "err", string(body))
		metrics.CounterInc(h.Metrics.BadRequests)
		return status.Error(
			codes.InvalidArgument,
			msgWithDetail("malformed request", problem.Detail),
		)
	case http.StatusUnauthorized:
		logger.Info("Unauthorized certificate renewal request", "err", string(body))
		metrics.CounterInc(h.Metrics.Unavailable)
		return status.Error(codes.Unavailable, "service unavailable")
	case http.StatusNotFound:
		logger.Info("Resource not found in certificate renewal request", "err", string(body))
		metrics.CounterInc(h.Metrics.BadRequests)
		return status.Error(
			codes.NotFound,
			msgWithDetail("resource not found", problem.Detail),
		)
	case http.StatusInternalServerError:
		logger.Info("Internal server error in certificate renewal request", "err", string(body))
		metrics.CounterInc(h.Metrics.InternalError)
		return status.Error(codes.Internal, "internal error")
	case http.StatusServiceUnavailable:
		logger.Info("Unavailable server error in certificate renewal request", "err", string(body))
		metrics.CounterInc(h.Metrics.Unavailable)
		return status.Error(
			codes.Unavailable,
			msgWithDetail("service unavailable", problem.Detail),
		)
	default:
		logger.Info("Unhandled CA service response", "response", string(body))
		metrics.CounterInc(h.Metrics.InternalError)
		return status.Error(
			codes.Internal,
			"unhandled service response",
		)
	}
}

func msgWithDetail(msg string, detail *string) string {
	if detail == nil {
		return msg
	}
	return fmt.Sprintf("%s: %s", msg, *detail)
}
