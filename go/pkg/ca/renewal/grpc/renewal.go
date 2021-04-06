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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/scrypto/cms/protocol"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/ca/renewal"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

// LegacyRequestHandler handles legacy requests.
type LegacyRequestHandler interface {
	HandleLegacyRequest(context.Context,
		*cppb.ChainRenewalRequest) (*cppb.ChainRenewalResponse, error)
}

// CMSRequestHandler handles CMS requests.
type CMSRequestHandler interface {
	HandleCMSRequest(context.Context, *cppb.ChainRenewalRequest) ([]*x509.Certificate, error)
}

// CMSSigner signs response message.
type CMSSigner interface {
	SignCMS(ctx context.Context, msg []byte) ([]byte, error)
}

// RenewalServerMetrics contains counters for RenewalServerMetrics.
type RenewalServerMetrics struct {
	BackendErrors metrics.Counter
	Success       metrics.Counter
}

// RenewalServer servers trust material for gRPC requests.
type RenewalServer struct {
	IA            addr.IA
	LegacyHandler LegacyRequestHandler
	CMSHandler    CMSRequestHandler
	CMSSigner     CMSSigner

	// Metrics contains the counters. Different error are different counters.
	Metrics RenewalServerMetrics
}

func (s RenewalServer) ChainRenewal(ctx context.Context,
	req *cppb.ChainRenewalRequest) (*cppb.ChainRenewalResponse, error) {

	peer, _ := peer.FromContext(ctx)
	logger := log.FromCtx(ctx).New("peer", peer)
	ctx = log.CtxWith(ctx, logger)

	if req.CmsSignedRequest == nil {
		if s.LegacyHandler == nil {
			metrics.CounterInc(s.Metrics.BackendErrors)
			return nil, status.Error(codes.Unimplemented, "legacy request not supported")
		}
		response, err := s.LegacyHandler.HandleLegacyRequest(ctx, req)
		if err != nil {
			metrics.CounterInc(s.Metrics.BackendErrors)
			return nil, err
		}
		metrics.CounterInc(s.Metrics.Success)
		return response, err
	}

	resp, err := s.CMSHandler.HandleCMSRequest(ctx, req)
	if err != nil {
		metrics.CounterInc(s.Metrics.BackendErrors)
		return nil, err
	}
	// Create response body.
	rawBody := append(resp[0].Raw, resp[1].Raw...)
	signedCMS, err := s.CMSSigner.SignCMS(ctx, rawBody)
	if err != nil {
		logger.Info("Failed to sign reply", "err", err)
		metrics.CounterInc(s.Metrics.BackendErrors)
		return nil, status.Error(codes.Unavailable, "failed to sign reply")
	}

	clientIA, _ := cppki.ExtractIA(resp[0].Subject)
	logger.Info("Issued new certificate chain",
		"isd_as", clientIA,
		"subject_key_id", resp[0].SubjectKeyId,
		"validity", cppki.Validity{
			NotBefore: resp[0].NotBefore,
			NotAfter:  resp[0].NotAfter,
		},
		"request_type", "cms",
	)

	metrics.CounterInc(s.Metrics.Success)
	return &cppb.ChainRenewalResponse{
		CmsSignedResponse: signedCMS,
	}, nil
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
	return renewal.ExtractChain(sd)
}
