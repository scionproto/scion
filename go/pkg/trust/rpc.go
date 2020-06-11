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
	"crypto/x509"
	"fmt"
	"net"

	"github.com/opentracing/opentracing-go"
	opentracingext "github.com/opentracing/opentracing-go/ext"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/tracing"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/pkg/trust/internal/metrics"
)

// RPC is the interface that executes the RPC using the low level message format.
type RPC interface {
	GetCertChain(ctx context.Context, msg *cert_mgmt.ChainReq, a net.Addr,
		id uint64) (*cert_mgmt.Chain, error)
	GetTRC(ctx context.Context, msg *cert_mgmt.TRCReq, a net.Addr,
		id uint64) (*cert_mgmt.TRC, error)
}

// Fetcher fetches trust material from a remote.
type Fetcher interface {
	// Chains fetches certificate chains that match the query from the remote.
	Chains(ctx context.Context, req ChainQuery, server net.Addr) ([][]*x509.Certificate, error)
	// TRC fetches a specific TRC from the remote.
	TRC(ctx context.Context, id cppki.TRCID, server net.Addr) (cppki.SignedTRC, error)
}

// DefaultFetcher fetches trust material from a remote.
type DefaultFetcher struct {
	RPC RPC
	IA  addr.IA
}

func (r DefaultFetcher) Chains(parentCtx context.Context, query ChainQuery,
	server net.Addr) ([][]*x509.Certificate, error) {

	l := metrics.RPCLabels{Type: metrics.ChainReq, Trigger: metrics.FromCtx(parentCtx),
		Peer: metrics.PeerToLabel(server, r.IA)}
	span, ctx := opentracing.StartSpanFromContext(parentCtx, "trustengine.fetch_chains")
	defer span.Finish()
	opentracingext.Component.Set(span, "trust")
	span.SetTag("query.isd_as", query.IA)
	span.SetTag("query.subject_key_id", fmt.Sprintf("%x", query.SubjectKeyID))
	span.SetTag("query.date", util.TimeToCompact(query.Date))

	logger := log.FromCtx(ctx)
	logger.Debug("[trust:Resolver] Fetch certificate chain from remote",
		"isd_as", query.IA,
		"date", util.TimeToCompact(query.Date),
		"subject_key_id", fmt.Sprintf("%x", query.SubjectKeyID),
		"server", server)
	req := &cert_mgmt.ChainReq{
		RawIA:        query.IA.IAInt(),
		SubjectKeyID: query.SubjectKeyID,
		RawDate:      query.Date.UTC().Unix(),
	}
	reply, err := r.RPC.GetCertChain(ctx, req, server, messenger.NextId())
	if err != nil {
		tracing.Error(span, err)
		metrics.RPC.Fetch(l.WithResult(metrics.ErrTransmit)).Inc()
		return nil, serrors.WrapStr("failed to fetch chain", err)
	}
	logger.Debug("[trust:Resolver] Received certificate chains from remote",
		"isd_as", query.IA, "chains", reply)
	chains, err := reply.Chains()
	if err != nil {
		tracing.Error(span, err)
		metrics.RPC.Fetch(l.WithResult(metrics.ErrParse)).Inc()
		return nil, serrors.WrapStr("failed to parse chain reply", err)
	}
	if err := checkChainsMatchQuery(query, chains); err != nil {
		tracing.Error(span, err)
		metrics.RPC.Fetch(l.WithResult(metrics.ErrMismatch)).Inc()
		return nil, serrors.WrapStr("chain reply doesn't match query", err)
	}
	metrics.RPC.Fetch(l.WithResult(metrics.Success)).Inc()
	return chains, nil
}

func (r DefaultFetcher) TRC(ctx context.Context, id cppki.TRCID,
	server net.Addr) (cppki.SignedTRC, error) {

	l := metrics.RPCLabels{Type: metrics.ChainReq, Trigger: metrics.FromCtx(ctx),
		Peer: metrics.PeerToLabel(server, r.IA)}
	span, ctx := opentracing.StartSpanFromContext(ctx, "trustengine.fetch_trc")
	defer span.Finish()
	opentracingext.Component.Set(span, "trust")
	span.SetTag("trc_id.isd", id.ISD)
	span.SetTag("trc_id.base", id.Base)
	span.SetTag("trc_id.serial", id.Serial)

	logger := log.FromCtx(ctx)
	logger.Debug("[trust:Resolver] Fetch certificate chain from remote", "id", id, "server", server)

	req := &cert_mgmt.TRCReq{
		ISD:    id.ISD,
		Base:   id.Base,
		Serial: id.Serial,
	}
	reply, err := r.RPC.GetTRC(ctx, req, server, messenger.NextId())
	if err != nil {
		tracing.Error(span, err)
		metrics.RPC.Fetch(l.WithResult(metrics.ErrTransmit)).Inc()
		return cppki.SignedTRC{}, serrors.WrapStr("fetch TRC", err)
	}
	trc, err := cppki.DecodeSignedTRC(reply.RawTRC)
	if err != nil {
		tracing.Error(span, err)
		metrics.RPC.Fetch(l.WithResult(metrics.ErrParse)).Inc()
		return cppki.SignedTRC{}, serrors.WrapStr("parse TRC reply", err)
	}
	logger.Debug("[trust:Resolver] Received TRC from remote", "id", id, "reply", reply)
	if trc.TRC.ID != id {
		tracing.Error(span, err)
		metrics.RPC.Fetch(l.WithResult(metrics.ErrMismatch)).Inc()
		return cppki.SignedTRC{}, serrors.New("received wrong TRC", "expected", id,
			"actual", trc.TRC.ID)
	}
	metrics.RPC.Fetch(l.WithResult(metrics.Success)).Inc()
	return trc, nil
}

func checkChainsMatchQuery(query ChainQuery, chains [][]*x509.Certificate) error {
	for i, chain := range chains {
		ia, err := cppki.ExtractIA(chain[0].Subject)
		if err != nil {
			return serrors.WrapStr("failed to extract chain ISD-AS", err, "index", i)
		}
		if !query.IA.Equal(*ia) {
			return serrors.New("mismatching ISD-AS",
				"index", i, "expected", query.IA, "actual", *ia)
		}
		if !bytes.Equal(query.SubjectKeyID, chain[0].SubjectKeyId) {
			return serrors.New("mismatching subject key id", "index", i)
		}
		validity := cppki.Validity{NotBefore: chain[0].NotBefore, NotAfter: chain[0].NotAfter}
		if !validity.Contains(query.Date) {
			return serrors.New("chain does not cover query date",
				"index", i, "date", util.TimeToCompact(query.Date), "validity", validity)
		}
	}
	return nil
}
