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
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"net"

	"github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/tracing"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/pkg/grpc"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	"github.com/scionproto/scion/go/pkg/trust"
	trustmetrics "github.com/scionproto/scion/go/pkg/trust/internal/metrics"
)

// Fetcher fetches trust material from a remote using gRPC.
type Fetcher struct {
	// IA is the local ISD-AS.
	IA addr.IA
	// Dialer dials a new gRPC connection.
	Dialer grpc.Dialer

	// Requests aggregates all the outgoing requests sent by the fetcher.
	// If it is not initialized, nothing is reported.
	Requests metrics.Counter
}

// Chains fetches certificate chains over the network
func (f Fetcher) Chains(ctx context.Context, query trust.ChainQuery,
	server net.Addr) ([][]*x509.Certificate, error) {

	labels := requestLabels{
		Type:    trustmetrics.ChainReq,
		Trigger: trustmetrics.FromCtx(ctx),
		Peer:    trustmetrics.PeerToLabel(server, f.IA),
	}

	span, ctx := addChainsSpan(ctx, query)
	defer span.Finish()

	logger := log.FromCtx(ctx)
	logger.Debug("Fetch certificate chain from remote",
		"isd_as", query.IA,
		"date", util.TimeToCompact(query.Date),
		"subject_key_id", fmt.Sprintf("%x", query.SubjectKeyID),
		"server", server,
	)

	conn, err := f.Dialer.Dial(ctx, server)
	if err != nil {
		f.updateMetric(span, labels.WithResult(trustmetrics.ErrTransmit), err)
		return nil, serrors.WrapStr("dialing", err)
	}
	defer conn.Close()
	client := cppb.NewTrustMaterialServiceClient(conn)
	rep, err := client.Chains(ctx, chainQueryToReq(query), grpc.RetryProfile...)
	if err != nil {
		f.updateMetric(span, labels.WithResult(trustmetrics.ErrTransmit), err)
		return nil, serrors.WrapStr("receiving chains", err)
	}

	chains, res, err := repToChains(rep.Chains)
	if err != nil {
		f.updateMetric(span, labels.WithResult(res), err)
		return nil, err
	}
	logger.Debug("Received certificate chains from remote",
		"isd_as", query.IA,
		"chains", len(chains),
	)

	if err := checkChainsMatchQuery(query, chains); err != nil {
		f.updateMetric(span, labels.WithResult(trustmetrics.ErrMismatch), err)
		return nil, serrors.WrapStr("chains do not match query", err)
	}
	f.updateMetric(span, labels.WithResult(trustmetrics.Success), nil)
	return chains, nil
}

// TRC fetches the TRC over the network.
func (f Fetcher) TRC(ctx context.Context, id cppki.TRCID,
	server net.Addr) (cppki.SignedTRC, error) {

	labels := requestLabels{
		Type:    trustmetrics.TRCReq,
		Trigger: trustmetrics.FromCtx(ctx),
		Peer:    trustmetrics.PeerToLabel(server, f.IA),
	}
	span, ctx := addTRCSpan(ctx, id)
	defer span.Finish()

	logger := log.FromCtx(ctx)
	logger.Debug("Fetch TRC from remote", "id", id, "server", server)

	conn, err := f.Dialer.Dial(ctx, server)
	if err != nil {
		f.updateMetric(span, labels.WithResult(trustmetrics.ErrTransmit), err)
		return cppki.SignedTRC{}, serrors.WrapStr("dialing", err)
	}
	defer conn.Close()
	client := cppb.NewTrustMaterialServiceClient(conn)
	rep, err := client.TRC(ctx, idToReq(id), grpc.RetryProfile...)
	if err != nil {
		f.updateMetric(span, labels.WithResult(trustmetrics.ErrTransmit), err)
		return cppki.SignedTRC{}, serrors.WrapStr("receiving TRC", err)
	}

	trc, err := cppki.DecodeSignedTRC(rep.Trc)
	if err != nil {
		f.updateMetric(span, labels.WithResult(trustmetrics.ErrParse), err)
		return cppki.SignedTRC{}, serrors.WrapStr("parse TRC reply", err)
	}
	logger.Debug("[trust:Resolver] Received TRC from remote", "id", id)
	if trc.TRC.ID != id {
		f.updateMetric(span, labels.WithResult(trustmetrics.ErrMismatch), err)
		return cppki.SignedTRC{}, serrors.New("received wrong TRC", "expected", id,
			"actual", trc.TRC.ID)
	}
	f.updateMetric(span, labels.WithResult(trustmetrics.Success), nil)
	return trc, nil
}

func (f Fetcher) updateMetric(span opentracing.Span, l requestLabels, err error) {
	if f.Requests != nil {
		f.Requests.With(l.Expand()...).Add(1)
	}
	tracing.ResultLabel(span, l.Result)
	tracing.Error(span, err)
}

func addChainsSpan(ctx context.Context,
	query trust.ChainQuery) (opentracing.Span, context.Context) {

	span, ctx := opentracing.StartSpanFromContext(ctx, "trustengine.fetch_chains")
	tracing.Component(span, "trust")
	span.SetTag("query.isd_as", query.IA)
	span.SetTag("query.subject_key_id", fmt.Sprintf("%x", query.SubjectKeyID))
	span.SetTag("query.date", util.TimeToCompact(query.Date))
	span.SetTag("msgr.stack", "grpc")
	return span, ctx
}

func addTRCSpan(ctx context.Context,
	id cppki.TRCID) (opentracing.Span, context.Context) {

	span, ctx := opentracing.StartSpanFromContext(ctx, "trustengine.fetch_trc")
	defer span.Finish()
	tracing.Component(span, "trust")
	span.SetTag("trc_id.isd", id.ISD)
	span.SetTag("trc_id.base", id.Base)
	span.SetTag("trc_id.serial", id.Serial)
	return span, ctx
}

func checkChainsMatchQuery(query trust.ChainQuery, chains [][]*x509.Certificate) error {
	for i, chain := range chains {
		ia, err := cppki.ExtractIA(chain[0].Subject)
		if err != nil {
			return serrors.WrapStr("extracting ISD-AS", err, "index", i)
		}
		if !query.IA.Equal(ia) {
			return serrors.New("ISD-AS mismatch",
				"index", i, "expected", query.IA, "actual", ia)
		}
		if !bytes.Equal(query.SubjectKeyID, chain[0].SubjectKeyId) {
			return serrors.New("SubjectKeyID mismatch", "index", i)
		}
		validity := cppki.Validity{NotBefore: chain[0].NotBefore, NotAfter: chain[0].NotAfter}
		if !validity.Contains(query.Date) {
			return serrors.New("queried date not covered",
				"index", i, "date", util.TimeToCompact(query.Date), "validity", validity)
		}
	}
	return nil
}

type requestLabels struct {
	Type    string
	Trigger string
	Peer    string
	Result  string
}

func (l requestLabels) Expand() []string {
	return []string{
		"type", l.Type,
		"trigger", l.Trigger,
		"peer", l.Peer,
		prom.LabelResult, l.Result,
	}
}

func (l requestLabels) WithResult(result string) requestLabels {
	l.Result = result
	return l
}
