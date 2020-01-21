// Copyright 2019 Anapaya Systems
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
	"context"
	"errors"
	"net"

	"github.com/opentracing/opentracing-go"
	opentracingext "github.com/opentracing/opentracing-go/ext"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/decoded"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/metrics"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/serrors"
)

var (
	// ErrResolveSuperseded indicates that the latest locally available TRC
	// supersedes the TRC to resolve.
	ErrResolveSuperseded = serrors.New("latest locally available is newer")
	// ErrInvalidResponse indicates an invalid response to an RPC call.
	ErrInvalidResponse = serrors.New("invalid RPC response")
)

// Resolver resolves verified trust material.
type Resolver interface {
	// TRC resolves the decoded signed TRC. Missing links in the TRC
	// verification chain are also requested.
	TRC(ctx context.Context, req TRCReq, server net.Addr) (decoded.TRC, error)
	// Chain resolves the raw signed certificate chain. If the issuing TRC is
	// missing, it is also requested.
	Chain(ctx context.Context, req ChainReq, server net.Addr) (decoded.Chain, error)
}

// DefaultResolver resolves trust material.
type DefaultResolver struct {
	DB       DBRead
	Inserter Inserter
	RPC      RPC
	IA       addr.IA
}

// TRC resolves the decoded signed TRC. Missing links in the TRC
// verification chain are also requested.
func (r DefaultResolver) TRC(parentCtx context.Context, req TRCReq,
	server net.Addr) (decoded.TRC, error) {

	span, ctx := opentracing.StartSpanFromContext(parentCtx, "resolve_trc")
	defer span.Finish()
	opentracingext.Component.Set(span, "trust")
	span.SetTag("isd", req.ISD)
	span.SetTag("version", req.Version)
	logger := log.FromCtx(ctx)

	if req.Version.IsLatest() {
		logger.Debug("[TrustStore:Resolver] Resolving latest version of TRC", "isd", req.ISD)
		latest, err := r.resolveLatestVersion(ctx, req, server)
		if err != nil {
			return decoded.TRC{}, serrors.WrapStr("error resolving latest TRC version number", err)
		}
		req = req.withVersion(latest)
		logger.Debug("[TrustStore:Resolver] Resolved latest version of TRC",
			"isd", req.ISD, "version", req.Version)
	}
	prev, err := r.DB.GetTRC(ctx, TRCID{ISD: req.ISD, Version: scrypto.LatestVer})
	if err != nil && !errors.Is(err, ErrNotFound) {
		return decoded.TRC{}, serrors.WrapStr("error fetching latest locally available TRC", err)
	}
	if prev != nil && prev.Version >= req.Version {
		return decoded.TRC{}, serrors.WithCtx(ErrResolveSuperseded, "requested", req.Version,
			"latest", prev.Version)
	}
	min := scrypto.Version(1)
	// If a previous TRC was found, use that as base case.
	if err == nil {
		min = prev.Version + 1
	}
	// Use slice of channels because the ordering of TRC replies matters.
	results := make([]chan resOrErr, req.Version-min+1)
	for i := range results {
		// buffered channel to avoid go routine leak.
		results[i] = make(chan resOrErr, 1)
		ireq := req.withVersion(min + scrypto.Version(i))
		r.startFetchTRC(ctx, results[i], ireq, server)
	}
	var decTRC decoded.TRC
	var w prevWrap
	w.SetTRC(prev)
	for i, resC := range results {
		l := metrics.ResolverLabels{Type: metrics.TRCReq, Trigger: metrics.FromCtx(ctx),
			Peer: peerToLabel(server, r.IA)}
		res := <-resC
		if res.Err != nil {
			// Ensure metrics are set even with short-circuit.
			metrics.Resolver.Fetch(l.WithResult(errToLabel(err))).Add(float64(len(results) - i))
			return decoded.TRC{}, serrors.WrapStr("unable to fetch TRC chain link", err)
		}
		decTRC = res.Decoded
		if err = r.Inserter.InsertTRC(ctx, decTRC, w.TRC); err != nil {
			// Ensure metrics are set even with short-circuit.
			metrics.Resolver.Fetch(l.WithResult(errToLabel(err))).Add(float64(len(results) - i))
			return decoded.TRC{}, serrors.WrapStr("unable to insert TRC chain link", err,
				"trc", decTRC)
		}
		metrics.Resolver.Fetch(l.WithResult(metrics.Success)).Inc()
		logger.Debug("[TrustStore:Resolver] Inserted resolved TRC", "isd", decTRC.TRC.ISD,
			"version", decTRC.TRC.Version)
		w.SetTRC(decTRC.TRC)
	}
	return decTRC, nil
}

// FIXME(roosd): Add RPC that resolves just the latest version instead of the
// full TRC.
func (r DefaultResolver) resolveLatestVersion(ctx context.Context, req TRCReq,
	server net.Addr) (scrypto.Version, error) {

	l := metrics.ResolverLabels{Type: metrics.LatestTRC, Trigger: metrics.FromCtx(ctx),
		Peer: peerToLabel(server, r.IA)}
	rawTRC, err := r.RPC.GetTRC(ctx, req, server)
	if err != nil {
		metrics.Resolver.Fetch(l.WithResult(metrics.ErrTransmit)).Inc()
		return 0, err
	}
	decTRC, err := decoded.DecodeTRC(rawTRC)
	if err != nil {
		metrics.Resolver.Fetch(l.WithResult(metrics.ErrParse)).Inc()
		return 0, err
	}
	if err := r.trcCheck(req, decTRC.TRC); err != nil {
		metrics.Resolver.Fetch(l.WithResult(errToLabel(err))).Inc()
		return 0, serrors.Wrap(ErrInvalidResponse, err)
	}
	metrics.Resolver.Fetch(l.WithResult(metrics.Success)).Inc()
	return decTRC.TRC.Version, nil
}

func (r DefaultResolver) startFetchTRC(parentCtx context.Context, res chan<- resOrErr,
	req TRCReq, server net.Addr) {

	go func() {
		span, ctx := opentracing.StartSpanFromContext(parentCtx, "resolve_trc_link")
		defer span.Finish()
		opentracingext.Component.Set(span, "trust")
		span.SetTag("isd", req.ISD)
		span.SetTag("version", req.Version)
		logger := log.FromCtx(ctx)

		defer log.LogPanicAndExit()
		logger.Debug("[TrustStore:Resolver] Fetch TRC from remote", "isd", req.ISD,
			"version", req.Version, "server", server)
		rawTRC, err := r.RPC.GetTRC(ctx, req, server)
		if err != nil {
			res <- resOrErr{Err: serrors.WithCtx(err, "version", req.Version)}
			return
		}
		logger.Debug("[TrustStore:Resolver] Received TRC from remote",
			"isd", req.ISD, "version", req.Version)
		decTRC, err := decoded.DecodeTRC(rawTRC)
		if err != nil {
			res <- resOrErr{Err: serrors.WithCtx(err, "version", req.Version)}
			return
		}
		if err := r.trcCheck(req, decTRC.TRC); err != nil {
			res <- resOrErr{Err: serrors.Wrap(ErrInvalidResponse, err, "version", req.Version)}
			return
		}
		res <- resOrErr{Decoded: decTRC}
	}()
}

func (r DefaultResolver) trcCheck(req TRCReq, t *trc.TRC) error {
	switch {
	case req.ISD != t.ISD:
		return serrors.WithCtx(ErrValidation, "msg", "wrong isd",
			"expected", req.ISD, "actual", t.ISD)
	case !req.Version.IsLatest() && req.Version != t.Version:
		return serrors.WithCtx(ErrValidation, "msg", "wrong version",
			"expected", req.Version, "actual", t.Version)
	}
	return nil
}

// Chain resolves the raw signed certificate chain. If the issuing TRC is
// missing, it is also requested.
func (r DefaultResolver) Chain(parentCtx context.Context, req ChainReq,
	server net.Addr) (decoded.Chain, error) {

	l := metrics.ResolverLabels{Type: metrics.ChainReq, Trigger: metrics.FromCtx(parentCtx),
		Peer: peerToLabel(server, r.IA)}
	span, ctx := opentracing.StartSpanFromContext(parentCtx, "resolve_chain")
	defer span.Finish()
	opentracingext.Component.Set(span, "trust")
	span.SetTag("ia", req.IA)
	span.SetTag("version", req.Version)
	logger := log.FromCtx(ctx)

	logger.Debug("[TrustStore:Resolver] Fetch certificate chain from remote", "ia", req.IA,
		"version", req.Version, "server", server)
	msg, err := r.RPC.GetCertChain(ctx, req, server)
	if err != nil {
		metrics.Resolver.Fetch(l.WithResult(metrics.ErrTransmit)).Inc()
		return decoded.Chain{}, err
	}
	logger.Debug("[TrustStore:Resolver] Received certificate chain from remote", "ia", req.IA,
		"version", req.Version)
	dec, err := decoded.DecodeChain(msg)
	if err != nil {
		metrics.Resolver.Fetch(l.WithResult(metrics.ErrParse)).Inc()
		return decoded.Chain{}, err
	}
	if err := r.chainCheck(req, dec.AS); err != nil {
		metrics.Resolver.Fetch(l.WithResult(metrics.ErrTransmit)).Inc()
		return decoded.Chain{}, serrors.Wrap(ErrInvalidResponse, err)
	}
	w := resolveWrap{
		resolver: r,
		server:   server,
	}
	if err := r.Inserter.InsertChain(ctx, dec, w.TRC); err != nil {
		metrics.Resolver.Fetch(l.WithResult(errToLabel(err))).Inc()
		return decoded.Chain{}, serrors.WrapStr("unable to insert certificate chain", err,
			"chain", dec)
	}
	metrics.Resolver.Fetch(l.WithResult(metrics.Success)).Inc()
	return dec, nil
}

func (r DefaultResolver) chainCheck(req ChainReq, as *cert.AS) error {
	switch {
	case !req.IA.Equal(as.Subject):
		return serrors.WithCtx(ErrValidation, "msg", "wrong subject",
			"expected", req.IA, "actual", as.Subject)
	case !req.Version.IsLatest() && req.Version != as.Version:
		return serrors.WithCtx(ErrValidation, "msg", "wrong version",
			"expected", req.Version, "actual", as.Version)
	}
	return nil
}

type resOrErr struct {
	Decoded decoded.TRC
	Err     error
}

// prevWrap provides one single previous TRC. It is used in the TRC chain
// verification to avoid unnecessary database access.
type prevWrap struct {
	prev *trc.TRC
}

func (w *prevWrap) SetTRC(prev *trc.TRC) {
	w.prev = prev
}

func (w *prevWrap) TRC(_ context.Context, id TRCID) (*trc.TRC, error) {
	if id.ISD != w.prev.ISD || id.Version != w.prev.Version {
		return nil, serrors.New("previous wrapper can only provide a single TRC",
			"expected_isd", w.prev.ISD, "expected_version", w.prev.Version,
			"actual_isd", id.ISD, "actual_version", id.Version)
	}
	return w.prev, nil
}

// resolverWrap provides TRCs that are backed by the resolver. If a TRC is
// missing in the DB, network requests are allowed.
type resolveWrap struct {
	resolver DefaultResolver
	server   net.Addr
}

func (w resolveWrap) TRC(ctx context.Context, id TRCID) (*trc.TRC, error) {
	t, err := w.resolver.DB.GetTRC(ctx, id)
	switch {
	case err == nil:
		return t, nil
	case !errors.Is(err, ErrNotFound):
		return nil, serrors.WrapStr("error querying DB for TRC", err)
	}
	req := TRCReq{
		ISD:     id.ISD,
		Version: id.Version,
	}
	decoded, err := w.resolver.TRC(ctx, req, w.server)
	if err != nil {
		return nil, serrors.WrapStr("unable to fetch TRC from network", err)
	}
	return decoded.TRC, nil
}
