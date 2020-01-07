// Copyright 2018 Anapaya Systems
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

package handlers

import (
	"context"
	"time"

	"github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/topology"
)

const (
	NoSegmentsErr = "No segments"
)

// HandlerArgs are the values required to create the path server's handlers.
type HandlerArgs struct {
	PathDB          pathdb.PathDB
	RevCache        revcache.RevCache
	ASInspector     infra.ASInspector
	VerifierFactory infra.VerificationFactory
	QueryInterval   time.Duration
	IA              addr.IA
	TopoProvider    topology.Provider
	SegRequestAPI   segfetcher.RequestAPI
}

type baseHandler struct {
	request         *infra.Request
	pathDB          pathdb.PathDB
	revCache        revcache.RevCache
	inspector       infra.ASInspector
	verifierFactory infra.VerificationFactory
	topoProvider    topology.Provider
	retryInt        time.Duration
	queryInt        time.Duration
}

func newBaseHandler(request *infra.Request, args HandlerArgs) *baseHandler {
	return &baseHandler{
		request:         request,
		pathDB:          args.PathDB,
		revCache:        args.RevCache,
		inspector:       args.ASInspector,
		verifierFactory: args.VerifierFactory,
		retryInt:        500 * time.Millisecond,
		queryInt:        args.QueryInterval,
		topoProvider:    args.TopoProvider,
	}
}

// fetchSegsFromDB gets segments from the path DB and filters revoked segments.
func (h *baseHandler) fetchSegsFromDB(ctx context.Context,
	params *query.Params) ([]*seg.PathSegment, error) {

	res, err := h.pathDB.Get(ctx, params)
	if err != nil {
		return nil, err
	}
	segs := query.Results(res).Segs()
	// XXX(lukedirtwalker): Consider cases where segment with revoked interfaces should be returned.
	_, err = segs.FilterSegsErr(func(s *seg.PathSegment) (bool, error) {
		noRevoked, err := revcache.NoRevokedHopIntf(ctx, h.revCache, s)
		if err != nil {
			return false, err
		}
		return noRevoked && time.Now().Before(s.MaxExpiry()), nil
	})
	if err != nil {
		return nil, common.NewBasicError("Failed to filter segments", err)
	}
	return segs, nil
}

// fetchSegsFromDBRetry calls fetchSegsFromDB and if this results in no segments,
// this method retries until either there is a result, or the context timed out.
//
// Note that looping is not the most efficient way to do this. We could also have a channel
// from the segReg handler to the segReq handlers, but this leads to a more complex logic
// (handlers are no longer independent).
// Also this would need to make sure that this is the only process that writes to the DB.
//
// If this is ever not performant enough it makes sense to change the logic.
// Retries should happen mostly at startup and otherwise very rarely.
func (h *baseHandler) fetchSegsFromDBRetry(ctx context.Context,
	params *query.Params) ([]*seg.PathSegment, error) {

	for {
		upSegs, err := h.fetchSegsFromDB(ctx, params)
		if err != nil || len(upSegs) > 0 {
			return upSegs, err
		}
		if err := h.sleepOrTimeout(ctx); err != nil {
			return nil, err
		}
	}
}

func (h *baseHandler) sleepOrTimeout(ctx context.Context) error {
	var span opentracing.Span
	span, ctx = opentracing.StartSpanFromContext(ctx, "sleep.wait")
	defer span.Finish()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(h.retryInt):
		return nil
	}
}
