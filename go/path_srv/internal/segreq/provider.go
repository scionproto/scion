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

package segreq

import (
	"context"
	"errors"
	"math/rand"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

// ErrNoConnectivity indicates that connectivity to the remote PS is not
// available.
const ErrNoConnectivity common.ErrMsg = "no connectivity to remote PS"

// SegSelector selects segments to use for a connection to a remote server.
type SegSelector struct {
	PathDB   pathdb.PathDB
	RevCache revcache.RevCache
}

// SelectSeg selects a suitable segment for the given path db query.
func (s *SegSelector) SelectSeg(ctx context.Context,
	params *query.Params) (*seg.PathSegment, error) {

	res, err := s.PathDB.Get(ctx, params)
	if err != nil {
		return nil, err
	}
	segs := query.Results(res).Segs()
	_, err = segs.FilterSegsErr(func(ps *seg.PathSegment) (bool, error) {
		return revcache.NoRevokedHopIntf(ctx, s.RevCache, ps)
	})
	if err != nil {
		return nil, common.NewBasicError("failed to filter segments", err)
	}
	if len(segs) < 1 {
		return nil, serrors.New("no segments found")
	}
	return segs[rand.Intn(len(segs))], nil
}

type nonCoreDstProvider struct {
	SegSelector
	inspector    infra.ASInspector
	coreChecker  CoreChecker
	localIA      addr.IA
	pathDB       pathdb.PathDB
	topoProvider topology.Provider
}

// Dst provides the server to lookup the segment for the given request.
// Querying for segments that start at the localIA will result in an error,
// since they should be locally resolved.
func (p *nonCoreDstProvider) Dst(ctx context.Context, req segfetcher.Request) (net.Addr, error) {
	if p.localIA.Equal(req.Src) {
		return nil, serrors.WithCtx(segfetcher.ErrInvalidRequest,
			"req", req, "reason", "up segments should be resolved locally")
	}
	dstCore, err := p.coreChecker.IsCore(ctx, req.Dst)
	if err != nil {
		return nil, err
	}
	if dstCore {
		// for a core segment request we have to request the segments at the
		// given start point (core PS).
		return p.coreSvcAddr(ctx, addr.SvcPS, []addr.IA{req.Src})
	}
	// for all other requests, i.e. down requests we can ask any core.
	cores, err := p.inspector.ByAttributes(ctx, p.localIA.I, infra.ASInspectorOpts{
		RequiredAttributes: []infra.Attribute{infra.Core},
	})
	if err != nil {
		return nil, err
	}
	return p.coreSvcAddr(ctx, addr.SvcPS, cores)
}

func (p *nonCoreDstProvider) coreSvcAddr(ctx context.Context, svc addr.HostSVC,
	coreASes []addr.IA) (net.Addr, error) {

	params := &query.Params{
		SegTypes: []proto.PathSegType{proto.PathSegType_up},
		StartsAt: coreASes,
		EndsAt:   []addr.IA{p.localIA},
	}
	seg, err := p.SelectSeg(ctx, params)
	if err != nil {
		return nil, common.NewBasicError(ErrNoConnectivity, err)
	}
	return addrutil.GetPath(svc, seg, p.topoProvider)
}

type coreDstProvider struct {
	SegSelector
	localIA      addr.IA
	pathDB       pathdb.PathDB
	topoProvider topology.Provider
}

func (p *coreDstProvider) Dst(ctx context.Context, req segfetcher.Request) (net.Addr, error) {
	dstISDLocal := req.Dst.I == p.localIA.I
	if dstISDLocal {
		return nil, errors.New("shouldn't need resolution for local dst")
	}
	return p.corePSAddr(ctx, req.Dst.I)
}

func (p *coreDstProvider) corePSAddr(ctx context.Context, destISD addr.ISD) (net.Addr, error) {
	params := &query.Params{
		SegTypes: []proto.PathSegType{proto.PathSegType_core},
		StartsAt: []addr.IA{{I: destISD}},
		EndsAt:   []addr.IA{p.localIA},
	}
	seg, err := p.SelectSeg(ctx, params)
	if err != nil {
		return nil, common.NewBasicError(ErrNoConnectivity, err)
	}
	return addrutil.GetPath(addr.SvcPS, seg, p.topoProvider)
}
