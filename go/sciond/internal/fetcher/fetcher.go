// Copyright 2018 ETH Zurich, Anapaya Systems
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

// Package fetcher implements path segment fetching, verification and
// combination logic for SCIOND.
package fetcher

import (
	"bytes"
	"context"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/hostinfo"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/combinator"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/sciond/internal/config"
)

const (
	DefaultMinWorkerLifetime = 10 * time.Second
)

type TrustStore interface {
	infra.VerificationFactory
	infra.ASInspector
}

type Fetcher struct {
	pathDB          pathdb.PathDB
	revocationCache revcache.RevCache
	topoProvider    topology.Provider
	config          config.SDConfig
	segfetcher      *segfetcher.Fetcher
}

func NewFetcher(messenger infra.Messenger, pathDB pathdb.PathDB, trustStore TrustStore,
	revCache revcache.RevCache, cfg config.SDConfig, topoProvider topology.Provider,
	logger log.Logger) *Fetcher {

	localIA := topoProvider.Get().ISD_AS
	return &Fetcher{
		pathDB:          pathDB,
		revocationCache: revCache,
		topoProvider:    topoProvider,
		config:          cfg,
		segfetcher: segfetcher.FetcherConfig{
			QueryInterval:       cfg.QueryInterval.Duration,
			LocalIA:             localIA,
			ASInspector:         trustStore,
			VerificationFactory: trustStore,
			PathDB:              pathDB,
			RevCache:            revCache,
			RequestAPI:          messenger,
			DstProvider:         &dstProvider{IA: localIA},
			Splitter:            NewRequestSplitter(localIA, trustStore),
			SciondMode:          true,
		}.New(),
	}
}

func (f *Fetcher) GetPaths(ctx context.Context, req *sciond.PathReq,
	earlyReplyInterval time.Duration, logger log.Logger) (*sciond.PathReply, error) {

	handler := &fetcherHandler{
		Fetcher:  f,
		topology: f.topoProvider.Get(),
		logger:   logger,
	}
	return handler.GetPaths(ctx, req, earlyReplyInterval)
}

// fetcherHandler contains the custom state of one path retrieval request
// received by the Fetcher.
type fetcherHandler struct {
	*Fetcher
	topology *topology.Topo
	logger   log.Logger
}

// GetPaths fulfills the path request described by req. GetPaths will attempt
// to build paths at start, after earlyReplyInterval and at context expiration
// (or whenever all background workers return). An earlyReplyInterval of 0
// means no early reply attempt is made.
func (f *fetcherHandler) GetPaths(ctx context.Context, req *sciond.PathReq,
	earlyReplyInterval time.Duration) (*sciond.PathReply, error) {

	// TODO(lukedirtwalker): move to validator, but we need to keep sciond
	// error codes.
	req = req.Copy()
	// Check context
	if _, ok := ctx.Deadline(); !ok {
		return nil, serrors.New("Context must have deadline set")
	}
	// Check source
	if req.Src.IA().IsZero() {
		req.Src = f.topology.ISD_AS.IAInt()
	}
	if !req.Src.IA().Equal(f.topology.ISD_AS) {
		return f.buildSCIONDReply(nil, 0, sciond.ErrorBadSrcIA),
			common.NewBasicError("Bad source AS", nil, "ia", req.Src.IA())
	}
	// Check destination
	if req.Dst.IA().I == 0 {
		return f.buildSCIONDReply(nil, 0, sciond.ErrorBadDstIA),
			common.NewBasicError("Bad destination AS", nil, "ia", req.Dst.IA())
	}
	if req.Dst.IA().Equal(f.topology.ISD_AS) {
		return f.buildSCIONDReply(nil, 0, sciond.ErrorOk), nil
	}
	if req.Flags.Refresh {
		// This is a workaround for https://github.com/scionproto/scion/issues/1876
		err := f.flushSegmentsWithFirstHopInterfaces(ctx)
		if err != nil {
			f.logger.Error("Failed to flush segments with first hop interfaces", "err", err)
			// continue anyway, things might still work out for the client.
		}
	}
	// A ISD-0 destination should not require a TRC lookup in sciond, it could lead to a
	// lookup loop: If sciond doesn't have the TRC, it would ask the CS, the CS would try to connect
	// to the CS in the destination ISD and for that it will ask sciond for paths to ISD-0.
	// Instead we consider ISD-0 always as core destination in sciond.
	// If there are no cached paths in sciond, send the query to the local PS,
	// which will forward the query to a ISD-local core PS, so there won't be
	// any loop.

	segs, err := f.segfetcher.FetchSegs(ctx,
		segfetcher.Request{Src: req.Src.IA(), Dst: req.Dst.IA()})
	if err != nil {
		return f.buildSCIONDReply(nil, 0, sciond.ErrorInternal), err
	}
	paths := f.buildPathsToAllDsts(req, segs.Up, segs.Core, segs.Down)
	paths, err = f.filterRevokedPaths(ctx, paths)
	if err != nil {
		return f.buildSCIONDReply(nil, 0, sciond.ErrorInternal), err
	}
	return f.buildSCIONDReply(paths, req.MaxPaths, sciond.ErrorOk), nil
}

// buildSCIONDReply constructs a fresh SCIOND PathReply from the information
// contained in paths. Information from the topology is used to populate the
// HostInfo field.
//
// If an error (so anything other that ErrorOk) is specified, a reply
// containing no path and the error is returned. For no error and len(paths) =
// 0, a reply containing an empty path is returned. For no error and non-zero
// len(paths), a path reply containing each path for which a BR could be found
// in the topology is returned. If no such paths exist, a reply containing no
// path and an internal error is returned.
func (f *fetcherHandler) buildSCIONDReply(paths []*combinator.Path,
	maxPaths uint16, errCode sciond.PathErrorCode) *sciond.PathReply {

	var entries []sciond.PathReplyEntry
	if errCode == sciond.ErrorOk {
		entries = f.buildSCIONDReplyEntries(paths, maxPaths)
	}
	return &sciond.PathReply{
		ErrorCode: errCode,
		Entries:   entries,
	}
}

// buildSCIONDReplyEntries returns a slice of sciond.PathReplyEntry objects
// from the metadata contained within paths.
//
// If paths is nil or contains zero entries, a slice containing a single
// PathReplyEntry is returned. The Entry contains an empty RawFwdPath, the MTU
// set to the MTU of the local AS and an expiration time of time.Now() +
// MAX_SEGMENT_TTL.
//
// The length of the returned slice is not guaranteed to be the same length as
// paths, as some paths might contain invalid first IFIDs that are not
// associated to any BR. Thus, it is possible for len(paths) to be non-zero
// length and the returned slice be of zero length.
func (f *fetcherHandler) buildSCIONDReplyEntries(paths []*combinator.Path,
	maxPaths uint16) []sciond.PathReplyEntry {

	var entries []sciond.PathReplyEntry
	if len(paths) == 0 {
		// Return a single entry with an empty path
		return []sciond.PathReplyEntry{
			{
				Path: &sciond.FwdPathMeta{
					FwdPath:    []byte{},
					Mtu:        uint16(f.topology.MTU),
					Interfaces: []sciond.PathInterface{},
					ExpTime:    util.TimeToSecs(time.Now().Add(spath.MaxTTL * time.Second)),
				},
			},
		}
	}
	for _, path := range paths {
		x := &bytes.Buffer{}
		_, err := path.WriteTo(x)
		if err != nil {
			// In-memory write should never fail
			panic(err)
		}
		ifInfo, ok := f.topology.IFInfoMap[path.Interfaces[0].IfID]
		if !ok {
			f.logger.Warn("Unable to find first-hop BR for path", "ifid", path.Interfaces[0].IfID)
			continue
		}
		entries = append(entries, sciond.PathReplyEntry{
			Path: &sciond.FwdPathMeta{
				FwdPath:    x.Bytes(),
				Mtu:        path.Mtu,
				Interfaces: path.Interfaces,
				ExpTime:    uint32(path.ComputeExpTime().Unix()),
			},
			HostInfo: hostinfo.FromTopoBRAddr(*ifInfo.InternalAddrs),
		})
		if maxPaths != 0 && len(entries) == int(maxPaths) {
			break
		}
	}
	return entries
}

// filterRevokedPaths returns a new slice containing only those paths that do
// not have revoked interfaces in their forwarding path. Only the interfaces
// that have traffic going through them are checked.
func (f *fetcherHandler) filterRevokedPaths(ctx context.Context,
	paths []*combinator.Path) ([]*combinator.Path, error) {

	prevPaths := len(paths)
	var newPaths []*combinator.Path
	for _, path := range paths {
		revoked := false
		for _, iface := range path.Interfaces {
			// cache automatically expires outdated revocations every second,
			// so a cache hit implies revocation is still active.
			revs, err := f.revocationCache.Get(ctx, revcache.SingleKey(iface.IA(), iface.IfID))
			if err != nil {
				f.logger.Error("Failed to get revocation", "err", err)
				// continue, the client might still get some usable paths like this.
			}
			revoked = revoked || len(revs) > 0
		}
		if !revoked {
			newPaths = append(newPaths, path)
		}
	}
	f.logger.Trace("Filtered paths with revocations",
		"paths", prevPaths, "nonrevoked", len(newPaths))
	return newPaths, nil
}

func (f *fetcherHandler) flushSegmentsWithFirstHopInterfaces(ctx context.Context) error {
	intfs := make([]*query.IntfSpec, 0, len(f.topology.IFInfoMap))
	for ifid := range f.topology.IFInfoMap {
		intfs = append(intfs, &query.IntfSpec{
			IA:   f.topology.ISD_AS,
			IfID: ifid,
		})
	}
	q := &query.Params{
		Intfs: intfs,
	}
	// this is a bit involved, we have to delete the next query cache,
	// otherwise it could be that next query is in the future but we don't have
	// any segments stored. Note that just deleting nextquery with start or end
	// IA equal to local IA is not enough, e.g. down segments can actually pass
	// through our AS but neither end nor start in our AS.
	tx, err := f.pathDB.BeginTransaction(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Get(ctx, q)
	if err != nil {
		return err
	}
	if err := segfetcher.DeleteNextQueryEntries(ctx, tx, res); err != nil {
		return err
	}
	_, err = tx.Delete(ctx, q)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (f *fetcherHandler) buildPathsToAllDsts(req *sciond.PathReq,
	ups, cores, downs seg.Segments) []*combinator.Path {

	dsts := f.determineDsts(req, ups, cores)
	var paths []*combinator.Path
	for dst := range dsts {
		paths = append(paths, combinator.Combine(req.Src.IA(), dst, ups, cores, downs)...)
	}
	return filterExpiredPaths(paths)
}

func (f *fetcherHandler) determineDsts(req *sciond.PathReq,
	ups, cores seg.Segments) map[addr.IA]struct{} {

	wildcardDst := req.Dst.IA().A == 0
	if wildcardDst {
		isdLocal := req.Dst.IA().I == f.topology.ISD_AS.I
		return wildcardDsts(wildcardDst, isdLocal, ups, cores)
	}
	return map[addr.IA]struct{}{req.Dst.IA(): {}}
}

func wildcardDsts(wildcard, isdLocal bool, ups, cores seg.Segments) map[addr.IA]struct{} {
	newDsts := cores.FirstIAs()
	if isdLocal {
		// for isd local wildcard we want to reach cores, they are at the end of the up segs.
		newDsts = append(newDsts, ups.FirstIAs()...)
	}
	dsts := make(map[addr.IA]struct{})
	for _, dst := range newDsts {
		dsts[dst] = struct{}{}
	}
	return dsts
}

func filterExpiredPaths(paths []*combinator.Path) []*combinator.Path {
	var validPaths []*combinator.Path
	now := time.Now()
	for _, path := range paths {
		if path.ComputeExpTime().After(now) {
			validPaths = append(validPaths, path)
		}
	}
	return validPaths
}

type dstProvider struct {
	IA addr.IA
}

func (r *dstProvider) Dst(_ context.Context, _ segfetcher.Request) (net.Addr, error) {
	return &snet.Addr{IA: r.IA, Host: addr.NewSVCUDPAppAddr(addr.SvcPS)}, nil
}
