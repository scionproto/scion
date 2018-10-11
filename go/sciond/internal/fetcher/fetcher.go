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
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/combinator"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/infra/modules/segsaver"
	"github.com/scionproto/scion/go/lib/infra/modules/segverifier"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
	"github.com/scionproto/scion/go/sciond/internal/sdconfig"
)

const (
	DefaultMinWorkerLifetime = 10 * time.Second
)

// requestID is used to generate unique request IDs for the messenger.
var requestID messenger.Counter

type Fetcher struct {
	messenger       infra.Messenger
	pathDB          pathdb.PathDB
	trustStore      infra.TrustStore
	revocationCache revcache.RevCache
	config          sdconfig.Config
	logger          log.Logger
}

func NewFetcher(messenger infra.Messenger, pathDB pathdb.PathDB,
	trustStore infra.TrustStore, revCache revcache.RevCache, cfg sdconfig.Config,
	logger log.Logger) *Fetcher {

	return &Fetcher{
		messenger:       messenger,
		pathDB:          pathDB,
		trustStore:      trustStore,
		revocationCache: revCache,
		config:          cfg,
		logger:          logger,
	}
}

func (f *Fetcher) GetPaths(ctx context.Context, req *sciond.PathReq,
	earlyReplyInterval time.Duration) (*sciond.PathReply, error) {

	handler := &fetcherHandler{Fetcher: f, topology: itopo.GetCurrentTopology()}
	return handler.GetPaths(ctx, req, earlyReplyInterval)
}

// fetcherHandler contains the custom state of one path retrieval request
// received by the Fetcher.
type fetcherHandler struct {
	*Fetcher
	topology *topology.Topo
}

// GetPaths fulfills the path request described by req. GetPaths will attempt
// to build paths at start, after earlyReplyInterval and at context expiration
// (or whenever all background workers return). An earlyReplyInterval of 0
// means no early reply attempt is made.
func (f *fetcherHandler) GetPaths(ctx context.Context, req *sciond.PathReq,
	earlyReplyInterval time.Duration) (*sciond.PathReply, error) {

	req = req.Copy()
	// Check context
	if _, ok := ctx.Deadline(); !ok {
		return nil, common.NewBasicError("Context must have deadline set", nil)
	}
	// Check source
	if req.Src.IA().IsZero() {
		req.Src = f.topology.ISD_AS.IAInt()
	}
	if !req.Src.IA().Eq(f.topology.ISD_AS) {
		return f.buildSCIONDReply(nil, sciond.ErrorBadSrcIA),
			common.NewBasicError("Bad source AS", nil, "ia", req.Src.IA())
	}
	// Commit to a path server, and use it for path and crypto queries
	svcInfo, err := f.topology.GetSvcInfo(proto.ServiceType_ps)
	if err != nil {
		return nil, err
	}
	topoAddr := svcInfo.GetAnyTopoAddr()
	if topoAddr == nil {
		return nil, common.NewBasicError("Failed to look up PS in topology", nil)
	}
	psAddr := topoAddr.PublicAddr(f.topology.Overlay)
	psOverlayAddr := topoAddr.OverlayAddr(f.topology.Overlay)
	ps := &snet.Addr{IA: f.topology.ISD_AS, Host: psAddr, NextHop: psOverlayAddr}
	// Check destination
	if req.Dst.IA().I == 0 {
		return f.buildSCIONDReply(nil, sciond.ErrorBadDstIA),
			common.NewBasicError("Bad destination AS", nil, "ia", req.Dst.IA())
	}
	if req.Dst.IA().Eq(f.topology.ISD_AS) {
		return f.buildSCIONDReply(nil, sciond.ErrorOk), nil
	}
	// A ISD-0 destination should not require a TRC lookup in sciond, it could lead to a
	// lookup loop: If sciond doesn't have the TRC, it would ask the CS, the CS would try to connect
	// to the CS in the destination ISD and for that it will ask sciond for paths to ISD-0.
	// Instead we consider ISD-0 always as core destination in sciond.
	// If there are no cached paths in sciond, send the query to the local PS,
	// which will forward the query to a ISD-local core PS, so there won't be any loop.

	refetch, err := f.shouldRefetchSegs(ctx, req)
	if err != nil {
		f.logger.Warn("Failed to check if refetch is required", "err", err)
	}
	// Try to build paths from local information first, if we don't have to
	// get fresh segments.
	if !req.Flags.Refresh && !refetch {
		paths, err := f.buildPathsFromDB(ctx, req)
		switch {
		case ctx.Err() != nil:
			return f.buildSCIONDReply(nil, sciond.ErrorNoPaths), nil
		case err != nil && common.GetErrorMsg(err) == trust.ErrNotFoundLocally:
		case err != nil:
			return f.buildSCIONDReply(nil, sciond.ErrorInternal), err
		case err == nil && len(paths) > 0:
			return f.buildSCIONDReply(paths, sciond.ErrorOk), nil
		}
	}
	if req.Flags.Refresh {
		// This is a workaround for https://github.com/scionproto/scion/issues/1876
		err := f.flushSegmentsWithFirstHopInterfaces(ctx)
		if err != nil {
			f.logger.Error("Failed to flush segments with first hop interfaces", "err", err)
			// continue anyway, things might still work out for the client.
		}
	}
	// We don't have enough local information, grab fresh segments from the
	// network. The spawned goroutine takes care of updating the path database
	// and revocation cache.
	subCtx, cancelF := NewExtendedContext(ctx, DefaultMinWorkerLifetime)
	earlyTrigger := util.NewTrigger(earlyReplyInterval)
	go f.fetchAndVerify(subCtx, cancelF, req, earlyTrigger, ps)
	// Wait for deadlines while also waiting for the early reply.
	select {
	case <-earlyTrigger.Done():
	case <-subCtx.Done():
	case <-ctx.Done():
	}
	if ctx.Err() == nil {
		_, err = f.pathDB.InsertNextQuery(ctx, req.Dst.IA(),
			time.Now().Add(f.config.QueryInterval.Duration))
		if err != nil {
			f.logger.Warn("Failed to update nextQuery", "err", err)
		}
	}
	paths, err := f.buildPathsFromDB(ctx, req)
	switch {
	case ctx.Err() != nil:
		return f.buildSCIONDReply(nil, sciond.ErrorNoPaths), nil
	case err != nil:
		return f.buildSCIONDReply(nil, sciond.ErrorInternal), err
	case err == nil && len(paths) > 0:
		return f.buildSCIONDReply(paths, sciond.ErrorOk), nil
	}
	// If we reached this point because the early reply fired but we still
	// weren't able to build and paths, wait as much as possible for new
	// segments and try again.
	if earlyTrigger.Triggered() {
		select {
		case <-subCtx.Done():
		case <-ctx.Done():
		}
		paths, err := f.buildPathsFromDB(ctx, req)
		switch {
		case ctx.Err() != nil:
			return f.buildSCIONDReply(nil, sciond.ErrorNoPaths), nil
		case err != nil:
			return f.buildSCIONDReply(nil, sciond.ErrorInternal), err
		case err == nil && len(paths) > 0:
			return f.buildSCIONDReply(paths, sciond.ErrorOk), nil
		}
	}
	// Your paths are in another castle
	return f.buildSCIONDReply(nil, sciond.ErrorNoPaths), nil
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
	errCode sciond.PathErrorCode) *sciond.PathReply {

	var entries []sciond.PathReplyEntry
	if errCode == sciond.ErrorOk {
		entries = f.buildSCIONDReplyEntries(paths)
		if len(entries) == 0 {
			// We dropped all the entries because we couldn't find the next hops
			// from the IFIDs
			errCode = sciond.ErrorInternal
		}
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
func (f *fetcherHandler) buildSCIONDReplyEntries(paths []*combinator.Path) []sciond.PathReplyEntry {
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
			HostInfo: sciond.HostInfoFromTopoBRAddr(*ifInfo.InternalAddrs),
		})
	}
	return entries
}

// buildPathsFromDB attempts to build paths only from information contained in the
// local path database, taking the revocation cache into account.
func (f *fetcherHandler) buildPathsFromDB(ctx context.Context,
	req *sciond.PathReq) ([]*combinator.Path, error) {

	// Try to determine whether the destination AS is core or not
	subCtx, subCancelF := context.WithTimeout(ctx, time.Second)
	defer subCancelF()
	dstTrc, err := f.trustStore.GetValidCachedTRC(subCtx, req.Dst.IA().I)
	if err != nil {
		// There are situations where we cannot tell if the remote is core. In
		// these cases we just error out, and calling code will try to get path
		// segments. When buildPaths is called again, err should be nil and the
		// function will proceed to the next part.
		return nil, err
	}
	localTrc, err := f.trustStore.GetValidTRC(ctx, f.topology.ISD_AS.I, nil)
	if err != nil {
		return nil, err
	}
	srcIsCore := localTrc.CoreASes.Contains(f.topology.ISD_AS)
	dstIsCore := req.Dst.IA().A == 0 || dstTrc.CoreASes.Contains(req.Dst.IA())
	// pathdb expects slices
	srcIASlice := []addr.IA{req.Src.IA()}
	dstIASlice := []addr.IA{req.Dst.IA()}
	// query pathdb and fill in the relevant segments below
	var ups, cores, downs seg.Segments
	switch {
	case srcIsCore && dstIsCore:
		// Gone corin'
		cores, err = f.getSegmentsFromDB(ctx, dstIASlice, srcIASlice, proto.PathSegType_core)
		if err != nil {
			return nil, err
		}
	case srcIsCore && !dstIsCore:
		cores, err = f.getSegmentsFromDB(ctx, dstTrc.CoreASes.ASList(), srcIASlice,
			proto.PathSegType_core)
		if err != nil {
			return nil, err
		}
		downs, err = f.getSegmentsFromDB(ctx, dstTrc.CoreASes.ASList(), dstIASlice,
			proto.PathSegType_down)
		if err != nil {
			return nil, err
		}
	case !srcIsCore && dstIsCore:
		ups, err = f.getSegmentsFromDB(ctx, localTrc.CoreASes.ASList(), srcIASlice,
			proto.PathSegType_up)
		if err != nil {
			return nil, err
		}
		cores, err = f.getSegmentsFromDB(ctx, dstIASlice, localTrc.CoreASes.ASList(),
			proto.PathSegType_core)
		if err != nil {
			return nil, err
		}
	case !srcIsCore && !dstIsCore:
		ups, err = f.getSegmentsFromDB(ctx, localTrc.CoreASes.ASList(), srcIASlice,
			proto.PathSegType_up)
		if err != nil {
			return nil, err
		}
		downs, err = f.getSegmentsFromDB(ctx, dstTrc.CoreASes.ASList(), dstIASlice,
			proto.PathSegType_down)
		if err != nil {
			return nil, err
		}
		cores, err = f.getSegmentsFromDB(ctx, downs.FirstIAs(), ups.FirstIAs(),
			proto.PathSegType_core)
		if err != nil {
			return nil, err
		}
	}
	paths := buildPathsToAllDsts(req, ups, cores, downs)
	paths = f.filterRevokedPaths(paths)
	return paths, nil
}

func (f *Fetcher) getSegmentsFromDB(ctx context.Context, startsAt,
	endsAt []addr.IA, segType proto.PathSegType) ([]*seg.PathSegment, error) {

	// We shouldn't query with zero length slices. Doing so would return too many segments.
	if len(startsAt) == 0 || len(endsAt) == 0 {
		return nil, nil
	}
	results, err := f.pathDB.Get(ctx, &query.Params{
		StartsAt: startsAt,
		EndsAt:   endsAt,
		SegTypes: []proto.PathSegType{segType},
	})
	if err != nil {
		return nil, err
	}
	return query.Results(results).Segs(), nil
}

// filterRevokedPaths returns a new slice containing only those paths that do
// not have revoked interfaces in their forwarding path. Only the interfaces
// that have traffic going through them are checked.
func (f *fetcherHandler) filterRevokedPaths(paths []*combinator.Path) []*combinator.Path {
	var newPaths []*combinator.Path
	for _, path := range paths {
		revoked := false
		for _, iface := range path.Interfaces {
			// cache automatically expires outdated revocations every second,
			// so a cache hit implies revocation is still active.
			if _, ok := f.revocationCache.Get(revcache.NewKey(iface.ISD_AS(), iface.IfID)); ok {
				revoked = true
			}
		}
		if !revoked {
			newPaths = append(newPaths, path)
		}
	}
	return newPaths
}

func (f *fetcherHandler) shouldRefetchSegs(ctx context.Context,
	req *sciond.PathReq) (bool, error) {

	nq, err := f.pathDB.GetNextQuery(ctx, req.Dst.IA())
	if err != nil || nq == nil {
		return true, err
	}
	return time.Now().After(*nq), nil
}

// fetchAndVerify downloads path segments from the network. Segments that are
// successfully verified are added to the pathDB. Revocations that are
// successfully verified are added to the revocation cache.
func (f *fetcherHandler) fetchAndVerify(ctx context.Context, cancelF context.CancelFunc,
	req *sciond.PathReq, earlyTrigger *util.Trigger, ps *snet.Addr) {

	defer cancelF()
	reply, err := f.getSegmentsFromNetwork(ctx, req, ps)
	if err != nil {
		log.Warn("Unable to retrieve paths from network", "err", err)
		return
	}
	timer := earlyTrigger.Arm()
	// Cleanup early reply goroutine if function exits early
	if timer != nil {
		defer timer.Stop()
	}
	// verify and store the segments
	var insertedSegmentIDs []string
	verifiedSeg := func(ctx context.Context, s *seg.Meta) {
		wasInserted, err := segsaver.StoreSeg(ctx, s, f.pathDB)
		if err != nil {
			f.logger.Error("Unable to insert segment into path database",
				"seg", s.Segment, "err", err)
			return
		}
		if wasInserted {
			insertedSegmentIDs = append(insertedSegmentIDs, s.Segment.GetLoggingID())
		}
	}
	verifiedRev := func(ctx context.Context, rev *path_mgmt.SignedRevInfo) {
		f.revocationCache.Insert(rev)
	}
	segErr := func(s *seg.Meta, err error) {
		f.logger.Warn("Segment verification failed", "segment", s.Segment, "err", err)
	}
	revErr := func(revocation *path_mgmt.SignedRevInfo, err error) {
		f.logger.Warn("Revocation verification failed", "revocation", revocation, "err", err)
	}
	revInfos := revcache.FilterNew(f.revocationCache, reply.Recs.SRevInfos)
	segverifier.Verify(ctx, f.trustStore, ps, reply.Recs.Recs, revInfos,
		verifiedSeg, verifiedRev, segErr, revErr)
	if len(insertedSegmentIDs) > 0 {
		log.Debug("Segments inserted in DB", "segments", insertedSegmentIDs)
	}
}

func (f *fetcherHandler) getSegmentsFromNetwork(ctx context.Context,
	req *sciond.PathReq, ps *snet.Addr) (*path_mgmt.SegReply, error) {

	// Get segments from path server
	msg := &path_mgmt.SegReq{
		RawSrcIA: req.Src,
		RawDstIA: req.Dst,
	}
	reply, err := f.messenger.GetSegs(ctx, msg, ps, requestID.Next())
	if err != nil {
		return nil, err
	}
	// Sanitize input. There's no point in propagating garbage all throughout other modules.
	return reply.Sanitize(f.logger), nil
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
	_, err := f.pathDB.Delete(ctx, q)
	return err
}

func buildPathsToAllDsts(req *sciond.PathReq,
	ups, cores, downs seg.Segments) []*combinator.Path {

	dsts := []addr.IA{req.Dst.IA()}
	if req.Dst.IA().A == 0 {
		dsts = cores.FirstIAs()
	}
	var paths []*combinator.Path
	for _, dst := range dsts {
		paths = append(paths, combinator.Combine(req.Src.IA(), dst, ups, cores, downs)...)
	}
	return filterExpiredPaths(paths)
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

// NewExtendedContext returns a new _independent_ context that can extend past
// refCtx's lifetime, guaranteeing a minimum lifetime of minLifetime. If
// refCtx has a deadline, the newly created context will have a deadline equal
// to the maximum of refCtx's deadline and (minLifetime + currentTime). If
// refCtx does not have a deadline, the function panics.
//
// Because the returned context is independent, calling refCtx's cancellation
// function will not result in the cancellation of the returned context.
func NewExtendedContext(refCtx context.Context,
	minLifetime time.Duration) (context.Context, context.CancelFunc) {

	deadline, ok := refCtx.Deadline()
	if !ok {
		panic("reference context needs to have deadline")
	}
	otherDeadline := time.Now().Add(minLifetime)
	return context.WithDeadline(context.Background(), max(deadline, otherDeadline))
}

func max(x, y time.Time) time.Time {
	if x.Before(y) {
		return y
	}
	return x
}
