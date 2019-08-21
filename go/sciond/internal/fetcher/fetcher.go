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

	"github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/hostinfo"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/combinator"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
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
	messenger       infra.Messenger
	pathDB          pathdb.PathDB
	inspector       infra.ASInspector
	revocationCache revcache.RevCache
	config          config.SDConfig
	replyHandler    *segfetcher.SegReplyHandler
}

func NewFetcher(messenger infra.Messenger, pathDB pathdb.PathDB, trustStore TrustStore,
	revCache revcache.RevCache, cfg config.SDConfig, logger log.Logger) *Fetcher {

	return &Fetcher{
		messenger:       messenger,
		pathDB:          pathDB,
		inspector:       trustStore,
		revocationCache: revCache,
		config:          cfg,
		replyHandler: &segfetcher.SegReplyHandler{
			Verifier: &segfetcher.SegVerifier{Verifier: trustStore.NewVerifier()},
			Storage: &segfetcher.DefaultStorage{
				PathDB:   pathDB,
				RevCache: revCache,
			},
		},
	}
}

func (f *Fetcher) GetPaths(ctx context.Context, req *sciond.PathReq,
	earlyReplyInterval time.Duration, logger log.Logger) (*sciond.PathReply, error) {

	handler := &fetcherHandler{
		Fetcher:  f,
		topology: itopo.Get(),
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

	req = req.Copy()
	// Check context
	if _, ok := ctx.Deadline(); !ok {
		return nil, common.NewBasicError("Context must have deadline set", nil)
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
		if reply, err := f.buildReplyFromDB(ctx, req, true); reply != nil {
			return reply, err
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
	// network. The spawned goroutine (in fetchAndVerify) takes care of
	// updating the path database and revocation cache.
	ps := &snet.Addr{IA: f.topology.ISD_AS, Host: addr.NewSVCUDPAppAddr(addr.SvcPS)}
	processedResult := f.fetchAndVerify(ctx, req, earlyReplyInterval, ps)
	if processedResult == nil {
		return f.buildSCIONDReply(nil, req.MaxPaths, sciond.ErrorInternal),
			common.NewBasicError("No result", nil)
	}
	var storedSegs int
	// Wait for deadline while also waiting for the early reply.
	select {
	case <-ctx.Done():
	case storedSegs = <-processedResult.EarlyTriggerProcessed():
	}
	if storedSegs > 0 {
		if reply, err := f.buildReplyFromDB(ctx, req, true); reply != nil {
			return reply, err
		}
	}
	// Wait for deadline or full reply processed.
	select {
	case <-ctx.Done():
	case <-processedResult.FullReplyProcessed():
	}
	if processedResult.Err() != nil {
		f.logger.Error("Failed to store segments", "err", err)
	}
	if processedResult.VerificationErrors() != nil {
		f.logger.Warn("Failed to verify reply",
			"errors", common.FmtErrors(processedResult.VerificationErrors()))
	}
	if reply, err := f.buildReplyFromDB(ctx, req, false); reply != nil {
		return reply, err
	}
	// Your paths are in another castle
	return f.buildSCIONDReply(nil, req.MaxPaths, sciond.ErrorNoPaths), nil
}

func (f *fetcherHandler) buildReplyFromDB(ctx context.Context,
	req *sciond.PathReq, ignoreTrustNotFoundLocally bool) (*sciond.PathReply, error) {

	paths, err := f.buildPathsFromDB(ctx, req)
	switch {
	case ctx.Err() != nil:
		return f.buildSCIONDReply(paths, req.MaxPaths, sciond.ErrorNoPaths), nil
	case ignoreTrustNotFoundLocally && common.GetErrorMsg(err) == trust.ErrNotFoundLocally:
		return nil, nil
	case err != nil:
		return f.buildSCIONDReply(paths, req.MaxPaths, sciond.ErrorInternal), err
	case len(paths) > 0:
		return f.buildSCIONDReply(paths, req.MaxPaths, sciond.ErrorOk), nil
	}
	return nil, nil
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

// buildPathsFromDB attempts to build paths only from information contained in the
// local path database, taking the revocation cache into account.
func (f *fetcherHandler) buildPathsFromDB(ctx context.Context,
	req *sciond.PathReq) ([]*combinator.Path, error) {

	// Try to determine whether the destination AS is core or not
	subCtx, subCancelF := context.WithTimeout(ctx, time.Second)
	defer subCancelF()

	dstArgs := infra.ASInspectorOpts{
		TrustStoreOpts: infra.TrustStoreOpts{
			LocalOnly: true,
		},
		RequiredAttributes: []infra.Attribute{infra.Core},
	}
	dstCores, err := f.inspector.ByAttributes(subCtx, req.Dst.IA().I, dstArgs)
	if err != nil {
		// There are situations where we cannot tell if the remote is core. In
		// these cases we just error out, and calling code will try to get path
		// segments. When buildPaths is called again, err should be nil and the
		// function will proceed to the next part.
		return nil, err
	}
	localArgs := infra.ASInspectorOpts{
		RequiredAttributes: []infra.Attribute{infra.Core},
	}
	locCores, err := f.inspector.ByAttributes(ctx, f.topology.ISD_AS.I, localArgs)
	if err != nil {
		return nil, err
	}
	srcIsCore := containsIA(locCores, f.topology.ISD_AS)
	dstIsCore := req.Dst.IA().A == 0 || containsIA(dstCores, req.Dst.IA())
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
		cores, err = f.getSegmentsFromDB(ctx, dstCores, srcIASlice, proto.PathSegType_core)
		if err != nil {
			return nil, err
		}
		downs, err = f.getSegmentsFromDB(ctx, dstCores, dstIASlice, proto.PathSegType_down)
		if err != nil {
			return nil, err
		}
	case !srcIsCore && dstIsCore:
		ups, err = f.getSegmentsFromDB(ctx, locCores, srcIASlice, proto.PathSegType_up)
		if err != nil {
			return nil, err
		}
		cores, err = f.getSegmentsFromDB(ctx, dstIASlice, locCores, proto.PathSegType_core)
		if err != nil {
			return nil, err
		}
	case !srcIsCore && !dstIsCore:
		ups, err = f.getSegmentsFromDB(ctx, locCores, srcIASlice, proto.PathSegType_up)
		if err != nil {
			return nil, err
		}
		downs, err = f.getSegmentsFromDB(ctx, dstCores, dstIASlice, proto.PathSegType_down)
		if err != nil {
			return nil, err
		}
		cores, err = f.getSegmentsFromDB(ctx, downs.FirstIAs(), ups.FirstIAs(),
			proto.PathSegType_core)
		if err != nil {
			return nil, err
		}
	}
	paths := f.buildPathsToAllDsts(req, ups, cores, downs)
	return f.filterRevokedPaths(ctx, paths)
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
func (f *fetcherHandler) filterRevokedPaths(ctx context.Context,
	paths []*combinator.Path) ([]*combinator.Path, error) {

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
	return newPaths, nil
}

func (f *fetcherHandler) shouldRefetchSegs(ctx context.Context,
	req *sciond.PathReq) (bool, error) {

	nq, err := f.pathDB.GetNextQuery(ctx, req.Src.IA(), req.Dst.IA(), nil)
	return time.Now().After(nq), err
}

// fetchAndVerify downloads path segments from the network. Segments that are
// successfully verified are added to the pathDB. Revocations that are
// successfully verified are added to the revocation cache.
func (f *fetcherHandler) fetchAndVerify(ctx context.Context, req *sciond.PathReq,
	earlyReplyInterval time.Duration, ps *snet.Addr) *segfetcher.ProcessedResult {

	extCtx, cancelF := NewExtendedContext(ctx, DefaultMinWorkerLifetime)
	reply, err := f.getSegmentsFromNetwork(extCtx, req, ps)
	if err != nil {
		f.logger.Error("Unable to retrieve paths from network", "err", err)
		return nil
	}
	revInfos, err := revcache.FilterNew(extCtx, f.revocationCache, reply.Recs.SRevInfos)
	if err != nil {
		f.logger.Error("Failed to determine new revocations", "err", err)
		// Assume all are new
		revInfos = reply.Recs.SRevInfos
	}
	reply.Recs.SRevInfos = revInfos
	f.logger.Trace("Handle reply")
	earlyTrigger := make(chan struct{})
	time.AfterFunc(earlyReplyInterval, func() { close(earlyTrigger) })
	// Create an extended context to verify and store the reply.
	r := f.replyHandler.Handle(extCtx, reply, nil, earlyTrigger)
	go func() {
		defer log.LogPanicAndExit()
		defer cancelF()
		select {
		case <-extCtx.Done():
		case <-r.FullReplyProcessed():
			_, err = f.pathDB.InsertNextQuery(extCtx, req.Src.IA(), req.Dst.IA(), nil,
				time.Now().Add(f.config.QueryInterval.Duration))
			if err != nil {
				f.logger.Warn("Failed to update nextQuery", "err", err)
			}
		}
	}()
	return r
}

func (f *fetcherHandler) getSegmentsFromNetwork(ctx context.Context,
	req *sciond.PathReq, ps *snet.Addr) (*path_mgmt.SegReply, error) {

	// Get segments from path server
	msg := &path_mgmt.SegReq{
		RawSrcIA: req.Src,
		RawDstIA: req.Dst,
	}
	f.logger.Debug("Requesting segments", "ps", ps)
	reply, err := f.messenger.GetSegs(ctx, msg, ps, messenger.NextId())
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

func containsIA(ias []addr.IA, ia addr.IA) bool {
	for _, v := range ias {
		if v.Equal(ia) {
			return true
		}
	}
	return false
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
	parentCtx := context.Background()
	// Make sure that the attached logger is attached to the new ctx.
	parentCtx = log.CtxWith(parentCtx, log.FromCtx(refCtx))
	// Make sure that the attached span is attached to the new ctx.
	if span := opentracing.SpanFromContext(refCtx); span != nil {
		parentCtx = opentracing.ContextWithSpan(parentCtx, span)
	}
	return context.WithDeadline(parentCtx, max(deadline, otherDeadline))
}

func max(x, y time.Time) time.Time {
	if x.Before(y) {
		return y
	}
	return x
}
