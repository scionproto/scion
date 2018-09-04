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
	"math/rand"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/combinator"
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
)

const (
	DefaultMinWorkerLifetime = 10 * time.Second
)

// requestID is used to generate unique request IDs for the messenger.
var requestID messenger.Counter

type Fetcher struct {
	topology        *topology.Topo
	messenger       infra.Messenger
	pathDB          pathdb.PathDB
	trustStore      infra.TrustStore
	revocationCache revcache.RevCache
	logger          log.Logger
}

func NewFetcher(topo *topology.Topo, messenger infra.Messenger, pathDB pathdb.PathDB,
	trustStore infra.TrustStore, revCache revcache.RevCache, logger log.Logger) *Fetcher {

	return &Fetcher{
		topology:        topo,
		messenger:       messenger,
		pathDB:          pathDB,
		trustStore:      trustStore,
		revocationCache: revCache,
		logger:          logger,
	}
}

// GetPaths fulfills the path request described by req. GetPaths will attempt
// to build paths at start, after earlyReplyInterval and at context expiration
// (or whenever all background workers return). An earlyReplyInterval of 0
// means no early reply attempt is made.
func (f *Fetcher) GetPaths(ctx context.Context, req *sciond.PathReq,
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
	psID, err := f.topology.PSNames.GetRandom()
	if err != nil {
		return nil, common.NewBasicError("PS not found in topology", err)
	}
	psAppAddr := f.topology.PS.GetById(psID).PublicAddr(f.topology.Overlay)
	if psAppAddr == nil {
		return nil, common.NewBasicError("PS not found in topology", nil)
	}
	ps := &snet.Addr{IA: f.topology.ISD_AS, Host: psAppAddr}

	// Check destination
	if req.Dst.IA().I == 0 {
		return f.buildSCIONDReply(nil, sciond.ErrorBadDstIA),
			common.NewBasicError("Bad destination AS", nil, "ia", req.Dst.IA())
	}
	// FIXME(scrye): If there are multiple core ASes in the remote ISD, we
	// might attempt to build paths towards one that is unreachable. SCIOND
	// should attempt to build paths towards multiple remote core ASes, and
	// return to the client one that is actually reachable.
	if req.Dst.IA().A == 0 {
		remoteTRC, err := f.trustStore.GetValidTRC(ctx, req.Dst.IA().I, ps)
		if err != nil {
			return f.buildSCIONDReply(nil, sciond.ErrorInternal),
				common.NewBasicError("Unable to select from remote core", err)
		}
		coreASes := remoteTRC.CoreASes.ASList()
		if len(coreASes) == 0 {
			return f.buildSCIONDReply(nil, sciond.ErrorInternal),
				common.NewBasicError("No remote core AS found", nil)
		}
		req.Dst = coreASes[rand.Intn(len(coreASes))].IAInt()
	}
	if req.Dst.IA().Eq(f.topology.ISD_AS) {
		return f.buildSCIONDReply(nil, sciond.ErrorOk), nil
	}
	// Try to build paths from local information first, if we don't have to
	// get fresh segments.
	if !req.Flags.Refresh {
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
func (f *Fetcher) buildSCIONDReply(paths []*combinator.Path,
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
func (f *Fetcher) buildSCIONDReplyEntries(paths []*combinator.Path) []sciond.PathReplyEntry {
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
		nextHop, ok := f.topology.IFInfoMap[path.Interfaces[0].IfID]
		if !ok {
			f.logger.Warn("Unable to find first-hop BR for path", "ifid", path.Interfaces[0].IfID)
			continue
		}
		entries = append(entries, sciond.PathReplyEntry{
			Path: &sciond.FwdPathMeta{
				FwdPath:    x.Bytes(),
				Mtu:        path.Mtu,
				Interfaces: path.Interfaces,
				ExpTime:    util.TimeToSecs(path.ExpTime),
			},
			HostInfo: sciond.HostInfo{
				Addrs: struct {
					Ipv4 []byte
					Ipv6 []byte
				}{
					Ipv4: nextHop.InternalAddr.IPv4.PublicAddr().L3.IP().To4(),
					// FIXME(scrye): also add support for IPv6
				},
				Port: nextHop.InternalAddr.IPv4.PublicAddr().L4.Port(),
			},
		})
	}
	return entries
}

// buildPathsFromDB attempts to build paths only from information contained in the
// local path database, taking the revocation cache into account.
func (f *Fetcher) buildPathsFromDB(ctx context.Context,
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
	dstIsCore := dstTrc.CoreASes.Contains(req.Dst.IA())
	// pathdb expects slices
	srcIASlice := []addr.IA{req.Src.IA()}
	dstIASlice := []addr.IA{req.Dst.IA()}
	// query pathdb and fill in the relevant segments below
	var ups, cores, downs seg.Segments
	switch {
	case srcIsCore && dstIsCore:
		// Gone corin'
		cores, err = f.getSegmentsFromDB(ctx, dstIASlice, srcIASlice)
		if err != nil {
			return nil, err
		}
	case srcIsCore && !dstIsCore:
		cores, err = f.getSegmentsFromDB(ctx, dstTrc.CoreASes.ASList(), srcIASlice)
		if err != nil {
			return nil, err
		}
		downs, err = f.getSegmentsFromDB(ctx, dstTrc.CoreASes.ASList(), dstIASlice)
		if err != nil {
			return nil, err
		}
	case !srcIsCore && dstIsCore:
		ups, err = f.getSegmentsFromDB(ctx, localTrc.CoreASes.ASList(), srcIASlice)
		if err != nil {
			return nil, err
		}
		cores, err = f.getSegmentsFromDB(ctx, dstIASlice, localTrc.CoreASes.ASList())
		if err != nil {
			return nil, err
		}
	case !srcIsCore && !dstIsCore:
		ups, err = f.getSegmentsFromDB(ctx, localTrc.CoreASes.ASList(), srcIASlice)
		if err != nil {
			return nil, err
		}
		downs, err = f.getSegmentsFromDB(ctx, dstTrc.CoreASes.ASList(), dstIASlice)
		if err != nil {
			return nil, err
		}
		cores, err = f.getSegmentsFromDB(ctx, downs.FirstIAs(), ups.FirstIAs())
		if err != nil {
			return nil, err
		}
	}
	paths := combinator.Combine(req.Src.IA(), req.Dst.IA(), ups, cores, downs)
	paths = f.filterRevokedPaths(paths)
	return paths, nil
}

func (f *Fetcher) getSegmentsFromDB(ctx context.Context, startsAt,
	endsAt []addr.IA) ([]*seg.PathSegment, error) {

	// We shouldn't query with zero length slices. Doing so would return too many segments.
	if len(startsAt) == 0 || len(endsAt) == 0 {
		return nil, nil
	}
	results, err := f.pathDB.Get(ctx, &query.Params{
		StartsAt: startsAt,
		EndsAt:   endsAt,
	})
	if err != nil {
		return nil, err
	}
	return query.Results(results).Segs(), nil
}

// filterRevokedPaths returns a new slice containing only those paths that do
// not have revoked interfaces in their forwarding path. Only the interfaces
// that have traffic going through them are checked.
func (f *Fetcher) filterRevokedPaths(paths []*combinator.Path) []*combinator.Path {
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

// fetchAndVerify downloads path segments from the network. Segments that are
// successfully verified are added to the pathDB. Revocations that are
// successfully verified are added to the revocation cache.
func (f *Fetcher) fetchAndVerify(ctx context.Context, cancelF context.CancelFunc,
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
	verifiedSeg := func(ctx context.Context, s *seg.Meta) {
		if err := segsaver.StoreSeg(ctx, s, f.pathDB, f.logger); err != nil {
			f.logger.Error("Unable to insert segment into path database",
				"seg", s.Segment, "err", err)
		}
	}
	verifiedRev := func(ctx context.Context, rev *path_mgmt.SignedRevInfo) {
		segsaver.StoreRevocation(rev, f.revocationCache)
	}
	segErr := func(s *seg.Meta, err error) {
		f.logger.Warn("Segment verification failed", "segment", s.Segment, "err", err)
	}
	revErr := func(revocation *path_mgmt.SignedRevInfo, err error) {
		f.logger.Warn("Revocation verification failed", "revocation", revocation, "err", err)
	}
	segverifier.Verify(ctx, f.trustStore, ps, reply.Recs.Recs, reply.Recs.SRevInfos,
		verifiedSeg, verifiedRev, segErr, revErr)
}

func (f *Fetcher) getSegmentsFromNetwork(ctx context.Context,
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
