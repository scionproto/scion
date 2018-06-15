// Copyright 2018 ETH Zurich
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

package fetchsegs

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	cache "github.com/patrickmn/go-cache"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto/trc"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/combinator"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/topology"
)

const (
	DefaultWorkerLifetime = 10 * time.Second
)

// requestID is used to generate unique request IDs for the messenger.
var requestID counter

type Fetcher struct {
	topology        *topology.Topo
	messenger       infra.Messenger
	pathDB          *pathdb.DB
	trustStore      infra.TrustStore
	revocationCache *cache.Cache
	coreASes        []addr.IA
	logger          log.Logger
}

func NewFetcher(topo *topology.Topo, messenger infra.Messenger, pathDB *pathdb.DB,
	localTRC *trc.TRC, trustStore infra.TrustStore) *Fetcher {

	return &Fetcher{
		topology:        topo,
		messenger:       messenger,
		pathDB:          pathDB,
		trustStore:      trustStore,
		revocationCache: cache.New(cache.NoExpiration, time.Second),
		coreASes:        localTRC.CoreASList(),
	}
}

// GetPaths fulfills the path request described by req. GetPaths will attempt
// to build paths at start, after earlyReplyInterval and at context expiration
// (or whenever all background workers return). An earlyReplyInterval of 0
// means no early reply attempt is made.
func (f *Fetcher) GetPaths(ctx context.Context, req *sciond.PathReq,
	earlyReplyInterval time.Duration) (*sciond.PathReply, error) {

	req = req.Copy()
	// Check source
	if req.Src.IA().IsZero() {
		req.Src = f.topology.ISD_AS.IAInt()
	}
	if !req.Src.IA().Eq(f.topology.ISD_AS) {
		return f.buildSCIONDReply(nil, sciond.ErrorBadSrcIA),
			common.NewBasicError("Bad source AS", nil, "ia", req.Src.IA())
	}
	// Check destination
	// FIXME(scrye): disallow remote AS = 0 for now, although we should add
	// support for this eventually
	if req.Dst.IA().I == 0 || req.Dst.IA().A == 0 {
		return f.buildSCIONDReply(nil, sciond.ErrorBadDstIA),
			common.NewBasicError("Bad destination AS", nil, "ia", req.Dst.IA())
	}
	if req.Dst.IA().Eq(f.topology.ISD_AS) {
		return f.buildSCIONDReply(nil, sciond.ErrorOk), nil
	}
	// Try to build paths from local information first
	paths, err := f.buildPathsFromDB(ctx, req)
	if err != nil {
		return f.buildSCIONDReply(nil, sciond.ErrorInternal), err
	}
	if err == nil && len(paths) > 0 {
		return f.buildSCIONDReply(paths, sciond.ErrorOk), nil
	}
	// We don't have enough local information, grab fresh segments from the
	// network. The spawned goroutine takes care of updating the path database
	// and revocation cache.
	subCtx, cancelF := context.WithTimeout(context.Background(), DefaultWorkerLifetime)
	earlyTrigger := newTrigger(earlyReplyInterval)
	go f.fetchAndVerify(subCtx, cancelF, req, earlyTrigger)
	// Wait for deadlines while also waiting for the early reply. If that
	// fires, try to build paths from local information again.
	select {
	case <-earlyTrigger.Done():
	case <-subCtx.Done():
	case <-ctx.Done():
	}
	paths, err = f.buildPathsFromDB(ctx, req)
	if err != nil {
		return f.buildSCIONDReply(nil, sciond.ErrorInternal), err
	}
	if err == nil && len(paths) > 0 {
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
		if err != nil {
			return f.buildSCIONDReply(nil, sciond.ErrorInternal), err
		}
		if err == nil && len(paths) > 0 {
			return f.buildSCIONDReply(paths, sciond.ErrorOk), err
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
					ExpTime:    uint32(time.Now().Add(spath.MaxTTL * time.Second).Unix()),
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
				ExpTime:    uint32(path.ExpTime.Unix()),
			},
			HostInfo: sciond.HostInfo{
				Addrs: struct {
					Ipv4 []byte
					Ipv6 []byte
				}{
					Ipv4: nextHop.InternalAddr.IPv4.PublicAddr(),
					// FIXME(scrye): also add support for IPv6
				},
				Port: uint16(nextHop.InternalAddr.IPv4.PublicL4Port()),
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
	// FIXME(scrye): The trail below is incorrect. The tests are written with
	// this in mind, and they populate the database s.t. the trust store is
	// guaranteed to not create network traffic here. This will be fixed when
	// the trust store adds support for address hints and trailless local
	// queries.
	trcObj, err := f.trustStore.GetValidTRC(context.TODO(), req.Dst.IA().I, req.Dst.IA().I)
	if err != nil {
		// There are situations where we cannot tell if the remote is core. In
		// these cases we just error out, and calling code will try to get path
		// segments. When buildPaths is called again, err should be nil and the
		// function will proceed to the next part.
		// FIXME(scrye): We want to differentiate between critical errors and
		// "I didn't find what you're looking for in the DB" errors. We want to
		// mask out the latter, s.t. calling code doesn't halt execution when
		// it sees an error.
		return nil, err
	}
	srcIsCore := iaInSlice(f.topology.ISD_AS, f.coreASes)
	dstIsCore := iaInSlice(req.Dst.IA(), trcObj.CoreASList())
	// pathdb expects slices
	srcIASlice := []addr.IA{req.Src.IA()}
	dstIASlice := []addr.IA{req.Dst.IA()}
	// query pathdb and fill in the relevant segments below
	var ups, cores, downs []*seg.PathSegment
	switch {
	case srcIsCore && dstIsCore:
		// Gone corin'
		cores, err = f.getSegmentsFromDB(dstIASlice, srcIASlice)
		if err != nil {
			return nil, err
		}
	case srcIsCore && !dstIsCore:
		if f.topology.ISD_AS.I == req.Dst.IA().I {
			// Only going down
			downs, err = f.getSegmentsFromDB(srcIASlice, dstIASlice)
			if err != nil {
				return nil, err
			}
		} else {
			cores, err = f.getSegmentsFromDB(trcObj.CoreASList(), srcIASlice)
			if err != nil {
				return nil, err
			}
			downs, err = f.getSegmentsFromDB(trcObj.CoreASList(), dstIASlice)
			if err != nil {
				return nil, err
			}
		}
	case !srcIsCore && dstIsCore:
		if f.topology.ISD_AS.I == req.Dst.IA().I {
			// Am I going up?
			ups, err = f.getSegmentsFromDB(dstIASlice, srcIASlice)
		} else {
			ups, err = f.getSegmentsFromDB(f.coreASes, srcIASlice)
			if err != nil {
				return nil, err
			}
			cores, err = f.getSegmentsFromDB(dstIASlice, f.coreASes)
			if err != nil {
				return nil, err
			}
		}
	case !srcIsCore && !dstIsCore:
		ups, err = f.getSegmentsFromDB(f.coreASes, srcIASlice)
		if err != nil {
			return nil, err
		}
		downs, err = f.getSegmentsFromDB(trcObj.CoreASList(), dstIASlice)
		if err != nil {
			return nil, err
		}
		startUps := getStartIAs(ups)
		startDowns := getStartIAs(downs)
		cores, err = f.getSegmentsFromDB(startDowns, startUps)
		if err != nil {
			return nil, err
		}
	}
	paths := combinator.Combine(req.Src.IA(), req.Dst.IA(), ups, cores, downs)
	paths = f.filterRevokedPaths(paths)
	return paths, nil
}

func (f *Fetcher) getSegmentsFromDB(startsAt, endsAt []addr.IA) ([]*seg.PathSegment, error) {
	results, err := f.pathDB.Get(&query.Params{
		StartsAt: startsAt,
		EndsAt:   endsAt,
	})
	if err != nil {
		return nil, err
	}
	var segments []*seg.PathSegment
	for _, result := range results {
		segments = append(segments, result.Seg)
	}
	return segments, nil
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
			if _, ok := f.revocationCache.Get(revCacheKey(iface.ISD_AS(), iface.IfID)); ok {
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
func (t *Fetcher) fetchAndVerify(ctx context.Context, cancelF context.CancelFunc,
	req *sciond.PathReq, earlyTrigger *trigger) {

	defer cancelF()
	reply, err := t.getSegmentsFromNetwork(ctx, req)
	if err != nil {
		log.Warn("Unable to retrieve paths from network", "err", err)
		return
	}
	timer := earlyTrigger.Arm()
	// Cleanup early reply goroutine if function exits early
	if timer != nil {
		defer timer.Stop()
	}
	// Build verification units
	units := t.buildVerificationUnits(reply.Recs.Recs, reply.Recs.SRevInfos)
	unitResultsC := make(chan UnitVerificationResult, len(units))
	for _, unit := range units {
		go t.verifyUnit(ctx, unit, unitResultsC)
	}
Loop:
	for numResults := 0; numResults < len(units); numResults++ {
		select {
		case result := <-unitResultsC:
			if _, ok := result.Errors[-1]; ok {
				log.Info("Segment verification failed", "errors", result.Errors[-1])
			} else {
				// Verification succeeded
				_, err := t.pathDB.Insert(&result.Unit.segMeta.Segment,
					[]seg.Type{result.Unit.segMeta.Type})
				if err != nil {
					log.Warn("Unable to insert segment into path database", "err", err)
					continue
				}
				log.Debug("Inserted segment into path database", "segment", result.Unit.segMeta)
			}
			// Insert successfully verified revocations into the revcache
			for index, revocation := range result.Unit.sRevInfos {
				if _, ok := result.Errors[index]; !ok {
					// Verification succeeded for this revocation, so we can add it to the cache
					info, err := revocation.RevInfo()
					if err != nil {
						panic(err)
					}
					t.revocationCache.Add(
						revCacheKey(info.IA(), common.IFIDType(info.IfID)),
						revocation,
						info.GetLifetime(time.Now()),
					)
				}
			}
		case <-ctx.Done():
			break Loop
		}
	}
}

func (f *Fetcher) getSegmentsFromNetwork(ctx context.Context,
	req *sciond.PathReq) (*path_mgmt.SegReply, error) {

	// Randomly choose a path server
	psName := f.topology.PSNames[rand.Intn(len(f.topology.PSNames))]
	topoAddr := f.topology.PS[psName]
	info := topoAddr.PublicAddrInfo(f.topology.Overlay)
	if info == nil {
		return nil, common.NewBasicError("Need PS for segments, but none found in topology", nil)
	}
	ps := &snet.Addr{
		IA:     f.topology.ISD_AS,
		Host:   addr.HostFromIP(info.IP),
		L4Port: uint16(info.L4Port),
	}
	// Get segments from path server
	msg := &path_mgmt.SegReq{
		RawSrcIA: req.Src,
		RawDstIA: req.Dst,
	}
	reply, err := f.messenger.GetPaths(ctx, msg, ps, requestID.Next())
	if err != nil {
		return nil, err
	}
	// Sanitize input. There's no point in propagating garbage all throughout other modules.
	return f.Sanitize(reply), nil
}

// Sanitize returns a fresh SegReply containing only the correct segments and
// revocations in argument reply.  . This greatly simplifies error processing
// in the rest of the module. Note that pointers in the returned value
// reference the same memory as the argument.
func (f *Fetcher) Sanitize(reply *path_mgmt.SegReply) *path_mgmt.SegReply {
	newReply := &path_mgmt.SegReply{
		Req:  reply.Req,
		Recs: &path_mgmt.SegRecs{},
	}
	for _, segment := range reply.Recs.Recs {
		ok := true
		for _, asEntry := range segment.Segment.ASEntries {
			for _, hopEntry := range asEntry.HopEntries {
				_, err := hopEntry.HopField()
				if err != nil {
					// Discard the whole segment. This should be a rare occurrence anyway.
					ok = false
				}
			}
		}
		if !ok {
			f.logger.Warn("Discarding bad segment", "segment", segment)
		} else {
			newReply.Recs.Recs = append(newReply.Recs.Recs, segment)
		}
	}
	for _, revocation := range reply.Recs.SRevInfos {
		_, err := revocation.RevInfo()
		if err != nil {
			f.logger.Warn("Discarding bad revocation", "revocation", revocation, "err", err)
		} else {
			newReply.Recs.SRevInfos = append(newReply.Recs.SRevInfos, revocation)
		}
	}
	return newReply
}

func (f *Fetcher) buildVerificationUnits(segMetas []*seg.Meta,
	sRevInfos []*path_mgmt.SignedRevInfo) []*verificationUnit {

	var units []*verificationUnit
	for _, segMeta := range segMetas {
		unit := &verificationUnit{segMeta: segMeta}
		for _, sRevInfo := range sRevInfos {
			revInfo, err := sRevInfo.RevInfo()
			if err != nil {
				panic(err)
			}
			if f.metaContainsInterface(segMeta, revInfo.IA(), common.IFIDType(revInfo.IfID)) {
				unit.sRevInfos = append(unit.sRevInfos, sRevInfo)
			}
		}
		units = append(units, unit)
	}
	return units
}

func (f *Fetcher) metaContainsInterface(segMeta *seg.Meta, ia addr.IA, ifid common.IFIDType) bool {
	for _, asEntry := range segMeta.Segment.ASEntries {
		for _, entry := range asEntry.HopEntries {
			hf, err := entry.HopField()
			if err != nil {
				panic(err)
			}
			if asEntry.IA().Eq(ia) && (hf.ConsEgress == ifid || hf.ConsIngress == ifid) {
				return true
			}
		}
	}
	return false
}

// verifyUnit spawns goroutines
func (f *Fetcher) verifyUnit(ctx context.Context, unit *verificationUnit,
	unitResults chan UnitVerificationResult) {

	subCtx, subCtxCancelF := context.WithCancel(ctx)
	// We return when either (1) ctx is done, (2) all verification succeeds,
	// (3) any verification fails. In all these cases, it's ok to immediately
	// cancel all workers.
	defer subCtxCancelF()
	// Build trail here because we need to pass it into VerifyRevInfo as it
	// doesn't have enough topology information to build it
	var trail []addr.ISD
	for _, asEntry := range unit.segMeta.Segment.ASEntries {
		trail = append(trail, asEntry.IA().I)
	}
	responses := make(chan VerificationResult, unit.Len())
	go f.verifySegment(subCtx, unit.segMeta, trail, responses)
	for index, sRevInfo := range unit.sRevInfos {
		subtrail := getTrailSlice(sRevInfo, trail)
		go f.verifyRevInfo(subCtx, index, sRevInfo, subtrail, responses)
	}
	// Response writers must guarantee that the for returns before (or very
	// close around) ctx.Done()
	errs := make(map[int]error)
	for numResults := 0; numResults < unit.Len(); numResults++ {
		result := <-responses
		if result.Error != nil {
			errs[result.Index] = result.Error
		}
	}
	select {
	case unitResults <- UnitVerificationResult{Unit: unit, Errors: errs}:
	default:
		panic("would block on channel")
	}
}

func (f *Fetcher) verifySegment(ctx context.Context, segment *seg.Meta, trail []addr.ISD,
	ch chan VerificationResult) {

	for i, asEntry := range segment.Segment.ASEntries {
		// TODO(scrye): get valid chain, then verify ASEntry at index i with
		// the key from the chain
		_, _ = i, asEntry
	}
	select {
	case ch <- VerificationResult{Index: -1, Error: nil}:
	default:
		panic("would block on channel")
	}
}

func (f *Fetcher) verifyRevInfo(ctx context.Context, index int, signedRevInfo *path_mgmt.SignedRevInfo,
	trail []addr.ISD, ch chan VerificationResult) {

	// TODO(scrye): get valid chain, then verify signedRevInfo.Blob with the
	// key from the chain
	select {
	case ch <- VerificationResult{Index: index, Error: nil}:
	default:
		panic("would block on channel")
	}
}

func revCacheKey(ia addr.IA, ifid common.IFIDType) string {
	return fmt.Sprintf("%v#%v", ia, ifid)
}

func iaInSlice(ia addr.IA, slice []addr.IA) bool {
	for _, otherIA := range slice {
		if ia.Eq(otherIA) {
			return true
		}
	}
	return false
}

func getStartIAs(segments []*seg.PathSegment) []addr.IA {
	var startIAs []addr.IA
	for _, segment := range segments {
		startIAs = append(startIAs, segment.ASEntries[0].IA())
	}
	return startIAs
}

func getTrailSlice(sRevInfo *path_mgmt.SignedRevInfo, trail []addr.ISD) []addr.ISD {
	info, err := sRevInfo.RevInfo()
	if err != nil {
		// Should be caught in first pass
		panic(err)
	}

	isd := info.IA().I
	for i := range trail {
		if trail[i] == isd {
			return trail[:i+1]
		}
	}
	// should never happen, the ISD in the revinfo has already been matched
	// when the verification unit was constructed
	panic(fmt.Sprintf("isd %d not in trail %v", isd, trail))
}

type VerificationResult struct {
	Index int
	Error error
}

type UnitVerificationResult struct {
	Unit   *verificationUnit
	Errors map[int]error
}

// verificationUnit contains multiple verification items.
type verificationUnit struct {
	segMeta   *seg.Meta
	sRevInfos []*path_mgmt.SignedRevInfo
}

func (unit *verificationUnit) Len() int {
	return len(unit.sRevInfos) + 1
}

type counter uint64

// Next is a concurrency-safe generator of unique request IDs for the
// messenger.
func (c *counter) Next() uint64 {
	return atomic.AddUint64((*uint64)(c), 1)
}

// trigger represents a timer with delayed arming. Once Arm is called, the
// object's Done() method will return after d time. If d is 0, Done will
// instead block forever.
type trigger struct {
	d    time.Duration
	ch   chan struct{}
	once sync.Once
}

func newTrigger(d time.Duration) *trigger {
	return &trigger{
		d:  d,
		ch: make(chan struct{}, 0),
	}
}

func (t *trigger) Done() <-chan struct{} {
	return t.ch
}

// Arm starts the trigger's preset timer, and returns the corresponding timer
// object. If the trigger is not configured with a timer, nil is returned.
func (t *trigger) Arm() *time.Timer {
	var timer *time.Timer
	t.once.Do(
		func() {
			if t.d != 0 {
				timer = time.AfterFunc(t.d, func() { close(t.ch) })
			}
		},
	)
	return timer
}

func (t *trigger) Triggered() bool {
	select {
	case <-t.ch:
		return true
	default:
		return false
	}
}
