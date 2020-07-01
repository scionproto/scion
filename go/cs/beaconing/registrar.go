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

package beaconing

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/cs/metrics"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/seghandler"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

// SegmentProvider provides segments to register for the specified type.
type SegmentProvider interface {
	SegmentsToRegister(ctx context.Context, segType proto.PathSegType) (
		<-chan beacon.BeaconOrErr, error)
}

// SegmentStore stores segments in the path database.
type SegmentStore interface {
	StoreSegs(context.Context, []*seghandler.SegWithHP) (seghandler.SegStats, error)
}

// RPC registers the path segment with the remote.
type RPC interface {
	RegisterSegment(ctx context.Context, meta seg.Meta, remote net.Addr) error
}

// Pather computes the remote address with a path based on the provided segment.
type Pather interface {
	GetPath(svc addr.HostSVC, ps *seg.PathSegment) (net.Addr, error)
}

var _ periodic.Task = (*Registrar)(nil)

// Registrar is used to periodically register path segments with the appropriate
// path servers. Core and Up segments are registered with the local path server.
// Down segments are registered at the core.
type Registrar struct {
	Extender Extender
	Provider SegmentProvider
	Store    SegmentStore
	RPC      RPC
	Pather   Pather
	IA       addr.IA
	Signer   ctrl.Signer
	Intfs    *ifstate.Interfaces
	Type     proto.PathSegType

	// tick is mutable.
	Tick     Tick
	lastSucc time.Time
}

// Name returns the tasks name.
func (r *Registrar) Name() string {
	return "bs_beaconing_registrar"
}

// Run registers path segments for the specified type to path servers.
func (r *Registrar) Run(ctx context.Context) {
	r.Tick.now = time.Now()
	if err := r.run(ctx); err != nil {
		log.FromCtx(ctx).Error("[beaconing.Registrar] Unable to register",
			"type", r.Type, "err", err)
	}
	metrics.Registrar.RuntimeWithType(r.Type.String()).Add(time.Since(r.Tick.now).Seconds())
	r.Tick.updateLast()
}

func (r *Registrar) run(ctx context.Context) error {
	if r.Tick.now.Sub(r.lastSucc) < r.Tick.period && !r.Tick.passed() {
		return nil
	}
	logger := log.FromCtx(ctx)
	segments, err := r.Provider.SegmentsToRegister(ctx, r.Type)
	if err != nil {
		return err
	}
	peers, nonActivePeers := sortedIntfs(r.Intfs, topology.Peer)
	if len(nonActivePeers) > 0 {
		logger.Debug("[beaconing.Registrar] Ignore non-active peer interfaces", "type", r.Type,
			"intfs", nonActivePeers)
	}
	if r.Type != proto.PathSegType_down {
		return r.registerLocal(ctx, segments, peers)
	}
	return r.registerRemote(ctx, segments, peers)
}

func (r *Registrar) registerRemote(ctx context.Context, segments <-chan beacon.BeaconOrErr,
	peers []common.IFIDType) error {

	logger := log.FromCtx(ctx)
	s := newSummary()
	var expected int
	var wg sync.WaitGroup
	for bOrErr := range segments {
		if bOrErr.Err != nil {
			logger.Error("[beaconing.Registrar] Unable to get beacon", "err", bOrErr.Err)
			metrics.Registrar.InternalErrorsWithType(r.Type.String()).Inc()
			continue
		}
		if !intfActive(r.Intfs, bOrErr.Beacon.InIfId) {
			continue
		}
		err := r.Extender.Extend(ctx, bOrErr.Beacon.Segment, bOrErr.Beacon.InIfId, 0, peers)
		if err != nil {
			metrics.Registrar.InternalErrorsWithType(r.Type.String()).Inc()
			logger.Error("[beaconing.Registrar] Unable to terminate beacon",
				"beacon", bOrErr.Beacon, "err", err)
			continue
		}
		expected++
		s := remoteRegistrar{
			segType: r.Type,
			rpc:     r.RPC,
			pather:  r.Pather,
			summary: s,
			wg:      &wg,
		}

		// Avoid head-of-line blocking when sending message to slow servers.
		s.start(ctx, bOrErr.Beacon)
	}
	wg.Wait()
	if expected > 0 && s.count <= 0 {
		return common.NewBasicError("No beacons registered", nil, "candidates", expected)
	}
	if s.count > 0 {
		r.lastSucc = r.Tick.now
	}
	r.logSummary(logger, s)
	return nil
}

func (r *Registrar) registerLocal(ctx context.Context, segments <-chan beacon.BeaconOrErr,
	peers []common.IFIDType) error {

	logger := log.FromCtx(ctx)
	beacons := make(map[string]beacon.Beacon)
	var toRegister []*seghandler.SegWithHP
	for bOrErr := range segments {
		if bOrErr.Err != nil {
			logger.Error("[beaconing.Registrar] Unable to get beacon", "err", bOrErr.Err)
			metrics.Registrar.InternalErrorsWithType(r.Type.String()).Inc()
			continue
		}
		if !intfActive(r.Intfs, bOrErr.Beacon.InIfId) {
			continue
		}
		err := r.Extender.Extend(ctx, bOrErr.Beacon.Segment, bOrErr.Beacon.InIfId, 0, peers)
		if err != nil {
			metrics.Registrar.InternalErrorsWithType(r.Type.String()).Inc()
			logger.Error("[beaconing.Registrar] Unable to terminate beacon",
				"beacon", bOrErr.Beacon, "err", err)
			continue
		}
		toRegister = append(toRegister, &seghandler.SegWithHP{
			Seg: &seg.Meta{Type: r.Type, Segment: bOrErr.Beacon.Segment},
		})
		beacons[bOrErr.Beacon.Segment.GetLoggingID()] = bOrErr.Beacon
	}
	if len(toRegister) == 0 {
		return nil
	}
	stats, err := r.Store.StoreSegs(ctx, toRegister)
	if err != nil {
		metrics.Registrar.InternalErrorsWithType(r.Type.String()).Inc()
		return err
	}
	updateMetricsFromStat(stats, beacons, r.Type.String())
	r.lastSucc = r.Tick.now
	r.logSummary(logger, summarizeStats(stats, beacons))
	return nil
}

func (r *Registrar) logSummary(logger log.Logger, s *summary) {
	if r.Tick.passed() {
		logger.Info("[beaconing.Registrar] Registered beacons", "type", r.Type, "count", s.count,
			"startIAs", len(s.srcs))
		return
	}
	if s.count > 0 {
		logger.Info("[beaconing.Registrar] Registered beacons after stale period",
			"type", r.Type, "count", s.count, "startIAs", len(s.srcs))
	}
}

// remoteRegistrar registers one segment with the path server.
type remoteRegistrar struct {
	segType proto.PathSegType
	rpc     RPC
	pather  Pather
	summary *summary
	wg      *sync.WaitGroup
}

// start extends the beacon and starts a go routine that registers the beacon
// with the path server.
func (r *remoteRegistrar) start(ctx context.Context, bseg beacon.Beacon) {
	logger := log.FromCtx(ctx)
	addr, err := r.pather.GetPath(addr.SvcPS, bseg.Segment)
	if err != nil {
		metrics.Registrar.InternalErrorsWithType(r.segType.String()).Inc()
		logger.Error("[beaconing.Registrar] Unable to choose server", "err", err)
		return
	}
	r.startSendSegReg(ctx, bseg, seg.Meta{Type: r.segType, Segment: bseg.Segment}, addr)
}

// startSendSegReg adds to the wait group and starts a goroutine that sends the
// registration message to the peer.
func (r *remoteRegistrar) startSendSegReg(ctx context.Context, bseg beacon.Beacon,
	reg seg.Meta, addr net.Addr) {

	r.wg.Add(1)
	go func() {
		defer log.HandlePanic()
		defer r.wg.Done()
		logger := log.FromCtx(ctx)
		if err := r.rpc.RegisterSegment(ctx, reg, addr); err != nil {
			logger.Error("[beaconing.Registrar] Unable to register segment", "type", r.segType,
				"addr", addr, "err", err)
			metrics.Registrar.InternalErrorsWithType(r.segType.String()).Inc()
			return
		}
		r.summary.AddSrc(bseg.Segment.FirstIA())
		r.summary.Inc()
		l := metrics.RegistrarLabels{
			SegType: r.segType.String(),
			StartIA: bseg.Segment.FirstIA(),
			InIfID:  bseg.InIfId,
			Result:  metrics.Success,
		}
		metrics.Registrar.Beacons(l).Inc()
		logger.Debug("[beaconing.Registrar] Successfully registered segment", "type", r.segType,
			"addr", addr, "seg", bseg.Segment)
	}()
}

func updateMetricsFromStat(s seghandler.SegStats, b map[string]beacon.Beacon, segType string) {
	for _, id := range s.InsertedSegs {
		metrics.Registrar.Beacons(metrics.RegistrarLabels{
			InIfID:  b[id].InIfId,
			StartIA: b[id].Segment.FirstIA(),
			Result:  metrics.OkNew,
			SegType: segType,
		}).Inc()
	}
	for _, id := range s.UpdatedSegs {
		metrics.Registrar.Beacons(metrics.RegistrarLabels{
			InIfID:  b[id].InIfId,
			StartIA: b[id].Segment.FirstIA(),
			Result:  metrics.OkUpdated,
			SegType: segType,
		}).Inc()
	}
}

func summarizeStats(s seghandler.SegStats, b map[string]beacon.Beacon) *summary {
	sum := newSummary()
	for _, id := range append(s.InsertedSegs, s.UpdatedSegs...) {
		sum.AddSrc(b[id].Segment.FirstIA())
		sum.Inc()
	}
	return sum
}
