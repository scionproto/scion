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
	"strconv"
	"sync"
	"time"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/seghandler"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
)

// Pather computes the remote address with a path based on the provided segment.
type Pather interface {
	GetPath(svc addr.HostSVC, ps *seg.PathSegment) (*snet.SVCAddr, error)
}

// SegmentProvider provides segments to register for the specified type.
type SegmentProvider interface {
	SegmentsToRegister(ctx context.Context, segType seg.Type) (
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
	Signer   seg.Signer
	Intfs    *ifstate.Interfaces
	Type     seg.Type

	Registered     metrics.Counter
	InternalErrors metrics.Counter

	// tick is mutable.
	Tick     Tick
	lastSucc time.Time
}

// Name returns the tasks name.
func (r *Registrar) Name() string {
	return "control_beaconing_registrar"
}

// Run registers path segments for the specified type to path servers.
func (r *Registrar) Run(ctx context.Context) {
	r.Tick.now = time.Now()
	if err := r.run(ctx); err != nil {
		log.FromCtx(ctx).Error("Unable to register", "seg_type", r.Type, "err", err)
	}
	r.Tick.updateLast()
}

func (r *Registrar) run(ctx context.Context) error {
	if r.Tick.now.Sub(r.lastSucc) < r.Tick.period && !r.Tick.passed() {
		return nil
	}
	segments, err := r.Provider.SegmentsToRegister(ctx, r.Type)
	if err != nil {
		return err
	}
	peers := sortedIntfs(r.Intfs, topology.Peer)
	if r.Type != seg.TypeDown {
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
			logger.Error("Unable to get beacon", "err", bOrErr.Err)
			r.incrementInternalErrors()
			continue
		}
		if r.Intfs.Get(bOrErr.Beacon.InIfId) == nil {
			continue
		}
		err := r.Extender.Extend(ctx, bOrErr.Beacon.Segment, bOrErr.Beacon.InIfId, 0, peers)
		if err != nil {
			logger.Error("Unable to terminate beacon", "beacon", bOrErr.Beacon, "err", err)
			r.incrementInternalErrors()
			continue
		}
		expected++
		s := remoteRegistrar{
			registrar: r,
			segType:   r.Type,
			rpc:       r.RPC,
			pather:    r.Pather,
			summary:   s,
			wg:        &wg,
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
			logger.Error("Unable to get beacon", "err", bOrErr.Err)
			r.incrementInternalErrors()
			continue
		}
		if r.Intfs.Get(bOrErr.Beacon.InIfId) == nil {
			continue
		}
		err := r.Extender.Extend(ctx, bOrErr.Beacon.Segment, bOrErr.Beacon.InIfId, 0, peers)
		if err != nil {
			logger.Error("Unable to terminate beacon", "beacon", bOrErr.Beacon, "err", err)
			r.incrementInternalErrors()
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
		r.incrementInternalErrors()
		return err
	}
	r.updateMetricsFromStat(stats, beacons)
	r.lastSucc = r.Tick.now
	r.logSummary(logger, summarizeStats(stats, beacons))
	return nil
}

func (r *Registrar) logSummary(logger log.Logger, s *summary) {
	if r.Tick.passed() {
		logger.Debug("Registered beacons", "seg_type", r.Type, "count", s.count,
			"start_isd_ases", len(s.srcs))
		return
	}
	if s.count > 0 {
		logger.Debug("Registered beacons after stale period",
			"seg_type", r.Type, "count", s.count, "start_isd_ases", len(s.srcs))
	}
}

// updateMetricsFromStat is used to update the metrics for local DB inserts.
func (r *Registrar) updateMetricsFromStat(s seghandler.SegStats, b map[string]beacon.Beacon) {
	for _, id := range s.InsertedSegs {
		r.incrementMetrics(registrarLabels{
			StartIA: b[id].Segment.FirstIA(),
			Ingress: b[id].InIfId,
			SegType: r.Type.String(),
			Result:  "ok_new",
		})
	}
	for _, id := range s.UpdatedSegs {
		r.incrementMetrics(registrarLabels{
			StartIA: b[id].Segment.FirstIA(),
			Ingress: b[id].InIfId,
			SegType: r.Type.String(),
			Result:  "ok_updated",
		})
	}
}

func (r *Registrar) incrementInternalErrors() {
	if r.InternalErrors == nil {
		return
	}
	r.InternalErrors.With("seg_type", r.Type.String()).Add(1)
}

func (r *Registrar) incrementMetrics(labels registrarLabels) {
	if r.Registered == nil {
		return
	}
	r.Registered.With(labels.Expand()...).Add(1)
}

// remoteRegistrar registers one segment with the path server.
type remoteRegistrar struct {
	registrar *Registrar
	segType   seg.Type
	rpc       RPC
	pather    Pather
	summary   *summary
	wg        *sync.WaitGroup
}

// start extends the beacon and starts a go routine that registers the beacon
// with the path server.
func (r *remoteRegistrar) start(ctx context.Context, bseg beacon.Beacon) {
	logger := log.FromCtx(ctx)
	addr, err := r.pather.GetPath(addr.SvcCS, bseg.Segment)
	if err != nil {
		logger.Error("Unable to choose server", "err", err)
		r.registrar.incrementInternalErrors()
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

		labels := registrarLabels{
			StartIA: bseg.Segment.FirstIA(),
			Ingress: bseg.InIfId,
			SegType: r.segType.String(),
		}

		logger := log.FromCtx(ctx)
		if err := r.rpc.RegisterSegment(ctx, reg, addr); err != nil {
			logger.Error("Unable to register segment",
				"seg_type", r.segType, "addr", addr, "err", err)
			r.registrar.incrementMetrics(labels.WithResult(prom.ErrNetwork))
			return
		}
		r.summary.AddSrc(bseg.Segment.FirstIA())
		r.summary.Inc()

		r.registrar.incrementMetrics(labels.WithResult(prom.Success))
		logger.Debug("Successfully registered segment", "seg_type", r.segType,
			"addr", addr, "seg", bseg.Segment)
	}()
}

func summarizeStats(s seghandler.SegStats, b map[string]beacon.Beacon) *summary {
	sum := newSummary()
	for _, id := range append(s.InsertedSegs, s.UpdatedSegs...) {
		sum.AddSrc(b[id].Segment.FirstIA())
		sum.Inc()
	}
	return sum
}

type registrarLabels struct {
	StartIA addr.IA
	Ingress common.IFIDType
	SegType string
	Result  string
}

func (l registrarLabels) Expand() []string {
	return []string{
		"start_isd_as", l.StartIA.String(),
		"ingress_interface", strconv.Itoa(int(l.Ingress)),
		"seg_type", l.SegType,
		prom.LabelResult, l.Result,
	}
}

func (l registrarLabels) WithResult(result string) registrarLabels {
	l.Result = result
	return l
}
